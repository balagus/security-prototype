[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype-phase4',
    [string]$BaoSecretPrefix = 'openbao_phase4',
    # Bounded wait for a record to reach the shipped store (seconds).
    [int]$ShipWaitSeconds = 30,
    # How long the login poller runs after "docker compose start maria-replica".
    [int]$PollSeconds = 45,
    # Extra time (beyond the event interval) the expiry backstop may take.
    [int]$EventSlackSeconds = 5,
    # Minimum outage for the reconciler test (PostgreSQL logins are measured meanwhile). OpenBao
    # retries a failed revocation with a jittered, growing delay (6 attempts, about 10.6 min in
    # all); after this minimum the test also waits until OpenBao's next own attempt for both
    # leases is at least 90 s away (read from OpenBao's log), so the completion it measures is the
    # reconciler's.
    [int]$OutageSeconds = 150,
    # Bound for the reconciler to complete a pending revocation after the target is back.
    [int]$ReconcileWaitSeconds = 120,
    # OPT-IN: produce a real irrevocable lease (MariaDB replica down for about 11 minutes) and show
    # that the reconciler detects, alerts and revokes it.
    [switch]$IrrevocableTest,
    [int]$IrrevocableWaitSeconds = 900
)

# Revocation backstops (design 5.4, "Revocation depends on the replica being reachable"), against
# the RUNNING, configured phase 4 stack (compose.phase4.yaml after scripts\phase4-setup.ps1).
# Windows PowerShell 5.1 compatible. One PASS/FAIL line per check; exit 0 only if all pass.
#
# Three layers, each tested alone and together:
#   1. Startup purge on maria-replica (init_file): every local v- user is dropped at each start
#      before the server accepts network connections. The ORDER is measured: a poller in the
#      maria-sweeper's network namespace tries to log in (session_sweeper as the control account,
#      plus a revoked and a still-valid temp user) as fast as it can from before the start, and
#      the first network answer is compared with the purge's completion time.
#   2. Expiry backstop on maria-replica (local event replica_local.revocation_backstop): a lab v-
#      user with a creation time in the past is dropped within the event interval, its session is
#      killed, nothing is binlogged, an alert is shipped; fresh, unparseable and non-v- accounts stay.
#      Each privilege of the event's definer is measured by removing it.
#   3. OpenBao lease reconciler (container lease-reconciler): a revocation queued while the
#      database was down (MariaDB replica, and PostgreSQL primary) is completed by the reconciler
#      after the database returns; the reconciler's token is refused everything else; each policy
#      rule is measured by removing it.
#      -IrrevocableTest: a real irrevocable lease (about 11 minutes) is detected, alerted, revoked.
#      PostgreSQL replica deny list (reconciler descriptor -> pg-deny-watcher.sh inside pg-replica
#      -> pg_hba @file reject): during the primary outage the revoked role is refused and its
#      session terminated (timed with a login poller), a still-valid role keeps working, a
#      still-valid role of the SAME second is over-denied (shown), the watcher survives kill -9
#      (restarted) and SIGTERM of its supervisor (alerted), a pg-replica restart during the outage
#      has no login window, and after the primary returns descriptor and entry are pruned (3).
#      Malicious descriptors written with the reconciler's uid and mount are rejected and alerted
#      and change nothing; mounts and ownership of the channel; no watcher activity when idle (3c, 3d).
#      This replaces the former measurement "the revoked role logged in 10/10 times during a
#      150 s primary outage" (PostgreSQL EXPOSURE).
#
# Same rules as the other suites: negative checks print the real error text; secrets are never
# printed (passwords go to containers as environment variables of the docker CLI process).
# LAB-ONLY changes made and undone here: lab accounts v-lab-*, lab-old-* on maria-replica (local,
# sql_log_bin = 0, hash-only passwords), the backstop event disabled / re-scheduled / its definer's
# privileges revoked one at a time (a restart of maria-replica restores everything from the
# init_file, and is part of the test), a lab event on maria-primary (created and dropped), the
# lease-reconciler policy replaced by reduced variants and restored, maria-replica stopped and
# started three times (once restarted), pg-primary stopped and started once, pg-replica restarted
# once (during that outage), its deny-list watcher killed once and its supervisor stopped once (the
# restart brings both back), lease-reconciler paused for the injection test, lab files *Inj* in the
# pg-deny volume (removed).
# Takes about 10 minutes; with -IrrevocableTest about 23 minutes.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.phase4.yaml' }
$P2ComposeFile = $ComposeFile
$P2Project = $Project
$P2BaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $root 'scripts\phase2-lib.ps1')

$netAccess = $P2Project + '_access'
$netRecon = $P2Project + '_bao-reconciler'
$volCa = $P2Project + '_pki-ca'
$volStore = $P2Project + '_log-store'
$accessMask = '10.81.5.0/255.255.255.0'
$backstopDir = '/var/log/mariadb-audit/backstop'
# ALTER EVENT without a DEFINER clause makes the CURRENT user (root here) the definer (measured);
# every ALTER EVENT below therefore names the definer again.
$evAlter = "SET SESSION sql_log_bin = 0; ALTER DEFINER = 'revocation_backstop'@'localhost' EVENT replica_local.revocation_backstop"
$realmFile = Join-Path $P2Root 'config\keycloak\lab-realm.json'
$inv = [System.Globalization.CultureInfo]::InvariantCulture

$script:Pass = 0
$script:Fail = 0
$script:Tokens = New-Object System.Collections.ArrayList
$script:Containers = New-Object System.Collections.ArrayList
$script:Measure = New-Object System.Collections.ArrayList
$script:Altered = New-Object System.Collections.ArrayList

function Write-Result {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) { $script:Pass++; $tag = 'PASS'; $color = 'Green' } else { $script:Fail++; $tag = 'FAIL'; $color = 'Red' }
    Write-Host ('{0} {1}' -f $tag, $Name) -ForegroundColor $color
    if ($Detail) { foreach ($l in ($Detail.Trim() -split "`r?`n")) { if ($l.Trim()) { Write-Host ('       | ' + $l.TrimEnd()) } } }
}
function Redact {
    param([string]$T)
    if (-not $T) { return $T }
    $T = $T -replace "(?i)(PASSWORD\s*\(?\s*)'[^']*'", '$1''<redacted>'''
    $T = $T -replace "(?i)(IDENTIFIED BY\s*)'[^']*'", '$1''<redacted>'''
    return $T
}
function Assert-Refused {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -ne 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, (Redact $Result.All))
    if (-not $ok) { $detail = $detail + ("`n(expected a failure matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}
function Assert-Works {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -eq 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, (Redact $Result.All))
    if (-not $ok) { $detail = $detail + ("`n(expected success matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}
function Note { param([string]$Text) Write-Host ('       | ' + $Text) }
function Add-Measure { param([string]$Text) [void]$script:Measure.Add($Text); Note ('measured: ' + $Text) }
function OneLine { param([string]$T, [int]$Max = 220) $s = ($T -replace '\s+', ' ').Trim(); if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }; return $s }

# --- identities --------------------------------------------------------------------------------
$realm = [System.IO.File]::ReadAllText($realmFile, $P2Utf8NoBom) | ConvertFrom-Json
function Get-TestPassword { param([string]$User) return [string](($realm.users | Where-Object { $_.username -eq $User }).credentials[0].value) }
function Get-IdToken {
    param([string]$User)
    $body = @{ grant_type = 'password'; client_id = 'bao-jwt-test'; username = $User; password = (Get-TestPassword $User); scope = 'openid' }
    $r = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8180/realms/lab/protocol/openid-connect/token' -Body $body -TimeoutSec 15
    return [string]$r.id_token
}
function Connect-Bao {
    param([string]$User)
    $r = Invoke-Bao @('write', '-format=json', 'auth/jwt/login', 'role=dev', 'jwt=-') '' (Get-IdToken $User)
    $o = ConvertFrom-JsonOrNull $r.Out
    $tok = $null
    if (($r.Code -eq 0) -and ($null -ne $o)) { $tok = [string]$o.auth.client_token; [void]$script:Tokens.Add($tok) }
    return @{ R = $r; Token = $tok }
}
function Get-Creds {
    param([string]$Token, [string]$Role)
    $r = Invoke-Bao @('read', '-format=json', ('database/creds/' + $Role)) $Token
    $o = ConvertFrom-JsonOrNull $r.Out
    if (($r.Code -eq 0) -and ($null -ne $o)) { return @{ R = $r; User = [string]$o.data.username; Password = [string]$o.data.password; Lease = [string]$o.lease_id } }
    return @{ R = $r; User = $null; Password = $null; Lease = $null }
}
$baoRootToken = Read-P2Secret $P2BaoRootTokenName
function BaoRoot { param([string[]]$A, [string]$Stdin = $null) Invoke-Bao $A $baoRootToken $Stdin }
function Test-LeaseExists { param([string]$Lease) return ((BaoRoot @('write', '-field=ttl', 'sys/leases/lookup', ('lease_id=' + $Lease))).Code -eq 0) }
function Get-LeaseTtl { param([string]$Lease) $r = BaoRoot @('write', '-field=ttl', 'sys/leases/lookup', ('lease_id=' + $Lease)); if ($r.Code -eq 0) { return $r.Out.Trim() }; return 'gone' }

# --- database access ---------------------------------------------------------------------------
$mariaRootPw = Read-P2Secret 'maria_root_password'
$ids = @{}
function Id { param([string]$S) if (-not $ids.ContainsKey($S)) { $ids[$S] = Get-P2ContainerId $S }; return $ids[$S] }
function PgSu { param([string]$S, [string]$Sql) Invoke-Docker @('exec', '-u', 'postgres', (Id $S), 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', 'app1', '-c', $Sql) }
function MaSu { param([string]$S, [string]$Sql) Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Id $S), 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mariaRootPw } }
function PgVal { param([string]$S, [string]$Sql) return (PgSu $S $Sql).Out.Trim() }
function MaVal { param([string]$S, [string]$Sql) return (MaSu $S $Sql).Out.Trim() }
function MaRows { param([string]$User) return (MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.global_priv WHERE User = '{0}'" -f $User)) }
function PgClient {
    param([string]$ConnInfo, [string]$Sql, [string]$Password)
    Invoke-Docker @('run', '--rm', '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD',
        '--entrypoint', 'psql', 'postgres:17', ($ConnInfo + ' connect_timeout=5'), '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', $Sql) @{ PGPASSWORD = $Password }
}
function MaClient {
    param([string]$User, [string]$Sql, [string]$Password)
    Invoke-Docker @('run', '--rm', '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD',
        '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', 'maria-replica', '-u', $User, '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert',
        '--connect-timeout=5', '-N', '-B', 'app1_masked', '-e', $Sql) @{ MYSQL_PWD = $Password }
}
$pgReplicaConn = 'host=pg-replica dbname=app1 sslmode=verify-full sslrootcert=/ca/ca.crt'
function Compose { param([string[]]$A) Invoke-Docker (@('compose', '-f', $P2ComposeFile) + $A) @{} 180 }
function Wait-Healthy {
    param([string]$Service, [int]$Seconds = 150)
    $deadline = (Get-Date).AddSeconds($Seconds)
    do { $h = (Invoke-Docker @('inspect', '-f', '{{.State.Health.Status}}', (Id $Service))).Out.Trim(); if ($h -eq 'healthy') { return $true }; Start-Sleep -Milliseconds 500 } while ((Get-Date) -lt $deadline)
    return $false
}
function New-LabPassword { $a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; return -join (1..28 | ForEach-Object { $a[(Get-Random -Maximum $a.Length)] }) }
function New-Suffix { return -join ((1..4) | ForEach-Object { 'abcdefghjkmnpqrstuvwxyz23456789'[(Get-Random -Maximum 31)] }) }
# A local lab account on maria-replica, created like the temp users' hash-only form: no
# IDENTIFIED BY, the password set with SET PASSWORD FOR ... = PASSWORD(...) on a locked account,
# everything with sql_log_bin = 0 (not in the replica's binlog; server_audit masks PASSWORD()).
function New-LabMariaUser {
    param([string]$Name, [string]$Password)
    $sql = 'SET SESSION sql_log_bin = 0; CREATE USER ''$U''@''$M'' REQUIRE SSL ACCOUNT LOCK; SET PASSWORD FOR ''$U''@''$M'' = PASSWORD(''$P4PW''); ALTER USER ''$U''@''$M'' ACCOUNT UNLOCK; GRANT SELECT ON app1_masked.* TO ''$U''@''$M'';'
    Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', '-e', 'P4PW', '-e', 'U', '-e', 'M', (Id 'maria-replica'), 'bash', '-c',
        ('mariadb --protocol=socket -uroot -e "' + $sql + '" 2>&1 | sed -E "s/PASSWORD\(.[^)]*\)/PASSWORD(<redacted>)/"')) @{ MYSQL_PWD = $mariaRootPw; P4PW = $Password; U = $Name; M = $accessMask }
}
# A login with a dropped account is refused with "Access denied for user" when some other account
# matches the client's host, and with "Host ... is not allowed to connect" (1130) when none does
# (for example right after the startup purge, when no v- account for the access network is left).
function MaRefused { param([string]$User) return ("Access denied for user '" + [regex]::Escape($User) + "'|Host '10\.81\.5\.\d+' is not allowed to connect") }
function Drop-LabMariaUser { param([string]$Name) [void](MaSu 'maria-replica' ("SET SESSION sql_log_bin = 0; DROP USER IF EXISTS '{0}'@'{1}'" -f $Name, $accessMask)) }
# Long-running MariaDB session on the replica; returns @{ Name; Id }.
function Start-MaSession {
    param([string]$User, [string]$Password, [string]$Tag, [int]$Seconds = 50)
    $n = 'revsess-' + $Tag + '-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    [void]$script:Containers.Add($n)
    [void](Invoke-Docker @('run', '-d', '--name', $n, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD', '--entrypoint', 'mariadb', 'mariadb:11.8',
        '-h', 'maria-replica', '-u', $User, '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert', '--skip-reconnect', '-N', '-B', 'app1_masked',
        '-e', ("SELECT CONCAT('session ', CONNECTION_ID()); SELECT SLEEP({0}); SELECT 'STILL ALIVE';" -f $Seconds)) @{ MYSQL_PWD = $Password })
    $id = '0'; $dl = (Get-Date).AddSeconds(20)
    do { Start-Sleep -Milliseconds 300; $id = MaVal 'maria-replica' ("SELECT COALESCE(MAX(ID), 0) FROM information_schema.PROCESSLIST WHERE USER = '{0}'" -f $User) } while (($id -eq '0') -and ((Get-Date) -lt $dl))
    return @{ Name = $n; Id = $id }
}
function Test-MaIdAlive { param([string]$I) return ((MaVal 'maria-replica' ("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = {0}" -f $I)) -eq '1') }
function Get-ContainerLog { param([string]$Name) [void](Invoke-Docker @('wait', $Name) @{} 30); return (Invoke-Docker @('logs', $Name)).All }
function ConvertTo-Epoch { param([string]$Ts) if (-not $Ts) { return $null }; return [DateTimeOffset]::Parse($Ts, $inv).ToUnixTimeMilliseconds() / 1000.0 }
function Get-ReconLog { param([string]$Since) return (Invoke-Docker @('logs', '--since', $Since, (Id 'lease-reconciler'))).All }
function UtcStamp { param([int]$Back = 1) return (Get-Date).ToUniversalTime().AddSeconds(-$Back).ToString('yyyy-MM-ddTHH:mm:ssZ') }

# --- the shipped store --------------------------------------------------------------------------
# A reader with the store mounted read-only polls a store file until one line contains all
# needles (or the wait ends) and prints the matching lines.
$findScript = @'
f="/store/$F"; end=$(( $(date +%s) + WAIT ))
while :; do
  out="$(grep -F -- "$N1" "$f" 2>/dev/null)"
  for v in N2 N3 N4 N5; do if [ -n "${!v:-}" ]; then out="$(printf '%s\n' "$out" | grep -F -- "${!v}")"; fi; done
  if [ -n "$out" ]; then printf '%s\n' "$out" | tail -n 5; exit 0; fi
  if [ "$(date +%s)" -ge "$end" ]; then echo "NOT_FOUND after ${WAIT} s"; exit 1; fi
  sleep 0.5
done
'@
function Find-InStore {
    param([string[]]$Needles, [string]$File = 'audit.jsonl', [int]$Wait = $ShipWaitSeconds)
    $envs = @{ WAIT = [string]$Wait; F = $File }
    $i = 0
    foreach ($n in $Needles) { $i++; $envs[('N' + $i)] = $n }
    $a = @('run', '--rm', '--network', 'none', '-v', ($volStore + ':/store:ro'))
    foreach ($k in $envs.Keys) { $a += @('-e', $k) }
    $a += @('--entrypoint', 'bash', 'postgres:17', '-c', $findScript)
    $r = Invoke-Docker $a $envs ($Wait + 60)
    $objs = @()
    foreach ($x in ($r.Out -split "`r?`n")) { if ($x.Trim().StartsWith('{')) { $o = ConvertFrom-JsonOrNull $x; if ($null -ne $o) { $objs += $o } } }
    return @{ Code = $r.Code; Objects = $objs; Raw = $r.Out }
}
function Show-Record {
    param($o)
    if ($null -eq $o) { return '(none)' }
    $parts = @()
    foreach ($k in @('timestamp', 'source', 'engine', 'event', 'dropped', 'users', 'lease_id', 'role', 'outcome', 'alert', 'alert_reason')) { if ($o.PSObject.Properties.Name -contains $k -and $null -ne $o.$k -and [string]$o.$k -ne '') { $parts += ('{0}={1}' -f $k, [string]$o.$k) } }
    return ($parts -join ' | ')
}

Write-Host ('Revocation checks: compose file {0}, project {1}' -f $P2ComposeFile, $P2Project)
foreach ($s in @('pg-primary', 'pg-replica', 'maria-primary', 'maria-replica', 'maria-sweeper', 'pg-sweeper', 'openbao', 'keycloak', 'fluent-bit', 'lease-reconciler')) { [void](Id $s) }
$st = Get-BaoStatus
if (($null -eq $st.Obj) -or $st.Obj.sealed) { throw 'OpenBao is sealed or not answering. Run scripts\phase4-setup.ps1.' }
$alice = Connect-Bao 'alice'
if (-not $alice.Token) { throw ('alice cannot log in to OpenBao: ' + $alice.R.All) }
$interval = [int](MaVal 'maria-replica' "SELECT INTERVAL_VALUE FROM information_schema.EVENTS WHERE EVENT_SCHEMA = 'replica_local' AND EVENT_NAME = 'revocation_backstop'")
$reconInterval = 60
foreach ($e in (ConvertFrom-Json (Invoke-Docker @('inspect', '-f', '{{json .Config.Env}}', (Id 'lease-reconciler'))).Out)) { if ($e -match '^RECONCILE_INTERVAL_SECONDS=(\d+)$') { $reconInterval = [int]$Matches[1] } }
$PgDenyGraceSeconds = 60
foreach ($e in (ConvertFrom-Json (Invoke-Docker @('inspect', '-f', '{{json .Config.Env}}', (Id 'pg-replica'))).Out)) { if ($e -match '^PG_DENY_RELEASE_GRACE_SECONDS=(\d+)$') { $PgDenyGraceSeconds = [int]$Matches[1] } }
Write-Host ('expiry backstop interval {0} s (lab; production proposal 300 s); reconciler interval {1} s (lab; production proposal 60 s); PostgreSQL deny-list release grace {2} s' -f $interval, $reconInterval, $PgDenyGraceSeconds)
# Clock offset Docker VM - Windows host: the poller and the purge line use the VM clock, the start
# command is timed on the host.
$h0 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$vmNow = [double]::Parse((Invoke-Docker @('exec', (Id 'maria-sweeper'), 'date', '+%s.%N')).Out.Trim(), $inv)
$h1 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$skew = $vmNow - (($h0 + $h1) / 2000.0)
Write-Host ('clock offset Docker VM minus host: {0:N3} s (+/- {1:N3} s)' -f $skew, (($h1 - $h0) / 2000.0))

# =============================================================================================
Write-Host ''
Write-Host '== Configuration: init_file, event, definer, reconciler placement =='
$r = MaSu 'maria-replica' "SELECT CONCAT('init_file=', @@init_file, ' event_scheduler=', @@event_scheduler, ' secure_file_priv=', @@secure_file_priv, ' read_only=', @@read_only)"
Assert-Works 'maria-replica: init_file set, event_scheduler ON, secure_file_priv limited to the backstop log directory, read_only ON' $r ('init_file=/etc/mysql/replica-init/init\.sql event_scheduler=ON secure_file_priv=' + [regex]::Escape($backstopDir) + '/ read_only=(1|ON)')
$r = MaSu 'maria-replica' "SELECT CONCAT(EVENT_SCHEMA, '.', EVENT_NAME, ' status=', STATUS, ' every=', INTERVAL_VALUE, ' ', INTERVAL_FIELD, ' definer=', DEFINER, ' originator=', ORIGINATOR, ' on_completion=', ON_COMPLETION) FROM information_schema.EVENTS ORDER BY 1"
Assert-Works 'maria-replica: the only event is replica_local.revocation_backstop, ENABLED, created locally (originator = server_id 2), definer revocation_backstop@localhost' $r '^replica_local\.revocation_backstop status=ENABLED every=\d+ SECOND definer=revocation_backstop@localhost originator=2 on_completion=PRESERVE$'
$maxTtlRole = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'database/roles/app1-maria-ro')).Out
$envMax = ''
foreach ($e in (ConvertFrom-Json (Invoke-Docker @('inspect', '-f', '{{json .Config.Env}}', (Id 'maria-replica'))).Out)) { if ($e -match '^BACKSTOP_(MAX_TTL|MARGIN|INTERVAL)_SECONDS=(\d+)$') { $envMax += ('{0}={1} ' -f $Matches[1], $Matches[2]) } }
$cmt = MaVal 'maria-replica' "SELECT EVENT_COMMENT FROM information_schema.EVENTS WHERE EVENT_NAME = 'revocation_backstop'"
$ok = ($null -ne $maxTtlRole) -and ($envMax -match ('MAX_TTL=' + [int]$maxTtlRole.data.max_ttl + ' ')) -and ($cmt -match ('max_ttl ' + [int]$maxTtlRole.data.max_ttl + ' s'))
Write-Result $ok ('backstop max_ttl equals the OpenBao role app1-maria-ro max_ttl ({0} s)' -f $maxTtlRole.data.max_ttl) ('replica environment: ' + $envMax + "`nevent comment: " + $cmt)
$g = MaSu 'maria-replica' "SHOW GRANTS FOR 'revocation_backstop'@'localhost'"
$ok = ($g.Code -eq 0) -and ($g.Out -match 'GRANT FILE, CREATE USER, CONNECTION ADMIN, READ_ONLY ADMIN, BINLOG ADMIN ON \*\.\* TO `revocation_backstop`@`localhost`') -and
      ($g.Out -match 'GRANT EVENT ON `replica_local`\.\* TO `revocation_backstop`@`localhost`') -and ($g.Out -match 'GRANT SELECT \(`Host`, `User`\) ON `mysql`\.`global_priv` TO `revocation_backstop`@`localhost`') -and
      (@($g.Out -split "`r?`n" | Where-Object { $_ -match '^GRANT' }).Count -eq 3) -and ($g.Out -notmatch 'SUPER|ALL PRIVILEGES|IDENTIFIED')
Write-Result $ok 'definer revocation_backstop@localhost: exactly CREATE USER, READ ONLY ADMIN, BINLOG ADMIN, CONNECTION ADMIN, FILE, SELECT (User, Host) ON mysql.global_priv, EVENT ON replica_local.*' $g.All
$r = Invoke-Docker @('exec', '-u', 'mysql', (Id 'maria-replica'), 'mariadb', '--protocol=socket', '--skip-ssl', '-urevocation_backstop', '-e', 'SELECT 1')
Assert-Refused 'definer revocation_backstop cannot log in (ACCOUNT LOCK, no password), not even over the local socket' $r 'account is locked'
$np = MaVal 'maria-primary' "SELECT CONCAT('accounts=', (SELECT COUNT(*) FROM mysql.global_priv WHERE User = 'revocation_backstop'), ' schema=', (SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'replica_local'), ' events=', (SELECT COUNT(*) FROM information_schema.EVENTS))"
$gb = MaVal 'maria-replica' 'SELECT @@gtid_binlog_state'
Write-Result (($np -eq 'accounts=0 schema=0 events=0') -and ($gb -notmatch '\b\d+-2-\d+')) 'the definer, the schema replica_local and the event exist on the replica only; the replica binlog has no local GTID' ('maria-primary: ' + $np + "; maria-replica gtid_binlog_state: " + $gb)
# Events that come from the primary by replication must not run on the replica.
$lev = 'lab_p4_repl_event_' + (Get-Date).ToString('HHmmss')
$pes = MaVal 'maria-primary' 'SELECT @@event_scheduler'
[void](MaSu 'maria-primary' ("CREATE EVENT app1.{0} ON SCHEDULE EVERY 1 HOUR ENABLE DO SELECT 1" -f $lev))
$gt = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
[void](MaVal 'maria-replica' ("SELECT MASTER_GTID_WAIT('{0}', 30)" -f $gt))
$rs = MaVal 'maria-replica' ("SELECT CONCAT(EVENT_SCHEMA, '.', EVENT_NAME, ' status=', STATUS, ' originator=', ORIGINATOR) FROM information_schema.EVENTS WHERE EVENT_NAME = '{0}'" -f $lev)
[void](MaSu 'maria-primary' ("DROP EVENT IF EXISTS app1.{0}" -f $lev))
$gt = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
[void](MaVal 'maria-replica' ("SELECT MASTER_GTID_WAIT('{0}', 30)" -f $gt))
$rs2 = MaVal 'maria-replica' ("SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_NAME = '{0}'" -f $lev)
Write-Result (($rs -match 'status=SLAVESIDE_DISABLED originator=1$') -and ($rs2 -eq '0')) 'an ENABLED event created on the primary arrives on the replica as SLAVESIDE_DISABLED (it does not run there although event_scheduler is ON); its DROP replicates' ('primary event_scheduler={0}; on the replica: {1}; after DROP EVENT on the primary: {2} rows' -f $pes, $rs, $rs2)
$rn = (Invoke-Docker @('inspect', '-f', '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}', (Id 'lease-reconciler'))).Out.Trim() -replace ($P2Project + '_'), ''
$nb = (Invoke-Docker @('network', 'inspect', '-f', '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}', $netRecon)).Out.Trim() -replace ($P2Project + '-'), '' -replace '-1=', '='
$ri = (Invoke-Docker @('inspect', '-f', 'user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} ports={{json .HostConfig.PortBindings}}', (Id 'lease-reconciler'))).Out.Trim()
$res = Invoke-Docker @('exec', (Id 'lease-reconciler'), 'sh', '-c', 'for h in maria-replica maria-replica-admin pg-primary pg-replica maria-primary keycloak openbao; do if nslookup $h >/dev/null 2>&1; then echo "$h=resolves"; else echo "$h=unresolved"; fi; done | tr "\n" " "')
$ok = ($rn -eq 'bao-reconciler=10.81.10.20') -and (@($nb -split '\s+' | Where-Object { $_ }).Count -eq 2) -and ($nb -match 'openbao=10\.81\.10\.10/24') -and ($nb -match 'lease-reconciler=10\.81\.10\.20/24') -and
      ($ri -match '^user=100:1000 read_only=true cap_drop=\[ALL\] ports=(\{\}|null)$') -and ($res.Out -match 'openbao=resolves') -and ($res.Out -notmatch '(maria|pg)-[a-z-]+=resolves|keycloak=resolves')
Write-Result $ok 'lease-reconciler: only on bao-reconciler (10.81.10.20), which holds only openbao (10.81.10.10); no database name resolves from it; non-root, read-only root fs, no capabilities, no published port' ('networks: ' + $rn + "`nbao-reconciler: " + $nb + "`n" + $ri + "`nname resolution: " + $res.All)

# =============================================================================================
Write-Host ''
Write-Host '== 1. Startup purge: revoke while maria-replica is down, then start it; order of purge and first connection =='
$cR = Get-Creds $alice.Token 'app1-maria-ro'   # revoked during the outage
$cV = Get-Creds $alice.Token 'app1-maria-ro'   # lease still valid
$okIssue = ($null -ne $cR.User) -and ($null -ne $cV.User) -and ((MaRows $cR.User) -eq '1') -and ((MaRows $cV.User) -eq '1')
$x1 = MaClient $cR.User 'SELECT 1' $cR.Password
Write-Result ($okIssue -and ($x1.Code -eq 0)) 'two MariaDB temp users issued (one to be revoked during the outage, one whose lease stays valid); control: the first can log in' ('{0}; {1}; login: exit {2}' -f $cR.User, $cV.User, $x1.Code)
$r = Compose @('stop', 'maria-replica')
$rq = BaoRoot @('lease', 'revoke', $cR.Lease)
$ttlQ = Get-LeaseTtl $cR.Lease
Write-Result (($r.Code -eq 0) -and ($rq.Code -eq 0) -and ($ttlQ -ne 'gone')) 'maria-replica stopped; "bao lease revoke" (asynchronous) of the first lease is accepted and queued (the lease stays, TTL 0)' ('stop exit {0}; revoke: {1}; lease TTL now {2}' -f $r.Code, (OneLine $rq.All), $ttlQ)
# The poller: from the maria-sweeper's network namespace (10.81.5.22) it tries, in a tight loop,
# session_sweeper (control: an account that exists and may connect from there), the revoked user
# and the still-valid user, and prints one line per attempt with the VM clock in epoch seconds.
$pollScript = @'
end=$(( $(date +%s) + DUR ))
while [ "$(date +%s)" -lt "$end" ]; do
  for who in sweeper revoked valid; do
    case $who in
      sweeper) u=session_sweeper; p="$SW_PW" ;;
      revoked) u="$R_USER"; p="$R_PW" ;;
      valid)   u="$V_USER"; p="$V_PW" ;;
    esac
    t=$(date +%s.%N)
    o=$(MYSQL_PWD="$p" mariadb -h maria-replica -u "$u" --ssl-ca=/ca/ca.crt --ssl-verify-server-cert --connect-timeout=2 -N -B -e 'SELECT UNIX_TIMESTAMP(NOW(6))' 2>&1); rc=$?
    e=$(date +%s.%N)
    echo "$t $e $who rc=$rc $(printf '%s' "$o" | tr '\n' ' ' | cut -c1-110)"
  done
done
'@
$poller = 'revpoll-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
[void]$script:Containers.Add($poller)
$penv = @{ DUR = [string]($PollSeconds + 5); SW_PW = (Read-P2Secret 'maria_session_sweeper_password'); R_USER = $cR.User; R_PW = $cR.Password; V_USER = $cV.User; V_PW = $cV.Password }
$pa = @('run', '-d', '--name', $poller, '--network', ('container:' + (Id 'maria-sweeper')), '-v', ($volCa + ':/ca:ro'))
foreach ($k in $penv.Keys) { $pa += @('-e', $k) }
$pa += @('--entrypoint', 'bash', 'mariadb:11.8', '-c', $pollScript)
[void](Invoke-Docker $pa $penv)
Start-Sleep -Seconds 4
# Host times converted to the VM clock.
$tStart = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0 + $skew
$r = Compose @('start', 'maria-replica')
$healthy = Wait-Healthy 'maria-replica' 150
$tHealthy = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0 + $skew
[void](Invoke-Docker @('wait', $poller) @{} ($PollSeconds + 60))
$plog = (Invoke-Docker @('logs', $poller)).Out
$lines = @($plog -split "`r?`n" | Where-Object { $_ -match '^\d+\.\d+ \d+\.\d+ (sweeper|revoked|valid) rc=' })
$purgeLine = (Invoke-Docker @('exec', (Id 'maria-replica'), 'sh', '-c', ('ls -1t ' + $backstopDir + '/startup-purge-*.log | head -n 1 | xargs cat'))).Out.Trim()
$tPurge = $null
if ($purgeLine -match '^(\S+Z) engine=mariadb action=startup-purge') { $tPurge = ConvertTo-Epoch $Matches[1] }
# An attempt is "answered" when the server sent anything (a login result: success, Access denied,
# host not allowed, account locked). The answer happened between the attempt's start and end
# (both VM clock). For a successful control login the server's own clock is printed too.
$firstAnsStart = $null; $firstAnsEnd = $null; $firstLoginServer = $null; $revokedOk = 0; $validOk = 0; $answeredBeforePurge = 0; $startedBeforePurgeAnswered = 0
foreach ($l in $lines) {
    $p = $l -split ' ', 5
    $ts = [double]::Parse($p[0], $inv); $te = [double]::Parse($p[1], $inv); $who = $p[2]; $rc = $p[3]; $msg = $p[4]
    $answered = ($rc -eq 'rc=0') -or ($msg -match 'Access denied|ERROR 1045|ERROR 1130|not allowed to connect|ERROR 4151')
    if ($answered) {
        if ($null -eq $firstAnsEnd) { $firstAnsStart = $ts; $firstAnsEnd = $te }
        if (($null -ne $tPurge) -and ($te -lt $tPurge)) { $answeredBeforePurge++ }
        if (($null -ne $tPurge) -and ($ts -lt $tPurge)) { $startedBeforePurgeAnswered++ }
    }
    if (($who -eq 'sweeper') -and ($rc -eq 'rc=0') -and ($null -eq $firstLoginServer) -and ($msg -match '^(\d+\.\d+)')) { $firstLoginServer = [double]::Parse($Matches[1], $inv) }
    if (($who -eq 'revoked') -and ($rc -eq 'rc=0')) { $revokedOk++ }
    if (($who -eq 'valid') -and ($rc -eq 'rc=0')) { $validOk++ }
}
$attemptGap = 0
if ($lines.Count -gt 1) { $attemptGap = [Math]::Round(([double]::Parse(($lines[-1] -split ' ')[0], $inv) - [double]::Parse(($lines[0] -split ' ')[0], $inv)) / $lines.Count * 1000, 0) }
$sample = @($lines | Where-Object { $_ -match ' (revoked|valid) ' -and $_ -match 'Access denied|not allowed' } | Select-Object -First 2)
$lastNoAnswer = @($lines | Where-Object { ($_ -notmatch ' rc=0') -and ($_ -notmatch 'Access denied|not allowed|ERROR 4151') } | Select-Object -Last 1)
$firstOk = @($lines | Where-Object { $_ -match ' sweeper rc=0' } | Select-Object -First 1)
$d = @(('poller: {0} attempts in {1} s, one every {2} ms on average (three accounts in turn); times are the VM clock' -f $lines.Count, ($PollSeconds + 5), $attemptGap),
      ('start command at {0:N3}; startup purge completed at {1:N3} (from its own log line: {2})' -f $tStart, $tPurge, $purgeLine),
      ('first answered attempt: started {0:N3}, answered by {1:N3}; attempts answered (ended) before the purge completed: {2}; attempts STARTED before the purge completed and answered only after it (held in the listen backlog while init_file ran): {3}' -f $firstAnsStart, $firstAnsEnd, $answeredBeforePurge, $startedBeforePurgeAnswered),
      ('first successful login of any account (session_sweeper), by the server''s own clock: {0:N6}; replica healthy at {1:N3}' -f $firstLoginServer, $tHealthy),
      ('last attempt without an answer: ' + ($lastNoAnswer -join '')), ('first successful login line: ' + ($firstOk -join '')),
      ('revoked user: successful logins {0}; still-valid user: successful logins {1}' -f $revokedOk, $validOk)) + @($sample | ForEach-Object { 'e.g. ' + $_ })
$ok = ($r.Code -eq 0) -and $healthy -and ($null -ne $tPurge) -and ($null -ne $firstAnsEnd) -and ($null -ne $firstLoginServer) -and ($answeredBeforePurge -eq 0) -and ($firstAnsEnd -gt $tPurge) -and ($firstLoginServer -gt $tPurge) -and ($revokedOk -eq 0) -and ($validOk -eq 0) -and ($lines.Count -ge 50)
Write-Result $ok 'ORDER: no connection attempt was answered before the startup purge completed, and the first session of any account ran after it (server clock); no login of the revoked (or the still-valid) temp user succeeded at any moment after the start' ($d -join "`n")
if (($null -ne $tPurge) -and ($null -ne $firstAnsEnd)) { Add-Measure ('startup purge completed {0:N3} s after the start command; first answer of the server {1:N3} s after the purge (that attempt had started {2:N3} s before it and waited in the listen backlog); first session of any account {3:N3} s after the purge by the server clock; poll resolution about {4} ms per attempt' -f ($tPurge - $tStart), ($firstAnsEnd - $tPurge), ($tPurge - $firstAnsStart), ($firstLoginServer - $tPurge), $attemptGap) }
$ok = ($purgeLine -match ('dropped=(\d+) users=\S*' + [regex]::Escape($cR.User))) -and ($purgeLine -match [regex]::Escape($cV.User)) -and ($purgeLine -match 'sql_log_bin=OFF read_only=ON') -and ((MaRows $cR.User) -eq '0') -and ((MaRows $cV.User) -eq '0')
Write-Result $ok 'the purge line names both temp users (the revoked one and the still-valid one) and ran with sql_log_bin=OFF on the read_only replica; both accounts are gone' $purgeLine
$gb = MaVal 'maria-replica' 'SELECT @@gtid_binlog_state'
Write-Result ($gb -notmatch '\b\d+-2-\d+') 'the purge left nothing in the replica''s binlog (no local GTID)' ('gtid_binlog_state ' + $gb)
Assert-Refused 'the revoked user cannot log in after the start' (MaClient $cR.User 'SELECT 1' $cR.Password) (MaRefused $cR.User)
Assert-Refused 'EXPECTED (documented): the user of a still-VALID lease is dropped by the restart too; the developer requests new credentials' (MaClient $cV.User 'SELECT 1' $cV.Password) (MaRefused $cV.User)
$f = Find-InStore @('"alert":"replica_startup_purge"', $cR.User) 'alerts.jsonl'
Write-Result ($f.Objects.Count -ge 1) 'alert replica_startup_purge shipped for the non-zero purge' (Show-Record ($f.Objects | Select-Object -Last 1))
$rvV = BaoRoot @('lease', 'revoke', '-sync', $cV.Lease)
Write-Result (($rvV.Code -eq 0) -and (-not (Test-LeaseExists $cV.Lease))) 'OpenBao''s later revocation of the still-valid lease succeeds (KILL USER matches nothing, DROP USER IF EXISTS) and the lease is gone' (OneLine $rvV.All)
# The revoked lease: completed by OpenBao's retry or by the reconciler (the timing case is below).
$dl = (Get-Date).AddSeconds($ReconcileWaitSeconds)
while ((Test-LeaseExists $cR.Lease) -and ((Get-Date) -lt $dl)) { Start-Sleep -Seconds 2 }
Write-Result (-not (Test-LeaseExists $cR.Lease)) 'the lease revoked during the outage is gone after the start (OpenBao retry or reconciler; timed in section 3)' ''

# =============================================================================================
Write-Host ''
Write-Host '== 2. Expiry backstop (local event): backdated lab user, fresh user, other accounts =='
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$old = $now - 14400 - 300 - 600     # older than max_ttl + margin
$uOld = 'v-lab-backstop-app1-maria-ro-' + $old + '-' + (New-Suffix)
$uNew = 'v-lab-fresh-app1-maria-ro-' + ($now - 60) + '-' + (New-Suffix)
$uOdd = 'v-lab-nostamp-' + (New-Suffix)
$uNonV = 'lab-old-' + $old + '-' + (New-Suffix)
$pwOld = New-LabPassword
$othersBefore = MaVal 'maria-replica' "SELECT GROUP_CONCAT(CONCAT(User, '@', Host) ORDER BY User, Host SEPARATOR ' ') FROM mysql.global_priv WHERE User NOT LIKE 'v-%' AND User NOT LIKE 'lab-old-%'"
# Disable the event while the lab user and its session are set up, so the timing starts at a known point.
[void](MaSu 'maria-replica' ($evAlter + ' DISABLE'))
$cr = @()
foreach ($u in @($uOld, $uNew, $uOdd, $uNonV)) { $cr += ('{0}: {1}' -f $u, (OneLine (New-LabMariaUser $u $pwOld).All)) }
$sOld = Start-MaSession $uOld $pwOld 'backstop' 50
$rows = @($uOld, $uNew, $uOdd, $uNonV | ForEach-Object { MaRows $_ }) -join ','
Write-Result (($rows -eq '1,1,1,1') -and ($sOld.Id -ne '0')) 'lab accounts created locally (sql_log_bin = 0, hash-only password): a v- user created 5 h 15 min ago (by its name), a fresh v- user, a v- name without a timestamp, a non-v- name with an old timestamp; an open session of the backdated user' (('rows ' + $rows + '; session id ' + $sOld.Id) + "`n" + ($cr -join "`n"))
$since = UtcStamp
$t0 = Get-Date
[void](MaSu 'maria-replica' ($evAlter + ' ENABLE'))
$goneAt = $null; $sessGoneAt = $null
$dl = $t0.AddSeconds($interval + $EventSlackSeconds + 5)
while ((Get-Date) -lt $dl) {
    if ((-not $goneAt) -and ((MaRows $uOld) -eq '0')) { $goneAt = Get-Date }
    if ((-not $sessGoneAt) -and (-not (Test-MaIdAlive $sOld.Id))) { $sessGoneAt = Get-Date }
    if ($goneAt -and $sessGoneAt) { break }
    Start-Sleep -Milliseconds 300
}
$gS = -1; if ($goneAt) { $gS = [Math]::Round(($goneAt - $t0).TotalSeconds, 1) }
$sS = -1; if ($sessGoneAt) { $sS = [Math]::Round(($sessGoneAt - $t0).TotalSeconds, 1) }
$clog = Get-ContainerLog $sOld.Name
$okDrop = ($gS -ge 0) -and ($gS -le ($interval + $EventSlackSeconds)) -and ($sS -ge 0) -and ($sS -le ($interval + $EventSlackSeconds)) -and ($clog -notmatch 'STILL ALIVE') -and ($clog -match 'Lost connection|server has gone away|Connection was killed|killed')
Write-Result $okDrop ('the backdated v- user was dropped {0} s and its open session killed {1} s after the event was enabled (limit: interval {2} s + {3} s)' -f $gS, $sS, $interval, $EventSlackSeconds) ('client saw: ' + (OneLine $clog))
Add-Measure ('expiry backstop: backdated user dropped {0} s, its session killed {1} s after the event was enabled (event interval {2} s)' -f $gS, $sS, $interval)
$rows = @($uNew, $uOdd, $uNonV | ForEach-Object { MaRows $_ }) -join ','
$othersAfter = MaVal 'maria-replica' "SELECT GROUP_CONCAT(CONCAT(User, '@', Host) ORDER BY User, Host SEPARATOR ' ') FROM mysql.global_priv WHERE User NOT LIKE 'v-%' AND User NOT LIKE 'lab-old-%'"
Write-Result (($rows -eq '1,1,1') -and ($othersBefore -eq $othersAfter)) 'the fresh v- user, the v- name without a timestamp and the old-stamped non-v- account are untouched; every other account is unchanged' ('rows {0}; accounts other than v-/lab-old-: {1}' -f $rows, $othersAfter)
$bl = (Invoke-Docker @('exec', (Id 'maria-replica'), 'sh', '-c', ('ls -1t ' + $backstopDir + '/expiry-drop-*.log | head -n 1 | xargs cat'))).Out.Trim()
$gb = MaVal 'maria-replica' 'SELECT @@gtid_binlog_state'
Write-Result (($bl -match ('action=expiry-drop dropped=1 users=' + [regex]::Escape($uOld) + ' max_ttl=14400 margin=\d+ sql_log_bin=OFF')) -and ($gb -notmatch '\b\d+-2-\d+')) 'the event logged the drop (one line, written by the server with INTO OUTFILE) and ran with sql_log_bin=OFF: no local GTID in the replica binlog' ($bl + "`ngtid_binlog_state " + $gb)
$f = Find-InStore @('"alert":"replica_expiry_backstop"', $uOld) 'alerts.jsonl'
Write-Result ($f.Objects.Count -ge 1) 'alert replica_expiry_backstop shipped (OpenBao failed to revoke)' (Show-Record ($f.Objects | Select-Object -Last 1))
$al = (Invoke-Docker @('exec', (Id 'maria-replica'), 'sh', '-c', ('grep -a -c -F "' + $uOld + '" /var/log/mariadb-audit/server_audit.log'))).Out.Trim()
Note ('server_audit lines naming the backdated user (its CREATE USER by root and its session; the event''s own statements are NOT audited by server_audit, measured): ' + $al + '. The audit record of the drop is the shipped backstop line.')
[void](MaSu 'maria-replica' ("SET SESSION sql_log_bin = 0; DROP USER IF EXISTS '{0}'@'{1}', '{2}'@'{1}', '{3}'@'{1}', '{4}'@'{1}'" -f $uOld, $accessMask, $uNew, $uOdd, $uNonV))

Write-Host ''
Write-Host '== 2b. Each privilege of the event definer, removed one at a time (event every 1 s meanwhile) =='
[void](MaSu 'maria-replica' ($evAlter + ' ON SCHEDULE EVERY 1 SECOND'))
$restore = "SET SESSION sql_log_bin = 0; GRANT CREATE USER, READ ONLY ADMIN, BINLOG ADMIN, CONNECTION ADMIN, FILE ON *.* TO 'revocation_backstop'@'localhost'; GRANT SELECT (User, Host) ON mysql.global_priv TO 'revocation_backstop'@'localhost'; GRANT EVENT ON replica_local.* TO 'revocation_backstop'@'localhost'"
$cases = @(
    @{ P = 'CREATE USER'; Revoke = "REVOKE CREATE USER ON *.* FROM 'revocation_backstop'@'localhost'"; Expect = 'kept'; Err = 'CREATE USER privilege' },
    @{ P = 'READ ONLY ADMIN'; Revoke = "REVOKE READ ONLY ADMIN ON *.* FROM 'revocation_backstop'@'localhost'"; Expect = 'kept'; Err = 'read-only' },
    @{ P = 'BINLOG ADMIN'; Revoke = "REVOKE BINLOG ADMIN ON *.* FROM 'revocation_backstop'@'localhost'"; Expect = 'kept'; Err = 'BINLOG ADMIN' },
    @{ P = 'SELECT (User, Host) ON mysql.global_priv'; Revoke = "REVOKE SELECT (User, Host) ON mysql.global_priv FROM 'revocation_backstop'@'localhost'"; Expect = 'kept'; Err = 'global_priv' },
    @{ P = 'EVENT ON replica_local.*'; Revoke = "REVOKE EVENT ON replica_local.* FROM 'revocation_backstop'@'localhost'"; Expect = 'kept'; Err = "database 'replica_local'|failed to authenticate the user" },
    @{ P = 'FILE'; Revoke = "REVOKE FILE ON *.* FROM 'revocation_backstop'@'localhost'"; Expect = 'dropped-nolog'; Err = 'FILE' },
    @{ P = 'CONNECTION ADMIN'; Revoke = "REVOKE CONNECTION ADMIN ON *.* FROM 'revocation_backstop'@'localhost'"; Expect = 'dropped-session-survives'; Err = '' })
foreach ($c in $cases) {
    $u = 'v-lab-matrix-app1-maria-ro-' + $old + '-' + (New-Suffix)
    $pw = New-LabPassword
    [void](MaSu 'maria-replica' ($evAlter + ' DISABLE'))
    [void](New-LabMariaUser $u $pw)
    $sess = $null
    if ($c.Expect -eq 'dropped-session-survives') { $sess = Start-MaSession $u $pw 'matrix' 30 }
    [void](MaSu 'maria-replica' ('SET SESSION sql_log_bin = 0; ' + $c.Revoke))
    $filesBefore = (Invoke-Docker @('exec', (Id 'maria-replica'), 'sh', '-c', ('ls ' + $backstopDir + ' | wc -l'))).Out.Trim()
    $since = UtcStamp 0
    [void](MaSu 'maria-replica' ($evAlter + ' ENABLE'))
    Start-Sleep -Seconds 4
    [void](MaSu 'maria-replica' ($evAlter + ' DISABLE'))
    $rows = MaRows $u
    $filesAfter = (Invoke-Docker @('exec', (Id 'maria-replica'), 'sh', '-c', ('ls ' + $backstopDir + ' | wc -l'))).Out.Trim()
    $err = @(((Invoke-Docker @('logs', '--since', $since, (Id 'maria-replica'))).All -split "`r?`n") | Where-Object { $_ -match 'Event Scheduler' -and $_ -match 'ERROR' } | Select-Object -First 1) -join ''
    $alive = $false; if ($sess) { $alive = Test-MaIdAlive $sess.Id }
    [void](MaSu 'maria-replica' $restore)
    Drop-LabMariaUser $u
    if ($sess) { [void](MaSu 'maria-replica' ("KILL CONNECTION {0}" -f $sess.Id)) }
    switch ($c.Expect) {
        'kept' { $ok = ($rows -eq '1') -and ($err -match $c.Err); $what = 'the event fails, the user stays' }
        'dropped-nolog' { $ok = ($rows -eq '0') -and ($filesAfter -eq $filesBefore) -and ($err -match $c.Err); $what = 'the user is dropped but the log line (INTO OUTFILE) fails: no record, no alert' }
        'dropped-session-survives' { $ok = ($rows -eq '0') -and $alive; $what = 'the user is dropped but KILL USER silently kills nothing: the open session survives (the sweeper would end it later)' }
    }
    Write-Result $ok ('without {0}: {1}' -f $c.P, $what) ('user rows {0}; backstop files {1} -> {2}; session alive {3}; error log: {4}' -f $rows, $filesBefore, $filesAfter, $alive, (OneLine $err 260))
}
$g2 = MaSu 'maria-replica' "SHOW GRANTS FOR 'revocation_backstop'@'localhost'"
Write-Result ($g2.Out -eq $g.Out) 'definer privileges restored exactly' ''

Write-Host ''
Write-Host '== 2c. Plain restart of maria-replica: the init_file restores the event and the definer, and drops a still-valid user =='
$cP2 = Get-Creds $alice.Token 'app1-maria-ro'
[void](MaSu 'maria-replica' "SET SESSION sql_log_bin = 0; REVOKE FILE ON *.* FROM 'revocation_backstop'@'localhost'")
$r = Compose @('restart', 'maria-replica')
$h = Wait-Healthy 'maria-replica' 150
$ev = MaVal 'maria-replica' "SELECT CONCAT('status=', STATUS, ' every=', INTERVAL_VALUE) FROM information_schema.EVENTS WHERE EVENT_NAME = 'revocation_backstop'"
$g3 = MaSu 'maria-replica' "SHOW GRANTS FOR 'revocation_backstop'@'localhost'"
$pl = (Invoke-Docker @('exec', (Id 'maria-replica'), 'sh', '-c', ('ls -1t ' + $backstopDir + '/startup-purge-*.log | head -n 1 | xargs cat'))).Out.Trim()
Write-Result ($h -and ($ev -eq ('status=ENABLED every=' + $interval)) -and ($g3.Out -eq $g.Out) -and ((MaRows $cP2.User) -eq '0') -and ($pl -match [regex]::Escape($cP2.User))) 'after "docker compose restart maria-replica": event ENABLED with its configured interval again, definer privileges as configured (a revoked FILE came back), the still-valid user was purged' ('event ' + $ev + "`npurge: " + $pl)
Assert-Refused 'the still-valid user cannot log in after the restart (documented: request new credentials)' (MaClient $cP2.User 'SELECT 1' $cP2.Password) (MaRefused $cP2.User)
$rv = BaoRoot @('lease', 'revoke', '-sync', $cP2.Lease)
Write-Result (($rv.Code -eq 0) -and (-not (Test-LeaseExists $cP2.Lease))) 'its lease is still revocable afterwards (bao lease revoke -sync succeeds, lease gone)' (OneLine $rv.All)

# =============================================================================================
# PostgreSQL replica deny list (config/postgres/pg-deny-watcher.sh): helpers.
$denyFile = '/var/lib/postgresql/pg-deny/denied_roles'
$denyLogPath = '/var/log/pgaudit/pg-deny/pg-deny-watcher.log'
function VmNow { return [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0 + $skew }
function DenyFile { return (Invoke-Docker @('exec', (Id 'pg-replica'), 'cat', $denyFile)).Out.Trim() }
function DenyTokens { return @((DenyFile) -split "`r?`n" | Where-Object { $_.Trim() -and -not $_.StartsWith('#') }) }
function DenyLog {
    param([string]$Since)
    $s = $Since.Substring(0, 19)
    return @(((Invoke-Docker @('exec', (Id 'pg-replica'), 'cat', $denyLogPath)).Out -split "`r?`n") | Where-Object { ($_ -match '^\d{4}-\d\d-\d\dT[\d:.]+Z engine=postgresql ') -and ($_.Substring(0, 19) -ge $s) })
}
function Descriptors { return @(((Invoke-Docker @('exec', (Id 'lease-reconciler'), 'ls', '-1A', '/pg-deny')).Out -split "`r?`n") | Where-Object { $_.Trim() }) }
function HbaLine2 { return PgVal 'pg-replica' "SELECT line_number || ':' || array_to_string(user_name, ',') || ':' || coalesce(address, 'all') || ':' || auth_method || ':' || coalesce(error, 'no error') FROM pg_hba_file_rules WHERE line_number = 2" }
function NameTs { param([string]$U) if ($U -match '-(\d{10})-[A-Za-z0-9]{4}$') { return [long]$Matches[1] }; return -1 }
function LogTs { param([string]$L) if ($L -match '^(\S+Z) ') { return ConvertTo-Epoch $Matches[1] }; return $null }
# The deny-list watcher's processes inside pg-replica: @{ tini; supervise; watch } (pids).
$psWatch = 'ps -eo pid,args | awk ''$2 == "tini" {print "tini", $1} $2 == "bash" && $3 == "/opt/replica/pg-deny-watcher.sh" {print $4, $1}'''
function WatcherProcs {
    $h = @{}
    foreach ($l in ((Invoke-Docker @('exec', (Id 'pg-replica'), 'sh', '-c', $psWatch)).Out -split "`r?`n")) { $p = $l.Trim() -split '\s+'; if ($p.Count -eq 2) { $h[$p[0]] = $p[1] } }
    return $h
}
# Abnormal child exits seen by the postmaster (each one restarts every session).
function CrashLines { return [int]((Invoke-Docker @('exec', (Id 'pg-replica'), 'sh', '-c', 'cat /var/log/pgaudit/*.json | grep -c -E "server process \(PID [0-9]+\) (was terminated by|exited with exit code)"')).Out.Trim()) }
# Two PostgreSQL temp roles issued at the same moment (two parallel requests in the openbao container).
# Each subshell writes its JSON and the newline in ONE printf (under PIPE_BUF, so atomic); with a
# separate echo the two outputs interleaved and neither line parsed (measured).
$pairScript = 'for i in 1 2; do (j="$(bao read -format=json database/creds/app1-pg-ro | tr -d "\n")"; printf "%s\n" "$j") & done; wait'
function Get-CredsPair {
    $x = Invoke-Docker @('exec', '-e', 'BAO_TOKEN', (Id 'openbao'), 'sh', '-c', $pairScript) @{ BAO_TOKEN = $alice.Token }
    $out = @()
    foreach ($l in ($x.Out -split "`r?`n")) { $o = ConvertFrom-JsonOrNull $l; if (($null -ne $o) -and $o.data.username) { $out += , @{ User = [string]$o.data.username; Password = [string]$o.data.password; Lease = [string]$o.lease_id } } }
    return , $out
}
# Long-running PostgreSQL session on the replica; returns @{ Name; Pid }.
function Start-PgSession {
    param($C, [string]$Tag, [int]$Rounds = 8)
    $n = 'revsess-pg-' + $Tag + '-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    [void]$script:Containers.Add($n)
    $a = @('run', '-d', '--name', $n, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD', '--entrypoint', 'psql', 'postgres:17', ($pgReplicaConn + ' user=' + $C.User + ' application_name=revsess'), '-X', '-At', '-c', 'SELECT pg_backend_pid()')
    for ($i = 0; $i -lt $Rounds; $i++) { $a += @('-c', 'SELECT pg_sleep(50)') }
    $a += @('-c', "SELECT 'STILL ALIVE'")
    [void](Invoke-Docker $a @{ PGPASSWORD = $C.Password })
    $p = '0'; $dl = (Get-Date).AddSeconds(20)
    do { Start-Sleep -Milliseconds 300; $p = PgVal 'pg-replica' ("SELECT coalesce(max(pid), 0) FROM pg_stat_activity WHERE usename = '{0}' AND application_name = 'revsess'" -f $C.User) } while (($p -eq '0') -and ((Get-Date) -lt $dl))
    return @{ Name = $n; Pid = $p }
}
function Test-PgPidAlive { param([string]$P) return ((PgVal 'pg-replica' ("SELECT count(*) FROM pg_stat_activity WHERE pid = {0}" -f $P)) -eq '1') }
# Login poller on the access network: the revoked role, a still-valid role of another second and
# a still-valid role of the SAME second as the revoked one, in turn, one line per attempt with the
# VM clock: "<start> <end> <who> rc=<n> <answer>".
$pgPollScript = @'
end=$(( $(date +%s) + DUR ))
while [ "$(date +%s)" -lt "$end" ]; do
  for who in revoked valid sibling; do
    case $who in
      revoked) u="$R_USER"; p="$R_PW" ;;
      valid)   u="$V_USER"; p="$V_PW" ;;
      sibling) u="$S_USER"; p="$S_PW" ;;
    esac
    t=$(date +%s.%N)
    o=$(PGPASSWORD="$p" psql "host=pg-replica dbname=app1 user=$u sslmode=verify-full sslrootcert=/ca/ca.crt connect_timeout=2 application_name=revpoll" -XAt -c "SELECT 'login-ok'" 2>&1); rc=$?
    e=$(date +%s.%N)
    echo "$t $e $who rc=$rc $(printf '%s' "$o" | tr '\n' ' ' | cut -c1-150)"
  done
  sleep 0.3
done
'@
function Get-PollLines {
    param([string]$Name)
    $o = @()
    foreach ($l in ((Invoke-Docker @('logs', $Name)).Out -split "`r?`n")) {
        if ($l -match '^(\d+\.\d+) (\d+\.\d+) (revoked|valid|sibling) rc=(\d+) ?(.*)$') {
            $s0 = $Matches[1]; $e0 = $Matches[2]; $who = $Matches[3]; $rc0 = $Matches[4]; $msg = $Matches[5]
            $o += , @{ S = [double]::Parse($s0, $inv); E = [double]::Parse($e0, $inv); Who = $who; Ok = (($rc0 -eq '0') -and ($msg -match 'login-ok')); Hba = ($msg -match 'pg_hba\.conf rejects connection'); Msg = $msg }
        }
    }
    return , $o
}

# =============================================================================================
Write-Host ''
Write-Host ('== 3. Reconciler and PostgreSQL replica deny list: revocations queued while maria-replica AND pg-primary are down (outage at least {0} s) ==' -f $OutageSeconds)
$cM = Get-Creds $alice.Token 'app1-maria-ro'
# R (revoked during the outage) and S (lease stays valid) issued in the same second; V (valid)
# issued 4 s later, outside R's timestamp window.
$cG = $null; $cS = $null; $pairTries = 0
while (($null -eq $cS) -and ($pairTries -lt 6)) {
    $pairTries++
    $pp = Get-CredsPair
    if (($pp.Count -eq 2) -and ((NameTs $pp[0].User) -eq (NameTs $pp[1].User)) -and ((NameTs $pp[0].User) -gt 0)) { $cG = $pp[0]; $cS = $pp[1] }
    else {
        foreach ($c in $pp) { [void](BaoRoot @('lease', 'revoke', '-sync', $c.Lease)) }
        # A lease of a failed attempt that could not be parsed stays until the token is revoked; wait
        # past the timestamp window so it can never share R's pattern.
        Start-Sleep -Seconds 5
    }
}
Start-Sleep -Seconds 4
$cV = Get-Creds $alice.Token 'app1-pg-ro'
$dl = (Get-Date).AddSeconds(60)
$q = "SELECT count(*) FROM pg_roles WHERE rolname IN ('{0}', '{1}', '{2}')" -f $cG.User, $cS.User, $cV.User
while (((PgVal 'pg-replica' $q) -ne '3') -and ((Get-Date) -lt $dl)) { Start-Sleep -Milliseconds 300 }
$validUntil = PgVal 'pg-replica' ("SELECT rolvaliduntil FROM pg_roles WHERE rolname = '{0}'" -f $cG.User)
$tokens0 = @(DenyTokens)
$okPre = ($null -ne $cS) -and ((PgVal 'pg-replica' $q) -eq '3') -and ((NameTs $cV.User) -gt (NameTs $cG.User) + 3) -and ($tokens0.Count -eq 1) -and ($tokens0[0] -eq '/^$') -and (@(Descriptors).Count -eq 0)
Write-Result $okPre 'three PostgreSQL temp roles on pg-replica: R (to be revoked) and S (stays valid) issued in the SAME second, V (stays valid) 4 s later; the deny list holds only the sentinel /^$; no descriptor' ('R {0}; S {1}; V {2} (pair attempts {3}); deny list: {4}; descriptors: {5}' -f $cG.User, $cS.User, $cV.User, $pairTries, ($tokens0 -join ' '), @(Descriptors).Count)
$sR = Start-PgSession $cG 'revoked'
$sV = Start-PgSession $cV 'valid'
$poller = 'revpoll-pg-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
[void]$script:Containers.Add($poller)
$penv = @{ DUR = '1500'; R_USER = $cG.User; R_PW = $cG.Password; V_USER = $cV.User; V_PW = $cV.Password; S_USER = $cS.User; S_PW = $cS.Password }
$pa = @('run', '-d', '--name', $poller, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'))
foreach ($k in $penv.Keys) { $pa += @('-e', $k) }
$pa += @('--entrypoint', 'bash', 'postgres:17', '-c', $pgPollScript)
[void](Invoke-Docker $pa $penv)
Start-Sleep -Seconds 3
$since = UtcStamp 2
$r1 = Compose @('stop', 'maria-replica', 'pg-primary')
$tDown = Get-Date
$rM = BaoRoot @('lease', 'revoke', $cM.Lease)
$tRevokeVm = VmNow
$rG = BaoRoot @('lease', 'revoke', $cG.Lease)
$tRevoke = Get-Date
Write-Result (($r1.Code -eq 0) -and ($rM.Code -eq 0) -and ($rG.Code -eq 0) -and (Test-LeaseExists $cM.Lease) -and (Test-LeaseExists $cG.Lease) -and ($sR.Pid -ne '0') -and ($sV.Pid -ne '0')) 'maria-replica and pg-primary stopped; the MariaDB lease and R''s lease revoked asynchronously; OpenBao keeps both (revocation queued); open replica sessions of R and V' ('maria {0} ttl {1}; R ttl {2}; sessions R pid {3}, V pid {4}; R''s VALID UNTIL (the former bound of the exposure): {5}' -f $cM.User, (Get-LeaseTtl $cM.Lease), (Get-LeaseTtl $cG.Lease), $sR.Pid, $sV.Pid, $validUntil)
# Wait for the deny: descriptor (reconciler), deny-applied (watcher), R's session gone.
$descAt = $null; $appliedLine = $null; $sessGoneAt = $null
$dl = (Get-Date).AddSeconds($reconInterval * 2 + 30)
while ((Get-Date) -lt $dl) {
    if (-not $appliedLine) { $appliedLine = @(DenyLog $since | Where-Object { $_ -match 'action=deny-applied ' -and $_ -match ('users=\S*' + [regex]::Escape($cG.User)) }) | Select-Object -First 1 }
    if ((-not $sessGoneAt) -and (-not (Test-PgPidAlive $sR.Pid))) { $sessGoneAt = VmNow }
    if ($appliedLine -and $sessGoneAt) { break }
    Start-Sleep -Milliseconds 500
}
Start-Sleep -Seconds 4
$rl = Get-ReconLog $since
$wl = @(($rl -split "`r?`n") | Where-Object { $_ -match ('action=pg-deny-written lease=' + [regex]::Escape($cG.Lease) + ' role=app1-pg-ro issued=\d+ outcome=ok') } | Select-Object -First 1)
$tDesc = $null; if ($wl.Count -ge 1) { $tDesc = LogTs $wl[0] }
$tApplied = $null; if ($appliedLine) { $tApplied = LogTs $appliedLine }
$pl = Get-PollLines $poller
$rAfter = @($pl | Where-Object { ($_.Who -eq 'revoked') -and ($_.S -ge $tRevokeVm) })
$firstHba = @($rAfter | Where-Object { $_.Hba } | Select-Object -First 1)
$lastOk = @($rAfter | Where-Object { $_.Ok } | Select-Object -Last 1)
$okAfterDeny = 0; if ($firstHba.Count -ge 1) { $okAfterDeny = @($rAfter | Where-Object { $_.Ok -and ($_.S -ge $firstHba[0].E) }).Count }
$refS = -1; if ($firstHba.Count -ge 1) { $refS = [Math]::Round($firstHba[0].E - $tRevokeVm, 1) }
$lastOkS = -1; if ($lastOk.Count -ge 1) { $lastOkS = [Math]::Round($lastOk[0].E - $tRevokeVm, 1) }
$descS = -1; if ($tDesc) { $descS = [Math]::Round($tDesc - $tRevokeVm, 1) }
$appS = -1; if ($tApplied) { $appS = [Math]::Round($tApplied - $tRevokeVm, 1) }
$sessS = -1; if ($sessGoneAt) { $sessS = [Math]::Round($sessGoneAt - $tRevokeVm, 1) }
$sessLog = Get-ContainerLog $sR.Name
$d = @(('reconciler descriptor: {0}' -f (($wl | ForEach-Object { OneLine $_ 220 }) -join '')), ('watcher: ' + (OneLine $appliedLine 400)),
       ('R''s logins after the revoke: {0} attempts, last success {1} s after the revoke, first pg_hba refusal answered {2} s after it; successes after that refusal: {3}' -f $rAfter.Count, $lastOkS, $refS, $okAfterDeny),
       ('refusal: ' + (($firstHba | ForEach-Object { OneLine $_.Msg 200 }) -join '')),
       ('R''s open session ended {0} s after the revoke; the client saw: {1}' -f $sessS, (OneLine $sessLog 200)))
$ok = ($descS -ge 0) -and ($appS -ge 0) -and ($refS -ge 0) -and ($okAfterDeny -eq 0) -and ($sessS -ge 0) -and ($sessLog -notmatch 'STILL ALIVE') -and ($sessLog -match 'terminating connection due to administrator command') -and ($appliedLine -match 'terminated=1 ')
Write-Result $ok ('DENY: during the primary outage pg-replica refused the revoked role {0} s after the revoke (descriptor +{1} s, watcher +{2} s); no login of it succeeded after that; its open session was terminated +{3} s' -f $refS, $descS, $appS, $sessS) ($d -join "`n")
Add-Measure ('PostgreSQL deny during a primary outage: revoked role refused on pg-replica {0} s after the revoke (reconciler descriptor +{1} s, interval {2} s; watcher deny +{3} s, interval 2 s); open session terminated +{4} s; formerly it logged in until VALID UNTIL {5}' -f $refS, $descS, $reconInterval, $appS, $sessS, $validUntil)
$vAfter = @($pl | Where-Object { ($_.Who -eq 'valid') -and ($_.S -ge $tRevokeVm) })
$vOk = @($vAfter | Where-Object { $_.Ok }).Count
$sAfter = @($pl | Where-Object { ($_.Who -eq 'sibling') -and $tApplied -and ($_.S -ge ($tApplied + 1)) })
$sRef = @($sAfter | Where-Object { $_.Hba }).Count
Write-Result (($vAfter.Count -ge 3) -and ($vOk -eq $vAfter.Count) -and (Test-PgPidAlive $sV.Pid)) ('the still-valid role V (issued 4 s later) kept logging in ({0} of {1}) and its open session stayed' -f $vOk, $vAfter.Count) ''
$ok = ($appliedLine -match 'matched=2 ') -and ($appliedLine -match 'over_deny=1') -and ($appliedLine -match [regex]::Escape($cS.User)) -and ($sAfter.Count -ge 2) -and ($sRef -eq $sAfter.Count)
Write-Result $ok ('OVER-DENY (documented): S, a still-valid role issued in the same second as R, is refused too ({0} of {1} attempts after the deny); the watcher logs matched=2 over_deny=1' -f $sRef, $sAfter.Count) (($sAfter | Select-Object -First 1 | ForEach-Object { OneLine $_.Msg 200 }) -join '')
$tok1 = @(DenyTokens)
$descs = @(Descriptors)
$dc = (Invoke-Docker @('exec', (Id 'lease-reconciler'), 'sh', '-c', 'cd /pg-deny && for f in *.deny; do stat -c "%n %u:%g %a %s" "$f"; cat "$f"; done')).Out.Trim()
$hl = HbaLine2
$ok = ($descs.Count -eq 1) -and ($descs[0] -eq ('app1-pg-ro.' + ($cG.Lease -split '/')[-1] + '.deny')) -and ($dc -match ' 100:1000 644 \d+\s+v1 app1-pg-ro \d{10}$') -and ($tok1.Count -eq 2) -and ($tok1[0] -eq '/^$') -and ($tok1[1] -match '^/\^v-\.\+-app1-pg-ro-\(\d{10}(\|\d{10}){3}\)-\[A-Za-z0-9\]\{4\}\$$') -and ($hl -match '^2:/\^\$,/\^v-.*:all:reject:no error$')
Write-Result $ok 'one descriptor (R''s lease only: none for the MariaDB lease), owner 100:1000 mode 644, body "v1 <role> <issue second>"; the deny list holds the sentinel and one /^v-...$ pattern; pg_hba line 2 loaded it without error' ('descriptors: ' + ($descs -join ' ') + "`n" + $dc + "`ndeny list: " + ($tok1 -join ' ') + "`npg_hba_file_rules line 2: " + $hl)
$f = Find-InStore @('"alert":"pg_replica_deny_applied"', $cG.User) 'alerts.jsonl'
Write-Result ($f.Objects.Count -ge 1) 'alert pg_replica_deny_applied shipped (source pg-replica, users = the denied roles)' ((Show-Record ($f.Objects | Select-Object -Last 1)) + ' | users=' + [string](($f.Objects | Select-Object -Last 1).users))

Write-Host ''
Write-Host '== 3b. Deny-list watcher robustness (primary still down) =='
$wp = WatcherProcs
$crash0 = CrashLines
$sinceK = UtcStamp 1
[void](Invoke-Docker @('exec', (Id 'pg-replica'), 'kill', '-9', [string]$wp['watch']))
$wp2 = $null; $dl = (Get-Date).AddSeconds(15)
do { Start-Sleep -Milliseconds 500; $wp2 = WatcherProcs } while (((-not $wp2['watch']) -or ($wp2['watch'] -eq $wp['watch'])) -and ((Get-Date) -lt $dl))
Start-Sleep -Seconds 3
$kl = @(DenyLog $sinceK | Where-Object { $_ -match 'action=(watcher-restarted|watcher-start)' })
$okK = ($wp2['watch'] -and ($wp2['watch'] -ne $wp['watch'])) -and ($wp2['supervise'] -eq $wp['supervise']) -and ((CrashLines) -eq $crash0) -and (Test-PgPidAlive $sV.Pid) -and (@(DenyTokens).Count -eq 2) -and (@($kl | Where-Object { $_ -match 'action=watcher-restarted rc=137' }).Count -eq 1)
Write-Result $okK 'kill -9 of the watcher: the supervisor restarts it (logged, rc=137); no postmaster crash-restart (V''s session survives), the deny list is unchanged' (('before: tini {0} supervise {1} watch {2}; after: tini {3} supervise {4} watch {5}; postmaster abnormal-exit lines {6} -> {7}' -f $wp['tini'], $wp['supervise'], $wp['watch'], $wp2['tini'], $wp2['supervise'], $wp2['watch'], $crash0, (CrashLines)) + "`n" + (($kl | ForEach-Object { OneLine $_ 220 }) -join "`n"))
$f = Find-InStore @('"alert":"pg_deny_watcher_failed"', '"event":"watcher-restarted"') 'alerts.jsonl'
Write-Result ($f.Objects.Count -ge 1) 'alert pg_deny_watcher_failed shipped for the restart' (Show-Record ($f.Objects | Select-Object -Last 1))
$sinceT = UtcStamp 1
[void](Invoke-Docker @('exec', (Id 'pg-replica'), 'kill', '-TERM', [string]$wp2['supervise']))
Start-Sleep -Seconds 4
$wp3 = WatcherProcs
$tl = @(DenyLog $sinceT | Where-Object { $_ -match 'action=supervisor-stopped' })
$okT = ($tl.Count -eq 1) -and (-not $wp3['watch']) -and (-not $wp3['supervise']) -and (-not $wp3['tini']) -and ((CrashLines) -eq $crash0) -and (Test-PgPidAlive $sV.Pid) -and (@(DenyTokens).Count -eq 2)
Write-Result $okT 'SIGTERM to the supervisor: it logs supervisor-stopped and exits 0 with the watcher (tini exits 0, no postmaster crash-restart); the last deny list stays in effect' (('processes left: {0}; postmaster abnormal-exit lines {1}' -f (($wp3.Keys | ForEach-Object { $_ + '=' + $wp3[$_] }) -join ' '), (CrashLines)) + "`n" + (($tl | ForEach-Object { OneLine $_ 240 }) -join ''))
$f = Find-InStore @('"alert":"pg_deny_watcher_failed"', '"event":"supervisor-stopped"') 'alerts.jsonl'
Write-Result ($f.Objects.Count -ge 1) 'alert pg_deny_watcher_failed shipped for the stopped supervisor' (Show-Record ($f.Objects | Select-Object -Last 1))
$x = PgClient ($pgReplicaConn + ' user=' + $cG.User) 'SELECT 1' $cG.Password
Assert-Refused 'with the watcher stopped, the revoked role is still refused (the loaded pg_hba and the file are unchanged)' $x ('pg_hba\.conf rejects connection .*user "' + [regex]::Escape($cG.User) + '"')
# Restart of pg-replica while the primary is down and the descriptor exists: the entrypoint writes
# the deny list BEFORE the server starts. Window measured with the poller.
$sinceR = UtcStamp 1
$tRs = VmNow
$rr = Invoke-Docker @('restart', '-t', '20', (Id 'pg-replica')) @{} 120
$tRe = VmNow
$dl = (Get-Date).AddSeconds(60)
$firstV = $null
while ((Get-Date) -lt $dl) {
    $pl = Get-PollLines $poller
    $firstV = @($pl | Where-Object { ($_.Who -eq 'valid') -and $_.Ok -and ($_.S -ge $tRs) } | Select-Object -First 1)
    if ($firstV.Count -ge 1) { break }
    Start-Sleep -Seconds 1
}
Start-Sleep -Seconds 4
$pl = Get-PollLines $poller
$rl2 = @(DenyLog $sinceR)
$sa = @($rl2 | Where-Object { $_ -match 'action=startup-apply' } | Select-Object -First 1)
$tSa = $null; if ($sa.Count -ge 1) { $tSa = LogTs $sa[0] }
$rAfterR = @($pl | Where-Object { ($_.Who -eq 'revoked') -and ($_.S -ge $tRs) })
$rOkR = @($rAfterR | Where-Object { $_.Ok }).Count
$firstAns = @($pl | Where-Object { ($_.S -ge $tRs) -and ($_.Ok -or $_.Hba -or ($_.Msg -match 'password authentication failed')) } | Select-Object -First 1)
$firstRRef = @($rAfterR | Where-Object { $_.Hba } | Select-Object -First 1)
$wp4 = WatcherProcs
$okR = ($rr.Code -eq 0) -and ($firstV.Count -ge 1) -and ($null -ne $tSa) -and ($tSa -lt $firstV[0].S) -and ($rOkR -eq 0) -and ($firstRRef.Count -ge 1) -and ($sa[0] -match 'entries=1 descriptors=1') -and $wp4['watch'] -and $wp4['supervise'] -and $wp4['tini']
$d = @(('restart command {0:N1} s; deny list written by the entrypoint (startup-apply) {1:N3} s after the restart command started: {2}' -f ($tRe - $tRs), ($tSa - $tRs), (($sa | ForEach-Object { OneLine $_ 200 }) -join '')),
       ('first answered login attempt after the restart: {0} at +{1:N3} s; first successful login (V) +{2:N3} s; the deny list was in place {3:N3} s before that' -f (($firstAns | ForEach-Object { $_.Who }) -join ''), [double](@($firstAns | ForEach-Object { $_.E - $tRs }) + @(0))[0], ($firstV[0].E - $tRs), ($firstV[0].S - $tSa)),
       ('revoked role after the restart: {0} attempts, {1} successful; first refusal: {2}' -f $rAfterR.Count, $rOkR, (($firstRRef | ForEach-Object { OneLine $_.Msg 160 }) -join '')),
       ('watcher back: tini {0} supervise {1} watch {2}' -f $wp4['tini'], $wp4['supervise'], $wp4['watch']))
Write-Result $okR 'RESTART of pg-replica during the outage: the deny list is written before the server starts, so the revoked role is refused from the very first accepted connection (no login window); the watcher is running again' ($d -join "`n")
Add-Measure ('pg-replica restart during the outage: deny list written {0:N2} s after the restart command, first accepted login {1:N2} s after it; revoked-role logins in the window: {2} of {3}' -f ($tSa - $tRs), ($firstV[0].E - $tRs), $rOkR, $rAfterR.Count)

# OpenBao's own retry delays are jittered (measured e.g. 25.8 s, 21.8 s, 43.3 s, 3m12 s for one
# lease), so the restart is timed from OpenBao's log: start the databases only when OpenBao's next
# own attempt for BOTH leases is at least 90 s away. Then a completion within that window is the
# reconciler's, and the log line proves it.
function Get-NextBaoAttempt {
    param([string]$Lease, [string]$Since)
    $last = @(((Invoke-Docker @('logs', '--since', $Since, (Id 'openbao'))).All -split "`r?`n") | Where-Object { $_ -match ('expiration: failed to revoke lease: lease_id=' + [regex]::Escape($Lease) + ' ') } | Select-Object -Last 1)
    if ($last.Count -eq 0) { return $null }
    if ($last[0] -notmatch '^(\S+Z) .*attempts=(\d+) next_attempt=((?:\d+h)?(?:\d+m)?(?:[\d.]+s)?)') { return $null }
    $at = ConvertTo-Epoch $Matches[1]; $n = [int]$Matches[2]; $dur = $Matches[3]; $sec = 0.0
    if ($dur -match '(\d+)h') { $sec += 3600 * [int]$Matches[1] }
    if ($dur -match '(\d+)m') { $sec += 60 * [int]$Matches[1] }
    if ($dur -match '([\d.]+)s$') { $sec += [double]::Parse($Matches[1], $inv) }
    return @{ Due = $at + $sec; Attempts = $n; Delay = $dur }
}
while (((Get-Date) - $tRevoke).TotalSeconds -lt $OutageSeconds) { Start-Sleep -Seconds 2 }
$dlWait = (Get-Date).AddSeconds(420)
do {
    $nM = Get-NextBaoAttempt $cM.Lease $since; $nG = Get-NextBaoAttempt $cG.Lease $since
    $remM = -1; $remG = -1
    if ($nM) { $remM = $nM.Due - (VmNow) }; if ($nG) { $remG = $nG.Due - (VmNow) }
    if (($remM -ge 90) -and ($remG -ge 90)) { break }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $dlWait)
Note ('OpenBao''s own retries so far: MariaDB lease attempts={0} (last delay {1}), next due in {2:N0} s; PostgreSQL lease attempts={3} (last delay {4}), next due in {5:N0} s' -f $nM.Attempts, $nM.Delay, $remM, $nG.Attempts, $nG.Delay, $remG)
$pl = Get-PollLines $poller
$rAll = @($pl | Where-Object { ($_.Who -eq 'revoked') -and $firstHba -and ($_.S -ge $firstHba[0].E) })
Write-Result ((@($rAll | Where-Object { $_.Ok }).Count -eq 0) -and ($rAll.Count -ge 10)) ('for the rest of the outage (about {0:N0} s) no login of the revoked role succeeded ({1} attempts, all refused or unanswered)' -f (((Get-Date) - $tRevoke).TotalSeconds), $rAll.Count) ''
$rlOut = Get-ReconLog $since
$failM = @(($rlOut -split "`r?`n") | Where-Object { $_ -match ('action=revoke-retried lease=' + [regex]::Escape($cM.Lease) + ' .*outcome=failed') })
$failG = @(($rlOut -split "`r?`n") | Where-Object { $_ -match ('action=revoke-retried lease=' + [regex]::Escape($cG.Lease) + ' .*outcome=failed') })
Write-Result (($failM.Count -ge 1) -and ($failG.Count -ge 1)) 'during the outage the reconciler retried both pending revocations (outcome=failed, target unreachable), with backoff' ((@($failM | Select-Object -First 2) + @($failG | Select-Object -First 2) | ForEach-Object { OneLine $_ 260 }) -join "`n")
$tStart = Get-Date
$tStartVm = VmNow
$sinceS = UtcStamp 1
$r2 = Compose @('start', 'pg-primary', 'maria-replica')
$hP = Wait-Healthy 'pg-primary' 120; $tPgUp = Get-Date
$hM = Wait-Healthy 'maria-replica' 150; $tMaUp = Get-Date
$goneM = $null; $goneG = $null; $roleGone = $null; $descGone = $null; $released = $null; $hbaEmpty = $null; $sBack = $null
$dl = (Get-Date).AddSeconds($ReconcileWaitSeconds + $PgDenyGraceSeconds + 30)
while ((Get-Date) -lt $dl) {
    if ((-not $goneM) -and (-not (Test-LeaseExists $cM.Lease))) { $goneM = Get-Date }
    if ((-not $goneG) -and (-not (Test-LeaseExists $cG.Lease))) { $goneG = Get-Date }
    if ((-not $roleGone) -and ((PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $cG.User)) -eq '0')) { $roleGone = Get-Date }
    if ((-not $descGone) -and (@(Descriptors).Count -eq 0)) { $descGone = Get-Date }
    if ((-not $hbaEmpty) -and (@(DenyTokens).Count -eq 1) -and ($descGone)) { $hbaEmpty = Get-Date }
    if ($goneM -and $goneG -and $roleGone -and $descGone -and $hbaEmpty) { break }
    Start-Sleep -Seconds 1
}
Start-Sleep -Seconds 3
$rlOut = Get-ReconLog $since
$okM = @(($rlOut -split "`r?`n") | Where-Object { $_ -match ('action=revoke-retried lease=' + [regex]::Escape($cM.Lease) + ' role=app1-maria-ro outcome=ok') })
$okG = @(($rlOut -split "`r?`n") | Where-Object { $_ -match ('action=revoke-retried lease=' + [regex]::Escape($cG.Lease) + ' role=app1-pg-ro outcome=ok') })
$rmG = @(($rlOut -split "`r?`n") | Where-Object { $_ -match ('action=pg-deny-removed lease=' + [regex]::Escape($cG.Lease) + ' role=app1-pg-ro outcome=ok') })
function Sec { param($A, $B) if ($A -and $B) { return [Math]::Round(($A - $B).TotalSeconds, 1) }; return -1 }
$d = @(('outage {0:N0} s; start command at +{1:N0} s after the revoke; pg-primary healthy {2} s, maria-replica healthy {3} s after the start command' -f ($tStart - $tDown).TotalSeconds, ($tStart - $tRevoke).TotalSeconds, (Sec $tPgUp $tStart), (Sec $tMaUp $tStart)),
      ('MariaDB lease gone {0} s after the start ({1} s after the replica was healthy); reconciler: {2}' -f (Sec $goneM $tStart), (Sec $goneM $tMaUp), (($okM | ForEach-Object { OneLine $_ 200 }) -join '')),
      ('PostgreSQL lease gone {0} s after the start ({1} s after the primary was healthy); reconciler: {2}' -f (Sec $goneG $tStart), (Sec $goneG $tPgUp), (($okG | ForEach-Object { OneLine $_ 200 }) -join '')),
      ('OpenBao''s own next attempts were due {0:N0} s (MariaDB) and {1:N0} s (PostgreSQL) after the start command' -f ($nM.Due - $tStartVm), ($nG.Due - $tStartVm)))
$beforeBao = $goneM -and $goneG -and (((Sec $goneM $tStart) + 0) -lt ($nM.Due - $tStartVm)) -and (((Sec $goneG $tStart) + 0) -lt ($nG.Due - $tStartVm))
Write-Result ($hP -and $hM -and $beforeBao -and ($okM.Count -eq 1) -and ($okG.Count -eq 1)) 'after the databases returned, the RECONCILER completed both queued revocations, before OpenBao''s own next retry was due' ($d -join "`n")
Add-Measure ('reconciler completed the pending MariaDB revocation {0} s after maria-replica was healthy, the PostgreSQL one {1} s after pg-primary was healthy (interval {2} s, backoff up to 2 passes); OpenBao''s own next retries were due {3:N0} s / {4:N0} s after the start (jittered backoff)' -f (Sec $goneM $tMaUp), (Sec $goneG $tPgUp), $reconInterval, ($nM.Due - $tStartVm), ($nG.Due - $tStartVm))
$wl3 = @(DenyLog $sinceS)
$gl = @($wl3 | Where-Object { $_ -match 'action=descriptor-gone ' } | Select-Object -First 1)
$rel = @($wl3 | Where-Object { $_ -match 'action=deny-released ' } | Select-Object -First 1)
$emp = @($wl3 | Where-Object { $_ -match 'action=deny-list-empty' } | Select-Object -First 1)
$tGl = $null; if ($gl.Count) { $tGl = LogTs $gl[0] }
$tRel = $null; if ($rel.Count) { $tRel = LogTs $rel[0] }
$tok2 = @(DenyTokens)
$d = @(('R''s role dropped on pg-replica {0} s after the start command; descriptor removed by the reconciler {1} s after it: {2}' -f (Sec $roleGone $tStart), (Sec $descGone $tStart), (($rmG | ForEach-Object { OneLine $_ 200 }) -join '')),
       ('watcher: ' + (($gl | ForEach-Object { OneLine $_ 220 }) -join '')), ('watcher: ' + (($rel | ForEach-Object { OneLine $_ 300 }) -join '')), ('watcher: ' + (($emp | ForEach-Object { OneLine $_ 200 }) -join '')),
       ('entry held {0:N0} s after the descriptor was gone (S still matched; grace {1} s, released only while streaming); deny list now: {2}' -f ($tRel - $tGl), $PgDenyGraceSeconds, ($tok2 -join ' ')))
$ok = $roleGone -and $descGone -and $hbaEmpty -and ($rmG.Count -eq 1) -and ($rel.Count -eq 1) -and ($rel[0] -match 'reason=grace-expired-while-streaming') -and ($rel[0] -match 'matched=1 ') -and ($rel[0] -match [regex]::Escape($cS.User)) -and (($tRel - $tGl) -ge ($PgDenyGraceSeconds - 1)) -and ($tok2.Count -eq 1) -and ($tok2[0] -eq '/^$') -and ($emp.Count -eq 1)
Write-Result $ok 'PRUNE: the reconciler removed the descriptor once the lease was gone; R''s role was dropped on the replica; the deny entry (still matching S) was held for the grace while streaming, then released; the deny list is back to the sentinel only' ($d -join "`n")
Add-Measure ('prune after the primary returned: role dropped on the replica {0} s, descriptor removed {1} s, deny list back to the sentinel {2} s after the start command (over-denied S held {3:N0} s by the {4} s grace)' -f (Sec $roleGone $tStart), (Sec $descGone $tStart), (Sec $hbaEmpty $tStart), ($tRel - $tGl), $PgDenyGraceSeconds)
Start-Sleep -Seconds 3
Assert-Works 'S (the over-denied still-valid role) logs in again after the release' (PgClient ($pgReplicaConn + ' user=' + $cS.User) "SELECT 'login ok as ' || current_user" $cS.Password) 'login ok as v-'
Assert-Works 'V (still valid) logs in' (PgClient ($pgReplicaConn + ' user=' + $cV.User) "SELECT 'login ok as ' || current_user" $cV.Password) 'login ok as v-'
Assert-Refused 'PG: the revoked role can no longer log in to the replica' (PgClient ($pgReplicaConn + ' user=' + $cG.User) 'SELECT 1' $cG.Password) ('pg_hba\.conf rejects connection .*user "' + [regex]::Escape($cG.User) + '"|password authentication failed for user "' + [regex]::Escape($cG.User) + '"|role "' + [regex]::Escape($cG.User) + '" does not exist')
Assert-Refused 'Maria: the revoked user cannot log in (purged at start, lease revoked by the reconciler)' (MaClient $cM.User 'SELECT 1' $cM.Password) (MaRefused $cM.User)
[void](Invoke-Docker @('rm', '-f', $poller))
$f = Find-InStore @('"alert":"revocation_retried_by_reconciler"', $cM.Lease, '"outcome":"ok"') 'alerts.jsonl'
$f2 = Find-InStore @('"alert":"revocation_retried_by_reconciler"', $cG.Lease, '"outcome":"failed"') 'alerts.jsonl'
Write-Result (($f.Objects.Count -ge 1) -and ($f2.Objects.Count -ge 1)) 'alert revocation_retried_by_reconciler shipped (failed attempts during the outage and the successful one)' ((Show-Record ($f2.Objects | Select-Object -Last 1)) + "`n" + (Show-Record ($f.Objects | Select-Object -Last 1)))
# A normal expiry is not touched: a lease that OpenBao revokes itself never shows up.
$cE = Get-Creds $alice.Token 'app1-pg-ro'
$sinceE = UtcStamp 0
[void](BaoRoot @('lease', 'revoke', '-sync', $cE.Lease))
Start-Sleep -Seconds ($reconInterval * 2 + 2)
$touched = @(((Get-ReconLog $sinceE) -split "`r?`n") | Where-Object { $_ -match [regex]::Escape($cE.Lease) })
Write-Result ($touched.Count -eq 0) ('control: a lease that OpenBao revoked itself is never touched by the reconciler (no line in {0} s)' -f ($reconInterval * 2 + 2)) ($touched -join "`n")

# =============================================================================================
Write-Host ''
Write-Host '== 3c. Deny descriptors: injection and validation (what a compromised reconciler can write) =='
# Written by a throwaway container with the reconciler's uid and its read-write mount of pg-deny:
# exactly what a compromised reconciler could do. The reconciler is paused meanwhile, so its own
# clean-up (it removes descriptors of leases OpenBao does not have) cannot race the watcher.
$volDeny = $P2Project + '_pg-deny'
$injScript = @'
cd /pg-deny || exit 1
t=$(date +%s)
printf 'v1 app1-pg-ro %s"\n' "$t" > app1-pg-ro.Inj01quote.deny
printf 'v1 app1-pg-ro %s\nall\n' "$t" > app1-pg-ro.Inj02newline.deny
printf 'v1 all %s\n' "$t" > all.Inj03all.deny
printf 'v1 +debug_ro %s\n' "$t" > '+debug_ro.Inj04group.deny'
printf 'v1 @/etc/passwd %s\n' "$t" > app1-pg-ro.Inj05atfile.deny
printf 'v1 replicator %s\n' "$t" > replicator.Inj06replicator.deny
printf 'v1 bao_admin %s\n' "$t" > bao_admin.Inj07baoadmin.deny
printf 'v1 postgres %s\n' "$t" > postgres.Inj08postgres.deny
printf 'v1 ../../../var/lib/postgresql/pg-deny/denied_roles %s\n' "$t" > app1-pg-ro.Inj09traversal.deny
ln -s /var/lib/postgresql/pg-deny/state app1-pg-ro.Inj10symlink.deny
{ printf 'v1 app1-pg-ro %s\n' "$t"; head -c 4096 /dev/zero | tr '\000' 'A'; } > app1-pg-ro.Inj11oversized.deny
printf 'v1 app1-pg-ro,all %s\n' "$t" > app1-pg-ro.Inj12comma.deny
printf 'v1 app1-pg-ro %sZ\n' "$t" | tr 'Z' '\000' > app1-pg-ro.Inj13nul.deny
printf 'v1 app1-maria-ro %s\n' "$t" > app1-maria-ro.Inj14mariadb.deny
printf 'v1 app1-pg-ro %s\n' "$((t + 86400))" > app1-pg-ro.Inj15future.deny
printf 'v1 app1-maria-ro %s\n' "$t" > app1-pg-ro.Inj16mismatch.deny
mkfifo app1-pg-ro.Inj17fifo.deny
mkdir app1-pg-ro.Inj18dir.deny
printf 'v1 app1-pg-ro %s\n' "$t" > 'app1-pg-ro.Inj19 space.deny'
printf 'v1 app1-pg-ro /^v-.*$\n' > app1-pg-ro.Inj20regex.deny
printf 'v1 app1-pg-ro %s\r\n' "$t" > app1-pg-ro.Inj21crlf.deny
printf 'v1 app1-pg-ro 0%s\n' "$t" > app1-pg-ro.Inj22leadingzero.deny
printf 'v1 app1-pg-ro %s\n' "$t" > app1-pg-ro.Inj23noext
# Control: a well-formed descriptor with a timestamp no temp role has (accepted: it denies nothing).
printf 'v1 app1-pg-ro 1600000000\n' > app1-pg-ro.Inj00control.deny
ls -1A | wc -l
'@
$cases = @(
    @{ N = 'Inj01quote'; W = 'bad-content'; D = 'double quote after the timestamp' }, @{ N = 'Inj02newline'; W = 'bad-content'; D = 'second line "all"' },
    @{ N = 'Inj03all'; W = 'role-not-allowed'; D = 'role "all"' }, @{ N = 'Inj04group'; W = 'bad-name'; D = '"+debug_ro" (group syntax)' },
    @{ N = 'Inj05atfile'; W = 'bad-content'; D = '"@/etc/passwd" (include syntax)' }, @{ N = 'Inj06replicator'; W = 'role-not-allowed'; D = 'role replicator' },
    @{ N = 'Inj07baoadmin'; W = 'role-not-allowed'; D = 'role bao_admin' }, @{ N = 'Inj08postgres'; W = 'role-not-allowed'; D = 'role postgres' },
    @{ N = 'Inj09traversal'; W = 'bad-content'; D = 'path traversal in the role field' }, @{ N = 'Inj10symlink'; W = 'symlink'; D = 'symlink to the watcher''s state file' },
    @{ N = 'Inj11oversized'; W = 'bad-content'; D = 'valid first line + 4 KB' }, @{ N = 'Inj12comma'; W = 'bad-content'; D = 'comma list "app1-pg-ro,all"' },
    @{ N = 'Inj13nul'; W = 'bad-content'; D = 'NUL byte' }, @{ N = 'Inj14mariadb'; W = 'role-not-allowed'; D = 'MariaDB role' },
    @{ N = 'Inj15future'; W = 'issued-in-future'; D = 'timestamp one day ahead' }, @{ N = 'Inj16mismatch'; W = 'role-mismatch'; D = 'file name and body disagree' },
    @{ N = 'Inj17fifo'; W = 'not-a-regular-file'; D = 'FIFO (would block a reader)' }, @{ N = 'Inj18dir'; W = 'not-a-regular-file'; D = 'directory' },
    @{ N = 'Inj19'; W = 'bad-name'; D = 'space in the file name' }, @{ N = 'Inj20regex'; W = 'bad-content'; D = 'a regular expression instead of the timestamp' },
    @{ N = 'Inj21crlf'; W = 'bad-content'; D = 'CR LF line end' }, @{ N = 'Inj22leadingzero'; W = 'bad-content'; D = '11-digit timestamp with a leading zero' },
    @{ N = 'Inj23noext'; W = 'bad-name'; D = 'no .deny extension' })
$tokBefore = DenyFile
$hbaBefore = PgVal 'pg-replica' "SELECT string_agg(line_number || ':' || array_to_string(user_name, ',') || ':' || coalesce(error, ''), ' / ' ORDER BY line_number) FROM pg_hba_file_rules"
$sinceI = UtcStamp 1
$paused = (Invoke-Docker @('pause', (Id 'lease-reconciler'))).Code -eq 0
try {
    $wr = Invoke-Docker @('run', '--rm', '--network', 'none', '-u', '100:1000', '-v', ($volDeny + ':/pg-deny'), '--entrypoint', 'sh', 'openbao/openbao:2.7.2', '-c', $injScript)
    $dl = (Get-Date).AddSeconds(20)
    do { Start-Sleep -Seconds 1; $il = @(DenyLog $sinceI); $rejN = @($il | Where-Object { $_ -match 'action=descriptor-rejected descriptor=\S*Inj' }).Count; $ctl = @($il | Where-Object { $_ -match 'action=deny-applied descriptor=app1-pg-ro\.Inj00control ' }) } while ((($rejN -lt $cases.Count) -or ($ctl.Count -lt 1)) -and ((Get-Date) -lt $dl))
    Start-Sleep -Seconds 3
    $il = @(DenyLog $sinceI)
    foreach ($c in $cases) {
        $line = @($il | Where-Object { $_ -match ('action=descriptor-rejected descriptor=\S*' + $c.N + '\S* ') })
        Write-Result (($line.Count -eq 1) -and ($line[0] -match ('reason=' + $c.W + ' outcome=ignored'))) ('descriptor {0} ({1}) rejected: {2}' -f $c.N, $c.D, $c.W) (($line | ForEach-Object { OneLine $_ 200 }) -join "`n")
    }
    $tokMid = @(DenyTokens)
    $ok = ($ctl.Count -eq 1) -and ($ctl[0] -match 'matched=0 ') -and ($tokMid.Count -eq 2) -and ($tokMid[1] -eq '/^v-.+-app1-pg-ro-(1599999997|1599999998|1599999999|1600000000)-[A-Za-z0-9]{4}$')
    Write-Result $ok 'control: the one well-formed descriptor is accepted and becomes exactly one /^v-...$ pattern (it matches no role); none of the rejected files left a trace in the deny list' (('files written: {0}' -f $wr.Out.Trim()) + "`n" + (($ctl | ForEach-Object { OneLine $_ 260 }) -join '') + "`ndeny list: " + ($tokMid -join ' '))
    $hbaMid = PgVal 'pg-replica' "SELECT string_agg(line_number || ':' || array_to_string(user_name, ',') || ':' || coalesce(error, ''), ' / ' ORDER BY line_number) FROM pg_hba_file_rules"
    $ok = ($hbaMid -match '^1:postgres: / 2:/\^\$,/\^v-\.\+-app1-pg-ro-\(1599999997\|1599999998\|1599999999\|1600000000\)-\[A-Za-z0-9\]\{4\}\$: / 3:bao_admin: / 4:\+debug_ro: / 5:session_sweeper: / 6:all: / 7:all:$')
    Write-Result $ok 'pg_hba_file_rules: line 2 holds only the sentinel and the control pattern, every other line unchanged, no error' ($hbaMid -replace ' / ', "`n")
    # Nothing else changed: the accounts the injection named still work.
    $st = PgVal 'pg-replica' "SELECT coalesce((SELECT status FROM pg_stat_wal_receiver), 'none')"
    $cT = Get-Creds $alice.Token 'app1-pg-ro'
    $dl = (Get-Date).AddSeconds(30); while (((PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $cT.User)) -ne '1') -and ((Get-Date) -lt $dl)) { Start-Sleep -Milliseconds 300 }
    $xT = PgClient ($pgReplicaConn + ' user=' + $cT.User) "SELECT 'login ok as ' || current_user" $cT.Password
    $swl = (Invoke-Docker @('logs', '--since', $sinceI, (Id 'pg-sweeper'))).All
    $sup = Invoke-Docker @('exec', '-u', 'postgres', (Id 'pg-replica'), 'psql', '-X', '-At', 'dbname=postgres application_name=p4-deny-probe', '-c', "SELECT 'postgres local ok'")
    $ok = ($st -eq 'streaming') -and ($xT.Code -eq 0) -and ($swl -notmatch 'action=error') -and ($sup.Out -match 'postgres local ok')
    Write-Result $ok 'with all of that in the volume: replication (replicator) still streams, a new temp role logs in, the sweeper reports no error, postgres works locally' ('receiver {0}; temp role: {1}; sweeper log since: {2}; postgres: {3}' -f $st, (OneLine $xT.All 80), $(if ($swl.Trim()) { OneLine $swl 120 } else { 'no new lines' }), $sup.Out.Trim())
    [void](BaoRoot @('lease', 'revoke', '-sync', $cT.Lease))
} finally {
    [void](Invoke-Docker @('run', '--rm', '--network', 'none', '-u', '100:1000', '-v', ($volDeny + ':/pg-deny'), '--entrypoint', 'sh', 'openbao/openbao:2.7.2', '-c', 'cd /pg-deny && rm -rf ./*Inj* ./.[!.]*Inj* 2>/dev/null; ls -1A | wc -l'))
    if ($paused) { [void](Invoke-Docker @('unpause', (Id 'lease-reconciler'))) }
}
$f = Find-InStore @('"alert":"pg_deny_descriptor_rejected"', 'Inj22leadingzero') 'alerts.jsonl'
$cnt = Invoke-Docker @('run', '--rm', '--network', 'none', '-v', ($volStore + ':/store:ro'), '--entrypoint', 'sh', 'postgres:17', '-c', ('grep "pg_deny_descriptor_rejected" /store/alerts.jsonl | grep -c "Inj[0-9][0-9]"'))
Write-Result (($f.Objects.Count -ge 1) -and ([int]$cnt.Out.Trim() -ge $cases.Count)) ('alert pg_deny_descriptor_rejected shipped for every rejected file ({0} alerts, {1} cases)' -f $cnt.Out.Trim(), $cases.Count) (Show-Record ($f.Objects | Select-Object -Last 1))
$dl = (Get-Date).AddSeconds(15)
do { Start-Sleep -Seconds 1; $tk = @(DenyTokens) } while (($tk.Count -ne 1) -and ((Get-Date) -lt $dl))
$rel = @(DenyLog $sinceI | Where-Object { $_ -match 'action=deny-released descriptor=app1-pg-ro\.Inj00control .*reason=no-matching-role' })
Write-Result (($tk.Count -eq 1) -and ($tk[0] -eq '/^$') -and ($rel.Count -eq 1) -and (@(Descriptors).Count -eq 0)) 'after the files are removed, the control entry is released (it matched no role) and the deny list is the sentinel only again' (($rel | ForEach-Object { OneLine $_ 220 }) -join '')
# Least privilege of the channel.
$all = @((Invoke-Docker @('compose', '-f', $P2ComposeFile, 'ps', '-a', '--format', '{{.Service}} {{.ID}}')).Out -split "`r?`n" | Where-Object { $_.Trim() })
$mnt = @()
foreach ($line in $all) {
    $svc, $cid = $line.Trim() -split '\s+', 2
    $m = (Invoke-Docker @('inspect', '-f', ('{{range .Mounts}}{{if eq .Name "' + $volDeny + '"}}{{.Destination}}:{{if .RW}}rw{{else}}ro{{end}}{{end}}{{end}}'), $cid)).Out.Trim()
    if ($m) { $mnt += ('{0}={1}' -f $svc, $m) }
}
$mnt = @($mnt | Sort-Object)
Write-Result (($mnt -join ' ') -eq 'lease-reconciler=/pg-deny:rw log-init=/v/pg-deny:rw pg-replica=/pg-deny:ro') 'volume pg-deny: read-write only in lease-reconciler (and the exited one-shot log-init, which only sets its owner), read-only in pg-replica, nowhere else' ($mnt -join "`n")
$x = Invoke-Docker @('exec', '-u', 'postgres', (Id 'pg-replica'), 'touch', '/pg-deny/x.deny')
Assert-Refused 'pg-replica cannot write the descriptor volume (read-only mount)' $x 'Read-only file system'
$st = (Invoke-Docker @('exec', (Id 'pg-replica'), 'stat', '-c', '%n %U:%G %a', '/var/lib/postgresql/pg-deny', $denyFile, '/var/lib/postgresql/pg-deny/state')).Out.Trim()
$x = Invoke-Docker @('exec', (Id 'lease-reconciler'), 'ls', '/var/lib/postgresql/pg-deny')
$vd = (Invoke-Docker @('exec', (Id 'lease-reconciler'), 'stat', '-c', '%n %u:%g %a', '/pg-deny')).Out.Trim()
$ok = ($st -match '/var/lib/postgresql/pg-deny postgres:postgres 700') -and ($st -match 'denied_roles postgres:postgres 600') -and ($x.Code -ne 0) -and ($vd -eq '/pg-deny 100:1000 755')
Write-Result $ok 'the pg_hba include file lives in pg-replica''s own file system (owner postgres, 0600, directory 0700), which the reconciler cannot reach; the descriptor directory is 100:1000 0755' ($st + "`n" + $vd + "`nfrom lease-reconciler: exit " + $x.Code + ' ' + (OneLine $x.All 120))
# Fail-safe without the descriptor volume (unit run of the entrypoint step with a missing directory).
$u = Invoke-Docker @('exec', '-u', 'postgres', '-e', 'PG_DENY_DIR=/nonexistent', '-e', 'PG_DENY_WORK_DIR=/tmp/pgdeny-unit', '-e', 'PG_DENY_LOG_DIR=/tmp/pgdeny-unit', (Id 'pg-replica'), 'bash', '-c', 'bash /opt/replica/pg-deny-watcher.sh apply-offline; echo "exit=$?"; grep -v "^#" /tmp/pgdeny-unit/denied_roles; rm -rf /tmp/pgdeny-unit')
Assert-Works 'fail-safe: without the descriptor directory the entrypoint step still exits 0 and writes the sentinel (the server starts), and logs an error (alert pg_deny_watcher_failed)' $u 'action=error reason=descriptor-dir-unreadable[\s\S]*action=startup-apply entries=0[\s\S]*exit=0\s+/\^\$'

Write-Host ''
Write-Host '== 3d. Normal operation: no descriptor, nothing denied, no watcher logins =='
$sinceN = UtcStamp 0
$cN = Get-Creds $alice.Token 'app1-pg-ro'
$dl = (Get-Date).AddSeconds(30); while (((PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $cN.User)) -ne '1') -and ((Get-Date) -lt $dl)) { Start-Sleep -Milliseconds 300 }
$xN = PgClient ($pgReplicaConn + ' user=' + $cN.User) "SELECT 'login ok as ' || current_user" $cN.Password
Start-Sleep -Seconds 20
$wlog = Invoke-Docker @('exec', (Id 'pg-replica'), 'sh', '-c', ('cat /var/log/pgaudit/*.json | grep "pg-deny-watcher" | grep -c "connection authorized" ; true'))
$nl = @(DenyLog $sinceN)
$hb = (Invoke-Docker @('exec', (Id 'pg-replica'), 'sh', '-c', 'echo $(( $(date +%s) - $(stat -c %Y /var/lib/postgresql/pg-deny/heartbeat) ))')).Out.Trim()
$h = (Invoke-Docker @('inspect', '-f', '{{.State.Health.Status}}', (Id 'pg-replica'))).Out.Trim()
$ok = ($xN.Code -eq 0) -and (@(DenyTokens).Count -eq 1) -and ((HbaLine2) -eq '2:/^$:all:reject:no error') -and ($nl.Count -eq 0) -and ([int]$hb -lt 10) -and ($h -eq 'healthy')
Write-Result $ok 'no descriptor: the deny list is the sentinel only (pg_hba line 2 = /^$, no error), a temp role logs in, the watcher wrote no line and made no SQL login in 20 s idle (heartbeat fresh, replica healthy)' ('login: {0}; pg_hba line 2: {1}; watcher lines in the idle window: {2}; heartbeat age {3} s; health {4}; watcher logins in the whole replica log so far: {5}' -f (OneLine $xN.All 80), (HbaLine2), $nl.Count, $hb, $h, $wlog.Out.Trim())
[void](BaoRoot @('lease', 'revoke', '-sync', $cN.Lease))

# =============================================================================================
if ($IrrevocableTest) {
    Write-Host ''
    Write-Host ('== 3b. Irrevocable lease (maria-replica down until OpenBao gives up; bound {0} s) ==' -f $IrrevocableWaitSeconds)
    $cI = Get-Creds $alice.Token 'app1-maria-ro'
    $since = UtcStamp 2
    [void](Compose @('stop', 'maria-replica'))
    $rI = BaoRoot @('lease', 'revoke', $cI.Lease)
    $tI = Get-Date
    $irrAt = $null; $irrObj = $null
    while (((Get-Date) - $tI).TotalSeconds -lt $IrrevocableWaitSeconds) {
        $x = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'sys/leases', 'type=irrevocable')).Out
        $hit = @($x.data.leases | Where-Object { $_.lease_id -eq $cI.Lease })
        if ($hit.Count -ge 1) { $irrAt = Get-Date; $irrObj = $hit[0]; break }
        Start-Sleep -Seconds 10
    }
    $irrS = Sec $irrAt $tI
    Write-Result ($null -ne $irrAt) ('OpenBao marked the lease irrevocable {0} s after the asynchronous revoke (replica still down)' -f $irrS) ('sys/leases?type=irrevocable entry: ' + (OneLine ($irrObj | ConvertTo-Json -Compress) 300))
    $detAt = $null
    $dl = (Get-Date).AddSeconds($reconInterval + 15)
    while ((Get-Date) -lt $dl) {
        if ((Get-ReconLog $since) -match ('action=irrevocable-found lease=' + [regex]::Escape($cI.Lease))) { $detAt = Get-Date; break }
        Start-Sleep -Seconds 1
    }
    Write-Result ($null -ne $detAt) ('the reconciler reported it (action=irrevocable-found) {0} s after OpenBao marked it' -f (Sec $detAt $irrAt)) ''
    Add-Measure ('irrevocable: OpenBao gave up {0} s after the revoke; reconciler detection {1} s later (interval {2} s)' -f $irrS, (Sec $detAt $irrAt), $reconInterval)
    $f = Find-InStore @('"alert":"irrevocable_lease_found"', $cI.Lease) 'alerts.jsonl'
    Write-Result ($f.Objects.Count -ge 1) 'alert irrevocable_lease_found shipped' (Show-Record ($f.Objects | Select-Object -Last 1))
    $retries = @(((Get-ReconLog $since) -split "`r?`n") | Where-Object { $_ -match ('lease=' + [regex]::Escape($cI.Lease)) -and $_ -match 'outcome=failed' }).Count
    $tS = Get-Date
    [void](Compose @('start', 'maria-replica'))
    $hM = Wait-Healthy 'maria-replica' 150; $tUp = Get-Date
    $gone = $null; $dl = (Get-Date).AddSeconds($ReconcileWaitSeconds)
    while ((Get-Date) -lt $dl) { if (-not (Test-LeaseExists $cI.Lease)) { $gone = Get-Date; break }; Start-Sleep -Seconds 1 }
    $x = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'sys/leases', 'type=irrevocable')).Out
    $okL = @(((Get-ReconLog $since) -split "`r?`n") | Where-Object { $_ -match ('action=revoke-irrevocable lease=' + [regex]::Escape($cI.Lease) + ' role=app1-maria-ro outcome=ok') })
    Write-Result ($hM -and $gone -and ($okL.Count -eq 1) -and ([int]$x.data.lease_count -eq 0)) ('after the replica returned, the reconciler revoked the irrevocable lease {0} s after the replica was healthy; no irrevocable lease is left' -f (Sec $gone $tUp)) ((($okL | ForEach-Object { OneLine $_ 220 }) -join '') + ("`nfailed reconciler attempts during the outage: {0}; irrevocable lease_count now {1}" -f $retries, $x.data.lease_count))
    Add-Measure ('irrevocable lease revoked by the reconciler {0} s after maria-replica was healthy ({1} failed attempts before, with backoff)' -f (Sec $gone $tUp), $retries)
}

# =============================================================================================
Write-Host ''
Write-Host '== 4. The reconciler''s token: what it may do, what it is refused =='
$rc = Id 'lease-reconciler'
function RB { param([string[]]$A) Invoke-Docker (@('exec', $rc, 'sh', '/opt/reconciler/lease-reconciler.sh', 'bao') + $A) }
$cX = Get-Creds $alice.Token 'app1-pg-ro'
Assert-Works 'reconciler token: LIST sys/leases/lookup/database/creds/ (roles with leases)' (RB @('list', 'sys/leases/lookup/database/creds/')) 'app1-pg-ro/'
Assert-Works 'reconciler token: look up a database lease (TTL)' (RB @('write', '-field=ttl', 'sys/leases/lookup', ('lease_id=' + $cX.Lease))) '^\d+'
Assert-Works 'reconciler token: list irrevocable leases' (RB @('read', 'sys/leases', 'type=irrevocable')) 'lease_count'
$denied = 'Code: 403\. Errors:\s+\* (1 error occurred:\s+\* )?permission denied'
Assert-Refused 'reconciler token cannot issue MariaDB credentials (database/creds/app1-maria-ro)' (RB @('read', 'database/creds/app1-maria-ro')) $denied
Assert-Refused 'reconciler token cannot issue PostgreSQL credentials (database/creds/app1-pg-ro)' (RB @('read', 'database/creds/app1-pg-ro')) $denied
Assert-Refused 'reconciler token cannot read a database connection (database/config/app1-pg)' (RB @('read', 'database/config/app1-pg')) $denied
Assert-Refused 'reconciler token cannot read a role (database/roles/app1-maria-ro)' (RB @('read', 'database/roles/app1-maria-ro')) $denied
Assert-Refused 'reconciler token cannot change a role (TTL)' (RB @('write', 'database/roles/app1-pg-ro', 'default_ttl=10h')) $denied
Assert-Refused 'reconciler token cannot rotate a root credential' (RB @('write', '-f', 'database/rotate-root/app1-pg')) $denied
Assert-Refused 'reconciler token cannot read or write policies' (RB @('read', 'sys/policy/lease-reconciler')) $denied
Assert-Refused 'reconciler token cannot read its own AppRole role-id' (RB @('read', 'auth/approle/role/lease-reconciler/role-id')) $denied
Assert-Refused 'reconciler token cannot create tokens' (RB @('token', 'create')) $denied
Assert-Refused 'reconciler token cannot renew a lease (extend access)' (RB @('write', 'sys/leases/renew', ('lease_id=' + $cX.Lease))) $denied
Assert-Refused 'reconciler token cannot look up a non-database lease (allowed_parameters lease_id = database/creds/*)' (RB @('write', 'sys/leases/lookup', 'lease_id=auth/jwt/login/x')) $denied
Assert-Refused 'reconciler token cannot list non-database leases' (RB @('list', 'sys/leases/lookup/auth/')) $denied
Assert-Refused 'reconciler token cannot revoke asynchronously (sync=false)' (RB @('write', 'sys/leases/revoke', ('lease_id=' + $cX.Lease), 'sync=false')) $denied
Assert-Refused 'reconciler token cannot revoke by prefix' (RB @('write', '-f', 'sys/leases/revoke-prefix/database/creds/')) $denied
Assert-Refused 'reconciler token cannot force-revoke (which would drop the lease without dropping the user)' (RB @('write', '-f', 'sys/leases/revoke-force/database/creds/')) $denied
Assert-Refused 'reconciler token cannot use the path form sys/leases/revoke/<id>' (RB @('write', '-f', ('sys/leases/revoke/' + $cX.Lease))) $denied
Assert-Refused 'reconciler token cannot read OpenBao''s configuration (sys/config/state/sanitized)' (RB @('read', 'sys/config/state/sanitized')) $denied
Assert-Refused 'reconciler token cannot list secret engines (sys/mounts)' (RB @('read', 'sys/mounts')) $denied
Assert-Refused 'reconciler token cannot use a cubbyhole (no default policy)' (RB @('read', 'cubbyhole/x')) $denied
Assert-Refused 'reconciler token cannot even look itself up (no default policy)' (RB @('token', 'lookup')) $denied
Assert-Works 'reconciler token CAN revoke a database lease synchronously (its one write action)' (RB @('write', 'sys/leases/revoke', ('lease_id=' + $cX.Lease), 'sync=true')) 'Success'
# AppRole binding: the same role ID and secret ID from another address on bao-reconciler.
$rf = Join-Path $P2SecretsDir 'openbao_phase4_reconciler_role_id'
$sf = Join-Path $P2SecretsDir 'openbao_phase4_reconciler_secret_id'
$x = Invoke-Docker @('run', '--rm', '--network', $netRecon, '-v', ($volCa + ':/pki-ca:ro'), '-v', ($rf + ':/s/role:ro'), '-v', ($sf + ':/s/secret:ro'), '-e', 'BAO_ADDR=https://openbao:8200', '-e', 'BAO_CACERT=/pki-ca/ca.crt',
    '--entrypoint', 'sh', 'openbao/openbao:2.7.2', '-c', 'bao write -format=json auth/approle/login role_id=@/s/role secret_id=@/s/secret > /tmp/o 2>&1; rc=$?; echo "exit=$rc client_token_lines=$(grep -c client_token /tmp/o) address=$(hostname -i)"; tr "\n" " " < /tmp/o | grep -o "Code: .*" | cut -c1-240')
Assert-Works 'the reconciler''s role ID + secret ID are refused from any other address (CIDR binding 10.81.10.20/32), even on bao-reconciler' $x 'exit=2 client_token_lines=0 address=10\.81\.10\.\d+\s+Code: 40[03]\..*unauthorized by CIDR'
$role = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'auth/approle/role/lease-reconciler')).Out
Write-Result (($role.data.token_type -eq 'batch') -and ($role.data.token_no_default_policy -eq $true) -and ((@($role.data.token_policies) -join ',') -eq 'lease-reconciler') -and ((@($role.data.token_bound_cidrs) -join ',') -match '^10\.81\.10\.20(/32)?$') -and ((@($role.data.secret_id_bound_cidrs) -join ',') -eq '10.81.10.20/32') -and ($role.data.token_ttl -eq 300)) 'AppRole lease-reconciler: batch tokens of 300 s, policy lease-reconciler only, no default policy, token and secret ID bound to 10.81.10.20/32' ('token_type={0} token_ttl={1} token_policies={2} no_default={3} token_bound_cidrs={4} secret_id_bound_cidrs={5} secret_id_ttl={6} secret_id_num_uses={7}' -f $role.data.token_type, $role.data.token_ttl, (@($role.data.token_policies) -join ','), $role.data.token_no_default_policy, (@($role.data.token_bound_cidrs) -join ','), (@($role.data.secret_id_bound_cidrs) -join ','), $role.data.secret_id_ttl, $role.data.secret_id_num_uses)
# The credentials appear in no log, no process listing, no container environment.
$sidVal = Read-P2Secret 'openbao_phase4_reconciler_secret_id'
$ridVal = Read-P2Secret 'openbao_phase4_reconciler_role_id'
$ps = (Invoke-Docker @('exec', $rc, 'ps', '-o', 'pid,args')).Out
$envJ = (Invoke-Docker @('inspect', '-f', '{{json .Config.Env}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}', $rc)).Out
$dlog = (Invoke-Docker @('logs', $rc)).All
$scan = @'
n=0
for f in /rl/* /store/audit.jsonl /store/alerts.jsonl /bao/audit.log; do
  a=$(grep -c -F -- "$SID" "$f" 2>/dev/null); b=$(grep -c -F -- "$RID" "$f" 2>/dev/null)
  echo "$f secret_id=${a:-0} role_id=${b:-0}"
done
'@
$sc = Invoke-Docker @('run', '--rm', '--network', 'none', '-u', '0', '-e', 'SID', '-e', 'RID', '-v', ($P2Project + '_reconciler-log:/rl:ro'), '-v', ($volStore + ':/store:ro'), '-v', ($P2Project + '_bao-audit:/bao:ro'), '--entrypoint', 'bash', 'postgres:17', '-c', $scan) @{ SID = $sidVal; RID = $ridVal }
$ok = (-not $ps.Contains($sidVal)) -and (-not $ps.Contains($ridVal)) -and (-not $envJ.Contains($sidVal)) -and (-not $dlog.Contains($sidVal)) -and (-not $dlog.Contains($ridVal)) -and ($sc.Code -eq 0) -and ($sc.Out -notmatch '(secret_id|role_id)=[1-9]')
Write-Result $ok 'the role ID and secret ID appear in no process listing, container config, docker logs, reconciler log, OpenBao audit log or the store (counts only)' (($sc.Out.Trim()) + ("`nps: {0} processes, contains secret_id: {1}; container config contains it: {2}; docker logs contain it: {3}" -f @($ps -split "`n" | Where-Object { $_.Trim() }).Count, $ps.Contains($sidVal), $envJ.Contains($sidVal), $dlog.Contains($sidVal)))
$sidVal = $null; $ridVal = $null

Write-Host ''
Write-Host '== 4b. Each rule of the lease-reconciler policy, removed one at a time =='
$probe = @'
t="$(bao write -field=token auth/approle/login role_id=@/run/secrets/openbao_reconciler_role_id secret_id=@/run/secrets/openbao_reconciler_secret_id 2>/dev/null)" || { echo login-failed; exit 9; }
c() { out="$(BAO_TOKEN="$t" bao "$@" 2>&1)"; rc=$?; if printf '%s' "$out" | grep -q 'Code: 403'; then echo DENIED; elif [ $rc -eq 0 ] || [ $rc -eq 2 ]; then echo ok; else echo "other:$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-80)"; fi; }
echo "list=$(c list sys/leases/lookup/database/creds/) lookup=$(c write sys/leases/lookup lease_id=database/creds/app1-pg-ro/nonexistent) revoke=$(c write sys/leases/revoke lease_id=database/creds/app1-pg-ro/nonexistent sync=true) irrevocable=$(c read sys/leases type=irrevocable)"
'@
$rList = "path `"sys/leases/lookup/database/creds/*`" {`n  capabilities = [`"list`", `"sudo`"]`n}`n"
$rListNoSudo = "path `"sys/leases/lookup/database/creds/*`" {`n  capabilities = [`"list`"]`n}`n"
$rLookup = "path `"sys/leases/lookup`" {`n  capabilities = [`"update`"]`n  allowed_parameters = {`n    `"lease_id`" = [`"database/creds/*`"]`n  }`n}`n"
$rRevoke = "path `"sys/leases/revoke`" {`n  capabilities = [`"update`"]`n  allowed_parameters = {`n    `"lease_id`" = [`"database/creds/*`"]`n    `"sync`" = [`"true`"]`n  }`n}`n"
$rIrr = "path `"sys/leases`" {`n  capabilities = [`"read`", `"sudo`"]`n}`n"
$rIrrNoSudo = "path `"sys/leases`" {`n  capabilities = [`"read`"]`n}`n"
$variants = @(
    @{ N = 'full policy (control)'; H = ($rList + $rLookup + $rRevoke + $rIrr); Want = 'list=ok lookup=ok revoke=ok irrevocable=ok' },
    @{ N = 'without LIST on sys/leases/lookup/database/creds/*'; H = ($rLookup + $rRevoke + $rIrr); Want = 'list=DENIED lookup=ok revoke=ok irrevocable=ok' },
    @{ N = 'LIST without sudo'; H = ($rListNoSudo + $rLookup + $rRevoke + $rIrr); Want = 'list=DENIED lookup=ok revoke=ok irrevocable=ok' },
    @{ N = 'without update on sys/leases/lookup'; H = ($rList + $rRevoke + $rIrr); Want = 'list=ok lookup=DENIED revoke=ok irrevocable=ok' },
    @{ N = 'without update on sys/leases/revoke'; H = ($rList + $rLookup + $rIrr); Want = 'list=ok lookup=ok revoke=DENIED irrevocable=ok' },
    @{ N = 'without read on sys/leases'; H = ($rList + $rLookup + $rRevoke); Want = 'list=ok lookup=ok revoke=ok irrevocable=DENIED' },
    @{ N = 'sys/leases read without sudo'; H = ($rList + $rLookup + $rRevoke + $rIrrNoSudo); Want = 'list=ok lookup=ok revoke=ok irrevocable=DENIED' })
$sinceP = UtcStamp 0
try {
    foreach ($v in $variants) {
        $w = BaoRoot @('policy', 'write', 'lease-reconciler', '-') $v.H
        $p = Invoke-Docker @('exec', $rc, 'sh', '-c', $probe)
        Write-Result (($w.Code -eq 0) -and ($p.Out.Trim() -eq $v.Want)) ('policy {0}: {1}' -f $v.N, $v.Want) $p.All
    }
} finally {
    $w = BaoRoot @('policy', 'write', 'lease-reconciler', '/openbao/setup/lease-reconciler.hcl')
}
$p = Invoke-Docker @('exec', $rc, 'sh', '-c', $probe)
Write-Result (($w.Code -eq 0) -and ($p.Out.Trim() -eq 'list=ok lookup=ok revoke=ok irrevocable=ok')) 'policy restored from config/openbao/lease-reconciler.hcl' $p.All
$dl = (Get-Date).AddSeconds($reconInterval * 2 + 10); $lastLine = ''
do { Start-Sleep -Seconds 2; $lastLine = @(((Get-ReconLog $sinceP) -split "`r?`n") | Where-Object { $_ -match 'action=(error|recovered)' } | Select-Object -Last 1) -join '' } while (($lastLine -match 'action=error') -and ((Get-Date) -lt $dl))
Write-Result ($lastLine -notmatch 'action=error') 'the reconciler loop is healthy again (after an error it logs action=recovered)' $lastLine

# =============================================================================================
Write-Host ''
Write-Host '== 5. Shipping: backstop and reconciler records in the store =='
$f1 = Find-InStore @('"source":"maria-replica"', '"engine":"backstop"', '"event":"startup-purge"') 'audit.jsonl' 5
$f2 = Find-InStore @('"source":"lease-reconciler"', '"engine":"reconciler"', '"event":"start"') 'audit.jsonl' 5
Write-Result (($f1.Objects.Count -ge 1) -and ($f2.Objects.Count -ge 1)) 'startup-purge lines (also with dropped=0, no alert) and reconciler lines are normalized into audit.jsonl' ((Show-Record ($f1.Objects | Select-Object -Last 1)) + "`n" + (Show-Record ($f2.Objects | Select-Object -Last 1)))
$z = Invoke-Docker @('run', '--rm', '--network', 'none', '-v', ($volStore + ':/store:ro'), '--entrypoint', 'bash', 'postgres:17', '-c', 'echo "startup-purge with dropped=0 that raised an alert: $(grep "replica_startup_purge" /store/alerts.jsonl | grep -c "\"dropped\":0")"')
Write-Result ($z.Out -match 'alert: 0') 'a startup purge that dropped nothing raises no alert' $z.Out

# =============================================================================================
# Cleanup: revoke this run's tokens (and with them its leases), remove clients, re-enable the event.
foreach ($tk in $script:Tokens) { [void](Invoke-Bao @('token', 'revoke', '-self') $tk) }
foreach ($c in $script:Containers) { [void](Invoke-Docker @('rm', '-f', $c)) }
[void](MaSu 'maria-replica' ("SET SESSION sql_log_bin = 0; ALTER DEFINER = 'revocation_backstop'@'localhost' EVENT replica_local.revocation_backstop ON SCHEDULE EVERY {0} SECOND ENABLE" -f $interval))
$evEnd = MaVal 'maria-replica' "SELECT CONCAT('status=', STATUS, ' every=', INTERVAL_VALUE, ' definer=', DEFINER) FROM information_schema.EVENTS WHERE EVENT_NAME = 'revocation_backstop'"
Write-Result ($evEnd -eq ('status=ENABLED every={0} definer=revocation_backstop@localhost' -f $interval)) 'after the test the backstop event is enabled, at its interval, with its own definer (every ALTER EVENT here names the definer: without it MariaDB makes the altering user, root, the definer)' $evEnd
$left = MaVal 'maria-replica' "SELECT COUNT(*) FROM mysql.global_priv WHERE User LIKE 'v-lab-%' OR User LIKE 'lab-old-%'"
$irr = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'sys/leases', 'type=irrevocable')).Out
Write-Host ''
Write-Host ('cleanup: tokens revoked, client containers removed, backstop event every {0} s and enabled; lab accounts left on maria-replica: {1}; irrevocable leases: {2}' -f $interval, $left, $irr.data.lease_count)
Write-Host ''
Write-Host 'Measurements:'
foreach ($m in $script:Measure) { Write-Host ('  ' + $m) }
Write-Host ''
Write-Host ('Summary: {0} passed, {1} failed' -f $script:Pass, $script:Fail)
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
