[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # Bounded wait for a record to reach the shipped store (seconds).
    [int]$ShipWaitSeconds = 30,
    # Seconds to wait for a replica to catch up (new users, lab accounts).
    [int]$ReplicaWaitSeconds = 60,
    # Requests per application for the volume measurement.
    [int]$AppRequests = 10,
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype-phase4',
    [string]$BaoSecretPrefix = 'openbao_phase4',
    # Temp users created and revoked in the churn check (replication health afterwards).
    [int]$ChurnUsers = 20,
    # Bound for OpenBao's revocation retry after a replica outage (measured retry delays about
    # 20 s, 40 s, 80 s, 160 s, 320 s; then the lease is irrevocable).
    [int]$RevokeRetryWaitSeconds = 200,
    # OPT-IN, LAB-ONLY: reproduce the OLD MariaDB leaks (a temp-user-style CREATE USER ...
    # IDENTIFIED BY and the phase 2/3 bao_admin rotation on the primary), then apply the
    # remediation for passwords already in binlogs (rotate, FLUSH, PURGE BINARY LOGS on the
    # primary and the replica once the replica has applied everything) and prove that the clear
    # text is gone everywhere. PURGE deletes all older binlogs of both servers, so leave this off
    # when the binlogs should stay available for inspection.
    [switch]$LeakAndPurgeTest
)

# Phase 4 checks against the RUNNING, configured phase 4 stack (compose.phase4.yaml after
# scripts\phase4-setup.ps1): database audit logging (pgAudit, server_audit), log shipping
# (Fluent Bit -> log-store volume), lab alert rules, and clear-text password leaks.
# Windows PowerShell 5.1 compatible. One PASS/FAIL line per check; exit 0 only if all pass.
#
# Same rules as the earlier checks: negative checks print the real error text and pass only if
# it matches the control under test. Developers are played by throwaway postgres:17 /
# mariadb:11.8 clients on the access network. The shipped store is read by throwaway reader
# containers that mount the log-store volume READ-ONLY (the fluent-bit image has no shell).
#
# Secrets are never printed. Password searches run inside throwaway containers that get the
# value as an environment variable of the docker CLI process and print only counts and file
# names. Lines that are printed go through Redact first.
#
# Phase 4 MariaDB design under test: OpenBao creates the MariaDB temp users on maria-replica
# ONLY, as bao_replica_admin (local to the replica) over the bao-replica network, in sessions
# with sql_log_bin = 0; the primary's MariaDB passwords are set with SET PASSWORD FOR (hash in
# the binlog); the replica's seed load is not audited.
#
# LAB-ONLY changes made and undone by this script: OpenBao's app1-pg password_authentication
# (briefly "password"), app1-maria-replica connection_url (briefly without ?sql_log_bin=0, to
# show the guard fails closed), ALTER ROLE bao_admin SET log_statement = 'ddl' (briefly), ALTER
# SYSTEM SET pgaudit.log on pg-primary (reset), SET GLOBAL server_audit_logging on
# maria-replica (OFF for one statement), lab accounts lab_rogue, lab_probe and v-lab-* (created
# and dropped), maria-sweeper and maria-replica stopped and started once each. All root
# credentials are rotated; bao_replica_admin gets a known initial password for a moment (as in
# phase4-setup.ps1) and is rotated right after. One revoked lab PostgreSQL temp password is
# written to the logs in clear text on purpose (PostgreSQL leak reproduction, case B). No
# MariaDB clear text is written unless -LeakAndPurgeTest is given (and then it is purged).
# Takes about 5 minutes.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.phase4.yaml' }
$P2ComposeFile = $ComposeFile
$P2Project = $Project
$P2BaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $root 'scripts\phase2-lib.ps1')

$netAccess = $P2Project + '_access'
$volCa = $P2Project + '_pki-ca'
$volStore = $P2Project + '_log-store'
$accessMask = '10.81.5.0/255.255.255.0'
$realmFile = Join-Path $P2Root 'config\keycloak\lab-realm.json'
$inv = [System.Globalization.CultureInfo]::InvariantCulture

$script:Pass = 0
$script:Fail = 0
$script:Tokens = New-Object System.Collections.ArrayList
$script:Leases = New-Object System.Collections.ArrayList
$script:Containers = New-Object System.Collections.ArrayList
$script:Measure = New-Object System.Collections.ArrayList

function Write-Result {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) { $script:Pass++; $tag = 'PASS'; $color = 'Green' } else { $script:Fail++; $tag = 'FAIL'; $color = 'Red' }
    Write-Host ('{0} {1}' -f $tag, $Name) -ForegroundColor $color
    if ($Detail) {
        foreach ($l in ($Detail.Trim() -split "`r?`n")) {
            if ($l.Trim()) { Write-Host ('       | ' + $l.TrimEnd()) }
        }
    }
}
# Masks anything that could be a password literal or a SCRAM verifier in text that is printed.
function Redact {
    param([string]$T)
    if (-not $T) { return $T }
    $T = $T -replace 'SCRAM-SHA-256\$[^''"\s\\]+', 'SCRAM-SHA-256$$<verifier>'
    $T = $T -replace "(?i)(PASSWORD\s*\(?\s*)'(?!SCRAM-SHA-256\$<verifier>')[^']*'", '$1''<redacted>'''
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

# --- identities (as in phase2/phase3-checks.ps1) ----------------------------------------------
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
    if (($r.Code -eq 0) -and ($null -ne $o)) {
        [void]$script:Leases.Add([string]$o.lease_id)
        return @{ R = $r; User = [string]$o.data.username; Password = [string]$o.data.password; Lease = [string]$o.lease_id; At = (Get-Date) }
    }
    return @{ R = $r; User = $null; Password = $null; Lease = $null; At = (Get-Date) }
}
$baoRootToken = Read-P2Secret $P2BaoRootTokenName
function BaoRoot { param([string[]]$A) Invoke-Bao $A $baoRootToken }

# --- database access ----------------------------------------------------------------------------
$mariaRootPw = Read-P2Secret 'maria_root_password'
$ids = @{}
function Id { param([string]$S) if (-not $ids.ContainsKey($S)) { $ids[$S] = Get-P2ContainerId $S }; return $ids[$S] }
function PgSu { param([string]$S, [string]$Sql, [string]$Db = 'app1') Invoke-Docker @('exec', '-u', 'postgres', (Id $S), 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', $Db, '-c', $Sql) }
function MaSu { param([string]$S, [string]$Sql) Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Id $S), 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mariaRootPw } }
function PgVal { param([string]$S, [string]$Sql) return (PgSu $S $Sql).Out.Trim() }
function MaVal { param([string]$S, [string]$Sql) return (MaSu $S $Sql).Out.Trim() }
function PgClient {
    param([string]$Net, [string]$ConnInfo, [string]$Sql, [string]$Password)
    Invoke-Docker @('run', '--rm', '--network', $Net, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD',
        '--entrypoint', 'psql', 'postgres:17', ($ConnInfo + ' connect_timeout=5'), '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', $Sql) @{ PGPASSWORD = $Password }
}
function MaClient {
    param([string]$Net, [string]$HostName, [string]$User, [string]$Sql, [string]$Password, [string]$Db = 'app1_masked')
    Invoke-Docker (@('run', '--rm', '--network', $Net, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD',
        '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', $HostName, '-u', $User, '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert',
        '--connect-timeout=5', '-N', '-B', $Db, '-e', $Sql)) @{ MYSQL_PWD = $Password }
}
function New-LabPassword { $a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; return -join (1..28 | ForEach-Object { $a[(Get-Random -Maximum $a.Length)] }) }
$pgReplicaConn = 'host=pg-replica dbname=app1 sslmode=verify-full sslrootcert=/ca/ca.crt'

function Wait-OnReplica {
    param([string]$PgUser, [string]$MariaUser)
    $deadline = (Get-Date).AddSeconds($ReplicaWaitSeconds)
    $pgOk = -not $PgUser; $maOk = -not $MariaUser
    while ((Get-Date) -lt $deadline) {
        if (-not $pgOk) { $pgOk = (PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $PgUser)) -eq '1' }
        if (-not $maOk) { $maOk = (MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $MariaUser)) -eq '1' }
        if ($pgOk -and $maOk) { return $true }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

# --- the shipped store --------------------------------------------------------------------------
# Starts a reader (store mounted read-only) that polls a store file until one line contains
# all needles, then prints FOUND_AT=<epoch> and the matching lines. Started BEFORE the action
# under test, so FOUND_AT minus the record's own timestamp is the shipping latency (upper bound;
# poll interval 0.2 s).
# With NEWONLY set, lines that already matched when the reader started do not count, so a
# watch started before an action waits for that action's own record.
$watchScript = @'
f="/store/$F"; end=$(( $(date +%s) + WAIT ))
match() {
  local out; out="$(grep -F -- "$N1" "$f" 2>/dev/null)"
  for v in N2 N3 N4 N5; do
    if [ -n "${!v:-}" ]; then out="$(printf '%s\n' "$out" | grep -F -- "${!v}")"; fi
  done
  printf '%s' "$out"
}
count() { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l; fi; }
base=0
if [ -n "${NEWONLY:-}" ]; then base="$(count "$(match)")"; fi
while :; do
  out="$(match)"; n="$(count "$out")"
  if [ "$n" -gt "$base" ]; then echo "FOUND_AT=$(date -u +%s.%N)"; printf '%s\n' "$out" | tail -n "$((n - base))"; exit 0; fi
  if [ "$(date +%s)" -ge "$end" ]; then echo "NOT_FOUND after ${WAIT} s (lines matching before the action: $base)"; exit 1; fi
  sleep 0.2
done
'@
function Start-StoreWatch {
    param([string[]]$Needles, [string]$File = 'audit.jsonl', [int]$Wait = $ShipWaitSeconds, [bool]$NewOnly = $true)
    $name = 'p4watch-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $envs = @{ WAIT = [string]$Wait; F = $File }
    if ($NewOnly) { $envs['NEWONLY'] = '1' }
    $i = 0
    foreach ($n in $Needles) { $i++; $envs[('N' + $i)] = $n }
    $a = @('run', '-d', '--name', $name, '--network', 'none', '-v', ($volStore + ':/store:ro'))
    foreach ($k in $envs.Keys) { $a += @('-e', $k) }
    $a += @('--entrypoint', 'bash', 'postgres:17', '-c', $watchScript)
    [void]$script:Containers.Add($name)
    [void](Invoke-Docker $a $envs)
    return $name
}
function Wait-StoreWatch {
    param([string]$Name, [int]$Wait = $ShipWaitSeconds)
    [void](Invoke-Docker @('wait', $Name) @{} ($Wait + 30))
    $l = (Invoke-Docker @('logs', $Name)).Out
    [void](Invoke-Docker @('rm', '-f', $Name))
    $found = $null
    $objs = @()
    foreach ($x in ($l -split "`r?`n")) {
        if ($x -match '^FOUND_AT=([\d.]+)') { $found = [double]::Parse($Matches[1], $inv) }
        elseif ($x.Trim().StartsWith('{')) { $o = ConvertFrom-JsonOrNull $x; if ($null -ne $o) { $objs += $o } }
    }
    return @{ FoundAt = $found; Objects = $objs; Raw = $l }
}
function Find-InStore {
    param([string[]]$Needles, [string]$File = 'audit.jsonl', [int]$Wait = $ShipWaitSeconds)
    return Wait-StoreWatch (Start-StoreWatch $Needles $File $Wait $false) $Wait
}
function ConvertTo-Epoch { param([string]$Ts) if (-not $Ts) { return $null }; return [DateTimeOffset]::Parse($Ts, $inv).ToUnixTimeMilliseconds() / 1000.0 }
function Show-Record {
    param($o)
    if ($null -eq $o) { return '(none)' }
    $keys = @('timestamp', 'source', 'engine', 'event', 'user', 'client_host', 'statement', 'alert', 'alert_reason', 'state_code', 'retcode', 'audit_class', 'message', 'lease_id', 'db_username', 'path', 'error')
    $parts = @()
    foreach ($k in $keys) { if ($o.PSObject.Properties.Name -contains $k -and $null -ne $o.$k -and [string]$o.$k -ne '') { $parts += ('{0}={1}' -f $k, [string]$o.$k) } }
    return (Redact ($parts -join ' | '))
}
# Runs a bash script in a throwaway container (root, no network unless given) with the given
# volumes; values in $Env reach the container as environment variables only.
function Invoke-Reader {
    param([string]$Script, [hashtable]$Env = @{}, [string[]]$Volumes = @(), [string]$Image = 'postgres:17', [string]$Network = 'none', [int]$Timeout = 180)
    $a = @('run', '--rm', '--network', $Network, '-u', '0')
    foreach ($k in $Env.Keys) { $a += @('-e', $k) }
    foreach ($v in $Volumes) { $a += @('-v', $v) }
    $a += @('--entrypoint', 'bash', $Image, '-c', $Script)
    Invoke-Docker $a $Env $Timeout
}
function Compose { param([string[]]$A) Invoke-Docker (@('compose', '-f', $P2ComposeFile) + $A) @{} 180 }

Write-Host ('Phase 4 checks: compose file {0}, project {1}' -f $P2ComposeFile, $P2Project)
foreach ($s in @('pg-primary', 'maria-primary', 'pg-replica', 'maria-replica', 'pg-sweeper', 'maria-sweeper', 'openbao', 'keycloak', 'fluent-bit')) { [void](Id $s) }
$st = Get-BaoStatus
if (($null -eq $st.Obj) -or $st.Obj.sealed) { throw 'OpenBao is sealed or not answering. Run scripts\phase4-setup.ps1 (or phase2-unseal.ps1 with the phase 4 parameters).' }
$stamp = (Get-Date).ToString('HHmmssfff')

# =============================================================================================
Write-Host ''
Write-Host '== Audit plugins loaded on all four database servers =='
foreach ($s in @('pg-primary', 'pg-replica')) {
    $r = PgSu $s "SELECT 'shared_preload_libraries=' || current_setting('shared_preload_libraries') || ' pgaudit_loaded=' || (SELECT count(*) FROM pg_settings WHERE name = 'pgaudit.log') || ' logging_collector=' || current_setting('logging_collector') || ' log_destination=' || current_setting('log_destination') || ' log_connections=' || current_setting('log_connections') || ' log_disconnections=' || current_setting('log_disconnections') || ' log_statement=' || current_setting('log_statement') || ' log_line_prefix=[' || current_setting('log_line_prefix') || ']' || ' pgaudit.log source=' || (SELECT source FROM pg_settings WHERE name = 'pgaudit.log')"
    Assert-Works ('{0}: pgAudit preloaded; jsonlog via the logging collector; log_connections/disconnections on; core log_statement none; log_line_prefix has %m %p %u %h' -f $s) $r 'shared_preload_libraries=pgaudit pgaudit_loaded=1 logging_collector=on log_destination=jsonlog log_connections=on log_disconnections=on log_statement=none log_line_prefix=\[%m \[%p\] user=%u db=%d host=%h app=%a \]'
}
foreach ($s in @('maria-primary', 'maria-replica')) {
    $r = MaSu $s "SELECT CONCAT('plugin=', PLUGIN_STATUS, ' load_option=', LOAD_OPTION, ' logging=', @@server_audit_logging, ' output=', @@server_audit_output_type, ' file=', @@server_audit_file_path, ' events=', @@server_audit_events, ' excl_users=', @@server_audit_excl_users, ' general_log=', @@general_log, ' slow_query_log=', @@slow_query_log) FROM information_schema.PLUGINS WHERE PLUGIN_NAME = 'SERVER_AUDIT'"
    Assert-Works ('{0}: server_audit ACTIVE, FORCE_PLUS_PERMANENT, logging ON to a file; general log and slow log OFF' -f $s) $r 'plugin=ACTIVE load_option=FORCE_PLUS_PERMANENT logging=(1|ON) output=file file=/var/log/mariadb-audit/server_audit\.log events=CONNECT,QUERY excl_users=\S+ general_log=(0|OFF) slow_query_log=(0|OFF)'
}

# =============================================================================================
Write-Host ''
Write-Host '== MariaDB temp users on the replica: network path, replica binlog, OpenBao configuration =='
$nb = (Invoke-Docker @('network', 'inspect', '-f', '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}', ($P2Project + '_bao-replica'))).Out.Trim() -replace ($P2Project + '-'), '' -replace '-1=', '='
$mrNets = (Invoke-Docker @('inspect', '-f', '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}}{{range $v.Aliases}},{{.}}{{end}} {{end}}', (Id 'maria-replica'))).Out.Trim() -replace ($P2Project + '_'), ''
$resolve = (Invoke-Docker @('exec', (Id 'maria-replica'), 'getent', 'hosts', 'maria-primary')).Out.Trim()
$resolveB = (Invoke-Docker @('exec', (Id 'openbao'), 'getent', 'hosts', 'maria-replica-admin')).Out.Trim()
$members = @($nb -split '\s+' | Where-Object { $_ })
$ok = ($members.Count -eq 2) -and ($nb -match 'openbao=10\.81\.9\.10/24') -and ($nb -match 'maria-replica=10\.81\.9\.12/24') -and ($mrNets -notmatch 'bao-admin=') -and
      ($mrNets -match 'bao-replica=10\.81\.9\.12,[^ ]*maria-replica-admin') -and ($resolve -match '^10\.81\.8\.10\s') -and ($resolveB -match '^10\.81\.9\.12\s')
Write-Result $ok 'network bao-replica holds only openbao (10.81.9.10) and maria-replica (10.81.9.12, alias maria-replica-admin there only); the replica is not on bao-admin and resolves maria-primary to its maria-repl address' ('bao-replica: ' + $nb + "`nmaria-replica: " + $mrNets + "`nin maria-replica, maria-primary -> " + $resolve + "`nin openbao, maria-replica-admin -> " + $resolveB)
$r = MaSu 'maria-replica' "SELECT CONCAT('log_bin=', @@log_bin, ' log_slave_updates=', @@log_slave_updates, ' binlog_format=', @@binlog_format, ' gtid_strict_mode=', @@gtid_strict_mode, ' gtid_binlog_state=[', @@gtid_binlog_state, '] gtid_slave_pos=', @@gtid_slave_pos)"
$ok = ($r.Code -eq 0) -and ($r.Out -match 'log_bin=(1|ON) log_slave_updates=(1|ON) binlog_format=ROW gtid_strict_mode=(1|ON)') -and ($r.Out -notmatch '\b\d+-2-\d+')
Write-Result $ok 'maria-replica writes its own binlog (log_bin, log_slave_updates), and that binlog has no local GTID (server_id 2): every local statement ran with sql_log_bin = 0' $r.All
$cfgR = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'database/config/app1-maria-replica')).Out
$roleM = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'database/roles/app1-maria-ro')).Out
$cfgP = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'database/config/app1-maria')).Out
$guardRe = '^SET @sql_log_bin_must_be_0 = \(SELECT 1 UNION ALL SELECT 1 FROM DUAL WHERE @@session\.sql_log_bin <> 0\);'
$cre = (@($roleM.data.creation_statements) -join ' '); $rev = (@($roleM.data.revocation_statements) -join ' '); $rot = (@($cfgR.data.root_credentials_rotate_statements) -join ' ')
$ok = ($cfgR.data.connection_details.connection_url -eq '{{username}}:{{password}}@tcp(maria-replica-admin:3306)/?sql_log_bin=0') -and ($cfgR.data.connection_details.username -eq 'bao_replica_admin') -and
      ($cfgR.data.connection_details.tls_server_name -eq 'maria-replica') -and ((@($cfgR.data.allowed_roles) -join ',') -eq 'app1-maria-ro') -and ($roleM.data.db_name -eq 'app1-maria-replica') -and
      ($cre -match $guardRe) -and ($cre -match "CREATE USER '\{\{name\}\}'@'10\.81\.5\.0/255\.255\.255\.0' IDENTIFIED BY '\{\{password\}\}'") -and ($rev -match $guardRe) -and ($rev -match "KILL USER '\{\{name\}\}'; DROP USER IF EXISTS") -and
      ($rot -match ($guardRe -replace ';$', '; SET PASSWORD = PASSWORD\(''\{\{password\}\}''\)')) -and (@($cfgP.data.allowed_roles) -notcontains 'app1-maria-ro')
Write-Result $ok 'OpenBao: role app1-maria-ro uses connection app1-maria-replica (bao_replica_admin @ maria-replica-admin, ?sql_log_bin=0, TLS name maria-replica); every statement list starts with the sql_log_bin guard; app1-maria (primary) no longer allows app1-maria-ro' (('connection_url: {0}; username: {1}; allowed_roles: {2}; app1-maria allowed_roles: {3}' -f $cfgR.data.connection_details.connection_url, $cfgR.data.connection_details.username, (@($cfgR.data.allowed_roles) -join ','), (@($cfgP.data.allowed_roles) -join ',')) + "`ncreation: " + $cre + "`nrevocation: " + $rev + "`nroot rotation: " + $rot)
$g = MaSu 'maria-replica' "SHOW GRANTS FOR 'bao_replica_admin'@'10.81.9.10'"
$gl = @($g.Out -split "`r?`n" | Where-Object { $_ -match '^GRANT' })
$ok = ($g.Code -eq 0) -and ($gl.Count -eq 2) -and ($g.Out -match 'GRANT CREATE USER, CONNECTION ADMIN, READ_ONLY ADMIN, BINLOG ADMIN ON \*\.\* TO `bao_replica_admin`@`10\.81\.9\.10`.*REQUIRE SSL') -and
      ($g.Out -match 'GRANT SELECT ON `app1_masked`\.\* TO `bao_replica_admin`@`10\.81\.9\.10` WITH GRANT OPTION') -and ($g.Out -notmatch 'SUPER|`app1`\.|`mysql`')
$np = MaVal 'maria-primary' "SELECT COUNT(*) FROM mysql.global_priv WHERE User = 'bao_replica_admin'"
Write-Result ($ok -and ($np -eq '0')) 'bao_replica_admin exists on maria-replica only (0 rows on the primary), host 10.81.9.10, REQUIRE SSL: CREATE USER, READ ONLY ADMIN, BINLOG ADMIN, CONNECTION ADMIN and SELECT ON app1_masked.* WITH GRANT OPTION, nothing else' (($g.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'") + "`nrows on maria-primary: " + $np)

# =============================================================================================
Write-Host ''
Write-Host '== A developer query on each replica reaches the store (person -> lease -> username -> query) =='
$alice = Connect-Bao 'alice'
Write-Result ($null -ne $alice.Token) 'alice logs in to OpenBao (jwt)' ('exit {0}' -f $alice.R.Code)
$cp = Get-Creds $alice.Token 'app1-pg-ro'
$cm = Get-Creds $alice.Token 'app1-maria-ro'
$onRep = Wait-OnReplica $cp.User $cm.User
Write-Result (($null -ne $cp.User) -and ($null -ne $cm.User) -and $onRep) 'alice gets a PostgreSQL and a MariaDB temp user; both reached the replicas' ('pg {0} (lease {1}); maria {2} (lease {3})' -f $cp.User, $cp.Lease, $cm.User, $cm.Lease)

# Server-wide pgAudit settings, as the temp user sees them (temp users have no role setting).
$r = PgClient $netAccess ($pgReplicaConn + ' user=' + $cp.User) "SELECT 'pgaudit.log=' || current_setting('pgaudit.log') || ' (source ' || (SELECT source FROM pg_settings WHERE name = 'pgaudit.log') || ') log_catalog=' || current_setting('pgaudit.log_catalog') || ' log_relation=' || current_setting('pgaudit.log_relation') || ' log_parameter=' || current_setting('pgaudit.log_parameter')" $cp.Password
Assert-Works 'PG replica: in a temp user''s session pgaudit.log = read, write, ddl, role, misc_set from the server command line; catalog queries logged' $r 'pgaudit\.log=read, write, ddl, role, misc_set \(source command line\) log_catalog=on log_relation=off log_parameter=off'

$qPg = ('SELECT count(*) AS p4q_{0} FROM debug.customers' -f $stamp)
$w = Start-StoreWatch @(('"user":"' + $cp.User + '"'), '"source":"pg-replica"', '"event":"audit"', ('p4q_' + $stamp))
$r = PgClient $netAccess ($pgReplicaConn + ' user=' + $cp.User) $qPg $cp.Password
$f = Wait-StoreWatch $w
$recPg = $f.Objects | Select-Object -First 1
$latPg = -1
if (($null -ne $recPg) -and $f.FoundAt) { $latPg = [Math]::Round($f.FoundAt - (ConvertTo-Epoch $recPg.timestamp), 2) }
$ok = ($r.Code -eq 0) -and ($null -ne $recPg) -and ($recPg.user -eq $cp.User) -and ($recPg.source -eq 'pg-replica') -and ($recPg.engine -eq 'postgresql') -and
      ([string]$recPg.client_host -match '^10\.81\.5\.\d+$') -and ($recPg.statement -eq $qPg) -and ($recPg.audit_class -eq 'READ') -and $recPg.timestamp
Write-Result $ok ('PG: the masked-view SELECT on pg-replica is in the store with the exact username, source, client host and statement ({0} s after the statement)' -f $latPg) ('query exit {0}: {1}' -f $r.Code, $r.All + "`n" + (Show-Record $recPg))
Add-Measure ('shipping latency PG (pgAudit record -> store): {0} s' -f $latPg)

$qMa = ('SELECT COUNT(*) AS p4q_{0} FROM app1_masked.customers' -f $stamp)
$w = Start-StoreWatch @(('"user":"' + $cm.User + '"'), '"source":"maria-replica"', '"event":"query"', ('p4q_' + $stamp))
$r = MaClient $netAccess 'maria-replica' $cm.User $qMa $cm.Password
$f = Wait-StoreWatch $w
$recMa = $f.Objects | Select-Object -First 1
$latMa = -1
if (($null -ne $recMa) -and $f.FoundAt) { $latMa = [Math]::Round($f.FoundAt - (ConvertTo-Epoch $recMa.timestamp), 2) }
$ok = ($r.Code -eq 0) -and ($null -ne $recMa) -and ($recMa.user -eq $cm.User) -and ($recMa.source -eq 'maria-replica') -and ($recMa.engine -eq 'mariadb') -and
      ([string]$recMa.client_host -match '^10\.81\.5\.\d+$') -and ($recMa.statement -eq $qMa) -and ($recMa.retcode -eq '0') -and $recMa.timestamp
Write-Result $ok ('Maria: the masked-view SELECT on maria-replica is in the store with the exact username, source, client host and statement ({0} s after the statement; server_audit timestamps have 1 s resolution)' -f $latMa) ('query exit {0}: {1}' -f $r.Code, $r.All + "`n" + (Show-Record $recMa))
Add-Measure ('shipping latency MariaDB (server_audit record -> store): {0} s (+/- 1 s)' -f $latMa)

# Logins of the temp users on the replicas (log_connections / server_audit CONNECT).
$f1 = Find-InStore @(('"user":"' + $cp.User + '"'), '"source":"pg-replica"', '"event":"login"') 'audit.jsonl' 10
$f2 = Find-InStore @(('"user":"' + $cm.User + '"'), '"source":"maria-replica"', '"event":"login"') 'audit.jsonl' 10
$ok = ($f1.Objects.Count -ge 1) -and ($f2.Objects.Count -ge 1) -and ([string]$f1.Objects[0].client_host -match '^10\.81\.5\.') -and ([string]$f2.Objects[0].client_host -match '^10\.81\.5\.')
Write-Result $ok 'both temp users'' logins are in the store with client host (PostgreSQL log_connections, server_audit CONNECT)' ((Show-Record $f1.Objects[0]) + "`n" + (Show-Record $f2.Objects[0]))

# The OpenBao audit record of the same credential requests, shipped to the same store.
$b1 = Find-InStore @('"source":"openbao"', '"event":"response"', ('"db_username":"' + $cp.User + '"')) 'audit.jsonl' 15
$b2 = Find-InStore @('"source":"openbao"', '"event":"response"', ('"db_username":"' + $cm.User + '"')) 'audit.jsonl' 15
$o1 = $b1.Objects | Select-Object -First 1
$o2 = $b2.Objects | Select-Object -First 1
$ok = ($null -ne $o1) -and ($null -ne $o2) -and ($o1.user -eq 'alice') -and ($o1.display_name -eq 'jwt-alice') -and ($o1.lease_id -eq $cp.Lease) -and ($o1.path -eq 'database/creds/app1-pg-ro') -and
      ($o2.user -eq 'alice') -and ($o2.lease_id -eq $cm.Lease) -and ($o2.path -eq 'database/creds/app1-maria-ro')
$join = @()
foreach ($pair in @(@($o1, $recPg), @($o2, $recMa))) {
    $b = $pair[0]; $q = $pair[1]
    if (($null -ne $b) -and ($null -ne $q)) {
        $join += ('person={0} (OpenBao display_name {1}, entity {2}) -> lease {3} (issued {4}) -> username {5} -> on {6} from {7} at {8}: {9}' -f $b.user, $b.display_name, $b.entity_id, $b.lease_id, $b.timestamp, $b.db_username, $q.source, $q.client_host, $q.timestamp, $q.statement)
    }
}
Write-Result $ok 'join in the store: OpenBao response (person, lease) -> generated username -> the query on the replica' ($join -join "`n")

# =============================================================================================
Write-Host ''
Write-Host '== Denied queries and writes by a temp user: audit records and alerts =='
$cases = @(
    @{ E = 'PG'; Sql = ("SELECT email, 'p4den_{0}' FROM public.customers" -f $stamp); Want = 'permission denied for table customers'; Alert = 'temp_user_denied'; Src = 'pg-replica' },
    @{ E = 'PG'; Sql = ("INSERT INTO public.customers (email, full_name) VALUES ('p4wr_{0}@x.test', 'X')" -f $stamp); Want = 'cannot execute INSERT in a read-only transaction'; Alert = 'temp_user_write'; Src = 'pg-replica' },
    @{ E = 'Maria'; Sql = ("SELECT email, 'p4den_{0}' FROM app1.customers" -f $stamp); Want = 'SELECT command denied to user'; Alert = 'temp_user_denied'; Src = 'maria-replica' },
    @{ E = 'Maria'; Sql = ("INSERT INTO app1.customers (email, full_name) VALUES ('p4wr_{0}@x.test', 'X')" -f $stamp); Want = 'INSERT command denied to user|running with the --read-only option'; Alert = 'temp_user_write'; Src = 'maria-replica' }
)
foreach ($c in $cases) {
    if ($c.E -eq 'PG') { $u = $cp.User } else { $u = $cm.User }
    $marker = [regex]::Match($c.Sql, 'p4(den|wr)_\d+').Value
    $wA = Start-StoreWatch @(('"user":"' + $u + '"'), ('"source":"' + $c.Src + '"'), $marker) 'audit.jsonl'
    $wB = Start-StoreWatch @(('"user":"' + $u + '"'), ('"alert":"' + $c.Alert + '"'), $marker) 'alerts.jsonl'
    if ($c.E -eq 'PG') { $r = PgClient $netAccess ($pgReplicaConn + ' user=' + $u) $c.Sql $cp.Password } else { $r = MaClient $netAccess 'maria-replica' $u $c.Sql $cm.Password }
    $fa = Wait-StoreWatch $wA
    $fb = Wait-StoreWatch $wB
    $ra = $fa.Objects | Select-Object -First 1
    $rb = $fb.Objects | Select-Object -First 1
    $ok = ($r.Code -ne 0) -and ($r.All -match $c.Want) -and ($null -ne $ra) -and ($null -ne $rb) -and ($rb.alert -eq $c.Alert) -and ($rb.statement -eq $c.Sql)
    Write-Result $ok ('{0}: "{1}" is refused, recorded in audit.jsonl and raises alert {2}' -f $c.E, ($c.Sql -replace '\s+', ' '), $c.Alert) ('client: exit {0}: {1}' -f $r.Code, $r.All + "`naudit: " + (Show-Record $ra) + "`nalert: " + (Show-Record $rb))
}

# =============================================================================================
Write-Host ''
Write-Host '== Login alerts: account not on the allowlist, superuser =='
$rogPw = New-LabPassword
[void](PgSu 'pg-primary' 'DROP ROLE IF EXISTS lab_rogue')
$r = Invoke-Docker @('exec', '-u', 'postgres', '-e', 'P4PW', (Id 'pg-primary'), 'bash', '-c', 'printf "%s" "\set pw ''$P4PW''
CREATE ROLE lab_rogue LOGIN PASSWORD :''pw'';
GRANT debug_ro TO lab_rogue;" | psql -X -q -v ON_ERROR_STOP=1 -d app1') @{ P4PW = $rogPw }
[void](MaSu 'maria-primary' ("DROP USER IF EXISTS 'lab_rogue'@'{0}'" -f $accessMask))
# Phase 4 rule for passwords set on the primary: SET PASSWORD FOR on a locked account (the
# binlog gets the hash only; IDENTIFIED BY would put lab_rogue's password there in clear text).
$r2 = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', '-e', 'P4PW', (Id 'maria-primary'), 'bash', '-c',
    ('mariadb --protocol=socket -uroot -e "CREATE USER ''lab_rogue''@''{0}'' REQUIRE SSL ACCOUNT LOCK; SET PASSWORD FOR ''lab_rogue''@''{0}'' = PASSWORD(''$P4PW''); ALTER USER ''lab_rogue''@''{0}'' ACCOUNT UNLOCK; GRANT SELECT ON app1_masked.* TO ''lab_rogue''@''{0}''" 2>&1 | sed -E "s/PASSWORD\(.[^)]*\)/PASSWORD(<redacted>)/"' -f $accessMask)) @{ MYSQL_PWD = $mariaRootPw; P4PW = $rogPw }
$onRep = Wait-OnReplica 'lab_rogue' 'lab_rogue'
Note ('LAB-ONLY account lab_rogue created outside OpenBao on both primaries (pg exit {0}, maria exit {1}); on the replicas: {2}' -f $r.Code, $r2.Code, $onRep)
$wP = Start-StoreWatch @('"user":"lab_rogue"', '"source":"pg-replica"', '"alert":"login_not_allowlisted"') 'alerts.jsonl'
$wM = Start-StoreWatch @('"user":"lab_rogue"', '"source":"maria-replica"', '"alert":"login_not_allowlisted"') 'alerts.jsonl'
$rp = PgClient $netAccess ($pgReplicaConn + ' user=lab_rogue') 'SELECT current_user' $rogPw
$rm = MaClient $netAccess 'maria-replica' 'lab_rogue' 'SELECT CURRENT_USER()' $rogPw
$fp = Wait-StoreWatch $wP
$fm = Wait-StoreWatch $wM
Write-Result (($rp.Code -eq 0) -and ($fp.Objects.Count -ge 1)) 'PG: a login on pg-replica by lab_rogue (not on the allowlist) raises login_not_allowlisted' ('login: exit {0}: {1}' -f $rp.Code, $rp.All + "`nalert: " + (Show-Record ($fp.Objects | Select-Object -First 1)))
Write-Result (($rm.Code -eq 0) -and ($fm.Objects.Count -ge 1)) 'Maria: a login on maria-replica by lab_rogue (not on the allowlist) raises login_not_allowlisted' ('login: exit {0}: {1}' -f $rm.Code, $rm.All + "`nalert: " + (Show-Record ($fm.Objects | Select-Object -First 1)))
$fc = Find-InStore @('"source":"pg-primary"', '"user":"postgres"', '"audit_command":"CREATE ROLE"', 'lab_rogue') 'audit.jsonl' 10
$fc2 = Find-InStore @('"source":"maria-primary"', '"user":"root"', 'SET PASSWORD FOR', 'lab_rogue') 'audit.jsonl' 10
$rc1 = $fc.Objects | Select-Object -Last 1
$rc2 = $fc2.Objects | Select-Object -Last 1
Write-Result (($null -ne $rc1) -and ($rc1.statement -match 'PASSWORD <REDACTED>$') -and ($null -ne $rc2) -and ($rc2.statement -match 'PASSWORD\(\*\*\*\*\*\)')) 'the superusers'' own account creation is audited on the primaries, with the password redacted (pgAudit role class for postgres; server_audit masks root''s SET PASSWORD FOR ... = PASSWORD(*****))' ((Show-Record $rc1) + "`n" + (Show-Record $rc2))
[void](PgSu 'pg-primary' 'DROP ROLE IF EXISTS lab_rogue')
[void](MaSu 'maria-primary' ("DROP USER IF EXISTS 'lab_rogue'@'{0}'" -f $accessMask))

# Superuser: over the network (refused by pg_hba / host), and locally (docker exec).
$wP = Start-StoreWatch @('"user":"postgres"', '"source":"pg-replica"', '"alert":"superuser_login"', '"event":"login_failed"') 'alerts.jsonl'
$r = PgClient $netAccess 'host=pg-replica dbname=app1 user=postgres sslmode=verify-full sslrootcert=/ca/ca.crt' 'SELECT 1' 'not-the-password'
$fp = Wait-StoreWatch $wP
Write-Result (($r.Code -ne 0) -and ($r.All -match 'pg_hba\.conf rejects connection .*user "postgres"') -and ($fp.Objects.Count -ge 1)) 'PG: a postgres login attempt over the network (rejected by pg_hba) raises superuser_login' ('client: exit {0}: {1}' -f $r.Code, $r.All + "`nalert: " + (Show-Record ($fp.Objects | Select-Object -First 1)))
$wP = Start-StoreWatch @('"user":"postgres"', '"source":"pg-replica"', '"alert":"superuser_login"', 'application_name=p4-superuser-probe') 'alerts.jsonl'
$r = Invoke-Docker @('exec', '-u', 'postgres', (Id 'pg-replica'), 'psql', '-X', '-At', 'dbname=postgres application_name=p4-superuser-probe', '-c', 'SELECT 1')
$fp = Wait-StoreWatch $wP
Write-Result (($r.Code -eq 0) -and ($fp.Objects.Count -ge 1)) 'PG: a local postgres login (docker exec psql) raises superuser_login' (Show-Record ($fp.Objects | Select-Object -First 1))
$wM = Start-StoreWatch @('"user":"root"', '"source":"maria-replica"', '"alert":"superuser_login"', '"event":"login_failed"') 'alerts.jsonl'
$r = MaClient $netAccess 'maria-replica' 'root' 'SELECT 1' 'not-the-password'
$fm = Wait-StoreWatch $wM
Write-Result (($r.Code -ne 0) -and ($fm.Objects.Count -ge 1)) 'Maria: a root login attempt over the network (refused) raises superuser_login' ('client: exit {0}: {1}' -f $r.Code, $r.All + "`nalert: " + (Show-Record ($fm.Objects | Select-Object -First 1)))
$wM = Start-StoreWatch @('"user":"root"', '"source":"maria-replica"', '"alert":"superuser_login"', '"event":"login"', '"client_host":"localhost"') 'alerts.jsonl'
[void](MaSu 'maria-replica' 'SELECT 1')
$fm = Wait-StoreWatch $wM
Write-Result ($fm.Objects.Count -ge 1) 'Maria: a local root login (docker exec mariadb) raises superuser_login' (Show-Record ($fm.Objects | Select-Object -First 1))

# Controls: no allowlist alert for temp users, the application, OpenBao, sweepers, replication;
# no superuser alert for the PostgreSQL healthcheck.
$r = Invoke-Reader @'
a=/store/alerts.jsonl
echo "login_not_allowlisted total: $(grep -c '"alert":"login_not_allowlisted"' $a)"
echo "login_not_allowlisted for allowlisted or v- accounts: $(grep '"alert":"login_not_allowlisted"' $a | grep -cE '"user":"(v-[^"]*|app1_runtime|app1_migrator|bao_admin|bao_replica_admin|session_sweeper|replicator|healthcheck|postgres|root)"')"
echo "superuser_login for the pg healthcheck: $(grep '"alert":"superuser_login"' $a | grep -c 'pg-healthcheck')"
echo "logins in the store by account: $(grep '"event":"login"' /store/audit.jsonl | grep -oE '"user":"[^"]*"' | sed -E 's/"user":"(v-[^"]*)"/v-*/; s/"user":"([^"]*)"/\1/' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
'@ @{} @(($volStore + ':/store:ro'))
$o = $r.Out
$ok = ($r.Code -eq 0) -and ($o -match 'for allowlisted or v- accounts: 0') -and ($o -match 'pg healthcheck: 0') -and ($o -match 'login_not_allowlisted total: [1-9]')
Write-Result $ok 'controls: no login_not_allowlisted alert for any allowlisted or temp account, no superuser alert for the PostgreSQL healthcheck' $o

# =============================================================================================
Write-Host ''
Write-Host '== OpenBao: a failed request raises an alert =='
$bob = Connect-Bao 'bob'
$w = Start-StoreWatch @('"source":"openbao"', '"user":"bob"', '"alert":"openbao_request_failed"', 'database/creds/app1-pg-ro') 'alerts.jsonl'
$cb = Get-Creds $bob.Token 'app1-pg-ro'
$fw = Wait-StoreWatch $w
Write-Result (($null -eq $cb.User) -and ($cb.R.All -match 'permission denied') -and ($fw.Objects.Count -ge 1)) 'bob (not in app1-devs) is refused database/creds/app1-pg-ro; the error response raises openbao_request_failed' ('bao: ' + $cb.R.All + "`nalert: " + (Show-Record ($fw.Objects | Select-Object -First 1)))
Note 'Stand-in only: a broken audit device cannot be seen in the log it breaks (OpenBao refuses requests when its only audit device fails); that needs a check outside OpenBao (phase 5).'

# =============================================================================================
Write-Host ''
Write-Host '== Clear-text passwords: PostgreSQL (pgAudit, core statement logging, OpenBao password_authentication) =='
# The CREATE ROLE of alice's pg user above: pgAudit's own record.
$f = Find-InStore @('"source":"pg-primary"', '"user":"bao_admin"', '"audit_command":"CREATE ROLE"', $cp.User) 'audit.jsonl' 15
$rec = $f.Objects | Select-Object -First 1
Write-Result (($null -ne $rec) -and ($rec.statement -match 'PASSWORD <REDACTED>')) 'PG primary: pgAudit logs bao_admin''s CREATE ROLE (role class) with the password replaced by <REDACTED>' (Show-Record $rec)

# Case matrix on the primary. Each case issues one credential and revokes it right away.
#   A: password_authentication=password (clear text sent), core log_statement off  -> pgAudit only
#   B: password_authentication=password, ALTER ROLE bao_admin SET log_statement = 'ddl' -> core logs the statement
#   C: password_authentication=scram-sha-256, log_statement = 'ddl'
$caseCreds = @{}
try {
    [void](BaoRoot @('write', 'database/config/app1-pg', 'password_authentication=password'))
    $caseCreds['A'] = Get-Creds $alice.Token 'app1-pg-ro'
    [void](PgSu 'pg-primary' "ALTER ROLE bao_admin SET log_statement = 'ddl'")
    # Writing the connection config makes OpenBao reconnect, so the role setting applies.
    [void](BaoRoot @('write', 'database/config/app1-pg', 'password_authentication=password'))
    $caseCreds['B'] = Get-Creds $alice.Token 'app1-pg-ro'
    [void](BaoRoot @('write', 'database/config/app1-pg', 'password_authentication=scram-sha-256'))
    $caseCreds['C'] = Get-Creds $alice.Token 'app1-pg-ro'
} finally {
    [void](PgSu 'pg-primary' 'ALTER ROLE bao_admin RESET log_statement')
    [void](BaoRoot @('write', 'database/config/app1-pg', 'password_authentication=scram-sha-256'))
    foreach ($k in $caseCreds.Keys) { if ($caseCreds[$k].Lease) { [void](BaoRoot @('lease', 'revoke', $caseCreds[$k].Lease)) } }
}
$cfg = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'database/config/app1-pg')).Out
$set = PgVal 'pg-primary' "SELECT coalesce((SELECT array_to_string(setconfig, ',') FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole WHERE r.rolname = 'bao_admin'), 'none')"
Write-Result (($caseCreds['A'].User) -and ($caseCreds['B'].User) -and ($caseCreds['C'].User) -and ($cfg.data.connection_details.password_authentication -eq 'scram-sha-256') -and ($set -eq 'none')) 'cases A/B/C issued (and revoked); restored: password_authentication=scram-sha-256, no role setting on bao_admin' ('A {0}; B {1}; C {2}; bao_admin role settings: {3}' -f $caseCreds['A'].User, $caseCreds['B'].User, $caseCreds['C'].User, $set)
Start-Sleep -Seconds 4

# =============================================================================================
# Every log location, searched for given values inside one throwaway container.
$searchVols = @(
    @{ N = 'pg-primary-log'; V = 'pg-primary-log' }, @{ N = 'pg-replica-log'; V = 'pg-replica-log' },
    @{ N = 'maria-primary-audit'; V = 'maria-primary-audit' }, @{ N = 'maria-replica-audit'; V = 'maria-replica-audit' },
    @{ N = 'bao-audit'; V = 'bao-audit' }, @{ N = 'pg-sweeper-log'; V = 'pg-sweeper-log' }, @{ N = 'maria-sweeper-log'; V = 'maria-sweeper-log' },
    @{ N = 'log-store'; V = 'log-store' },
    @{ N = 'pg-data'; V = 'pg-data' }, @{ N = 'pg-replica-data'; V = 'pg-replica-data' },
    @{ N = 'maria-data'; V = 'maria-data' }, @{ N = 'maria-replica-data'; V = 'maria-replica-data' })
# One pass per location with all values (grep -f), then per value only over the files that hit.
$searchScript = @'
vars="$(compgen -A variable | grep '^PW_' | sort)"
: > /tmp/all
for v in $vars; do printf '%s\n' "${!v}" >> /tmp/all; done
for d in /s/*; do
  cand="$(grep -rlaF -f /tmp/all "$d" 2>/dev/null)"
  for v in $vars; do
    printf '%s\n' "${!v}" > /tmp/one
    files=""
    for f in $cand; do if grep -qaF -f /tmp/one "$f"; then files="$files ${f#$d/}"; fi; done
    echo "$v|$(basename "$d")|$files"
  done
done
rm -f /tmp/all /tmp/one
'@
function Search-Values {
    param([hashtable]$Values)
    $vols = @()
    foreach ($s in $searchVols) { $vols += ('{0}_{1}:/s/{2}:ro' -f $P2Project, $s.V, $s.N) }
    $envs = @{}
    foreach ($k in $Values.Keys) { $envs[('PW_' + $k)] = $Values[$k] }
    $r = Invoke-Reader $searchScript $envs $vols 'postgres:17' 'none' 300
    $res = @{}
    foreach ($l in ($r.Out -split "`r?`n")) {
        if ($l -match '^PW_([^|]+)\|([^|]+)\|(.*)$') {
            if (-not $res.ContainsKey($Matches[1])) { $res[$Matches[1]] = @{} }
            $res[$Matches[1]][$Matches[2]] = $Matches[3].Trim()
        }
    }
    # docker logs (stdout/stderr) of every server, OpenBao and the shipper.
    $dl = @{}
    foreach ($s in @('pg-primary', 'pg-replica', 'maria-primary', 'maria-replica', 'openbao', 'fluent-bit', 'pg-sweeper', 'maria-sweeper')) { $dl[$s] = (Invoke-Docker @('logs', (Id $s))).All }
    foreach ($k in $Values.Keys) {
        if (-not $res.ContainsKey($k)) { $res[$k] = @{} }
        $hits = @()
        foreach ($s in $dl.Keys) { if ($dl[$s].Contains($Values[$k])) { $hits += $s } }
        $res[$k]['docker-logs'] = ($hits -join ' ')
    }
    return @{ R = $r; Res = $res }
}
function Format-Hits { param($H) return ((@($H.Keys | Sort-Object | ForEach-Object { if ($H[$_]) { '{0}: {1}' -f $_, $H[$_] } else { '{0}: -' -f $_ } })) -join "`n") }
function Get-HitLocations { param($H) return @($H.Keys | Where-Object { $H[$_] }) }

$wrongPg = New-LabPassword
$wrongMa = New-LabPassword
$r1 = PgClient $netAccess ($pgReplicaConn + ' user=' + $cp.User) 'SELECT 1' $wrongPg
$r2 = MaClient $netAccess 'maria-replica' $cm.User 'SELECT 1' $wrongMa
Write-Result (($r1.All -match 'password authentication failed') -and ($r2.All -match 'Access denied')) 'failed logins with a fresh random wrong password (control: both refused)' ($r1.All + "`n" + $r2.All)
$fw = Find-InStore @(('"user":"' + $cp.User + '"'), '"event":"login_failed"') 'audit.jsonl' 15
$fw2 = Find-InStore @(('"user":"' + $cm.User + '"'), '"event":"login_failed"') 'audit.jsonl' 15
Write-Result (($fw.Objects.Count -ge 1) -and ($fw2.Objects.Count -ge 1)) 'both failed logins are in the store (control that they were logged)' ((Show-Record ($fw.Objects | Select-Object -First 1)) + "`n" + (Show-Record ($fw2.Objects | Select-Object -First 1)))

$sv = Search-Values @{ pg = $cp.Password; maria = $cm.Password; pgA = $caseCreds['A'].Password; pgB = $caseCreds['B'].Password; pgC = $caseCreds['C'].Password; wrongpg = $wrongPg; wrongmaria = $wrongMa }
$res = $sv.Res
$hits = Get-HitLocations $res['pg']
Write-Result (($sv.R.Code -eq 0) -and ($res['pg'].Count -ge 13) -and ($hits.Count -eq 0)) 'PG (scram-sha-256, the phase 4 setting): alice''s temp password is in no log, no data directory, no docker log and not in the store' (Format-Hits $res['pg'])
$hits = Get-HitLocations $res['pgA']
Write-Result (($res['pgA'].Count -ge 13) -and ($hits.Count -eq 0)) 'PG case A (password sent in clear text, pgAudit only): no clear text anywhere: pgAudit 17.1 redacts the PASSWORD clause itself' (Format-Hits $res['pgA'])
$hits = Get-HitLocations $res['pgB']
Write-Result ((@($hits) -contains 'pg-primary-log') -and (@($hits) -contains 'log-store')) 'PG case B: LEAK REPRODUCED without the mitigation: with core statement logging (log_statement=ddl for bao_admin) and password_authentication=password the clear-text temp password is in the pg-primary log and was shipped to the store' (Format-Hits $res['pgB'])
$hits = Get-HitLocations $res['pgC']
$f = Find-InStore @('"source":"pg-primary"', '"user":"bao_admin"', $caseCreds['C'].User, 'statement: CREATE ROLE') 'audit.jsonl' 10
$rec = $f.Objects | Select-Object -First 1
Write-Result (($res['pgC'].Count -ge 13) -and ($hits.Count -eq 0) -and ($null -ne $rec) -and ([string]$rec.message -match "PASSWORD 'SCRAM-SHA-256\$")) 'PG case C: MITIGATION: with password_authentication=scram-sha-256 the same core statement log holds only the SCRAM verifier; the password is nowhere' ((Format-Hits $res['pgC']) + "`nlogged: " + (Redact ([string]$rec.message)))
foreach ($k in @('wrongpg', 'wrongmaria')) {
    $hits = Get-HitLocations $res[$k]
    Write-Result (($res[$k].Count -ge 13) -and ($hits.Count -eq 0)) ('failed login ({0}): the attempted password is in no log and not in the store' -f $k) (Format-Hits $res[$k])
}

Write-Host ''
Write-Host '== Clear-text passwords: MariaDB (server_audit, binary logs, relay log) =='
Note 'Phase 4: temp users are created on maria-replica by bao_replica_admin with sql_log_bin = 0; primary passwords are set with SET PASSWORD FOR. The former KNOWN LEAK checks are now checks that the leak is ABSENT.'
$f = Find-InStore @('"source":"maria-replica"', '"user":"bao_replica_admin"', 'CREATE USER', $cm.User) 'audit.jsonl' 15
$rec = $f.Objects | Select-Object -First 1
Write-Result (($null -ne $rec) -and ($rec.statement -match 'IDENTIFIED BY \*\*\*\*\*')) 'Maria replica: server_audit logs bao_replica_admin''s CREATE USER of the temp user with the password masked (IDENTIFIED BY *****)' (Show-Record $rec)
$hm = $res['maria']
$textLocs = @('maria-primary-audit', 'maria-replica-audit', 'log-store', 'docker-logs', 'pg-primary-log', 'pg-replica-log', 'bao-audit', 'pg-sweeper-log', 'maria-sweeper-log')
$bad = @($textLocs | Where-Object { $hm[$_] })
Write-Result (($hm.Count -ge 13) -and ($bad.Count -eq 0)) 'Maria: alice''s temp password is in no audit log, no text log and not in the store' (Format-Hits $hm)
$allHits = Get-HitLocations $hm
Write-Result (($hm.Count -ge 13) -and ($allHits.Count -eq 0)) 'Maria: LEAK ABSENT: alice''s temp password is nowhere at all, including the primary''s binary log, the replica''s relay log, the replica''s own binary log and every other file of both data directories' ('maria-data: ' + $(if ($hm['maria-data']) { $hm['maria-data'] } else { '-' }) + "`nmaria-replica-data: " + $(if ($hm['maria-replica-data']) { $hm['maria-replica-data'] } else { '-' }))
# The temp user's NAME is not secret: its absence shows that no statement about it was binlogged
# or replicated at all (control: the name IS in the replica's server_audit log).
$nameScript = @'
for f in /m/mariadb-bin.[0-9]*; do n=$(grep -c -aF "$U" "$f"); [ "$n" != 0 ] && echo "HIT maria-data/${f##*/} $n"; done
for f in /r/maria-replica-bin.[0-9]* /r/maria-replica-relay.[0-9]*; do [ -e "$f" ] || continue; n=$(grep -c -aF "$U" "$f"); [ "$n" != 0 ] && echo "HIT maria-replica-data/${f##*/} $n"; done
echo "binlog files: primary $(ls /m/mariadb-bin.[0-9]* | wc -l), replica $(ls /r/maria-replica-bin.[0-9]* 2>/dev/null | wc -l), relay $(ls /r/maria-replica-relay.[0-9]* 2>/dev/null | wc -l)"
echo "control, lines naming the user in the replica's server_audit log: $(cat /a/server_audit.log* | grep -c -aF "$U")"
'@
$nr = Invoke-Reader $nameScript @{ U = $cm.User } @(($P2Project + '_maria-data:/m:ro'), ($P2Project + '_maria-replica-data:/r:ro'), ($P2Project + '_maria-replica-audit:/a:ro'))
Write-Result (($nr.Code -eq 0) -and ($nr.Out -notmatch 'HIT') -and ($nr.Out -match 'server_audit log: [1-9]')) 'Maria: the temp user''s name is in no binary log or relay log of either server (never binlogged, never replicated); it is in the replica''s audit log' $nr.Out

# Pattern scan, independent of known passwords: decode every binary and relay log of both servers
# and count statements that carry a password literal in clear text (any account, including test
# probes created by other suites). Literals are masked before anything is printed.
$formScript = @'
for d in /m /r; do
  for f in $(ls $d | grep -E -- '-bin\.[0-9]+$|-relay\.[0-9]+$|relay-bin\.[0-9]+$'); do
    mariadb-binlog --base64-output=decode-rows -vv "$d/$f" 2>/dev/null
  done
done > /tmp/dec
echo "decoded lines: $(wc -l < /tmp/dec)"
echo "CLEAR $(grep -ciE "IDENTIFIED (BY|VIA [a-z_0-9]+ USING PASSWORD *\() *'|PASSWORD *\( *'" /tmp/dec)"
echo "control, hash-only SET PASSWORD FOR: $(grep -ciE "SET PASSWORD FOR .*= *'\*" /tmp/dec)"
grep -iE "IDENTIFIED (BY|VIA [a-z_0-9]+ USING PASSWORD *\() *'|PASSWORD *\( *'" /tmp/dec | sed -E "s/(IDENTIFIED BY|PASSWORD *\() *'[^']*'/\1 '?'/Ig" | sort | uniq -c | head -10
rm -f /tmp/dec
'@
$fr = Invoke-Reader $formScript @{} @(($P2Project + '_maria-data:/m:ro'), ($P2Project + '_maria-replica-data:/r:ro')) 'mariadb:11.8'
Write-Result (($fr.Code -eq 0) -and ($fr.Out -match 'CLEAR 0\b') -and ($fr.Out -match 'hash-only SET PASSWORD FOR: [1-9]')) 'Maria: pattern scan of every decoded binary and relay log of both servers: no statement carries a password literal in clear text (any account, any form); hash-only SET PASSWORD FOR statements are present (control)' $fr.Out

# Long-lived secrets from secrets\ (set by the init and setup scripts, several of them in
# CREATE/ALTER ROLE|USER statements run as postgres / root), and lab_rogue's password (set by
# postgres and root in this run).
$lived = @{ rogue = $rogPw }
foreach ($fi in (Get-ChildItem (Join-Path $P2Root 'secrets') -File | Where-Object { $_.Name -match '^(pg_|maria_|keycloak_|laravel_app_key$|openbao_phase4_)' })) {
    $v = Read-P2Secret $fi.Name
    if ($v.Length -ge 12) { $lived[('secret_' + $fi.Name)] = $v }
}
$sl = Search-Values $lived
$textBad = @(); $dataHits = @(); $dataBad = @()
foreach ($k in ($sl.Res.Keys | Sort-Object)) {
    $h = $sl.Res[$k]
    foreach ($loc in $textLocs) { if ($h[$loc]) { $textBad += ('{0} in {1}' -f $k, $loc) } }
    foreach ($loc in @('pg-data', 'pg-replica-data', 'maria-data', 'maria-replica-data')) {
        if ($h[$loc]) {
            $dataHits += ('{0}: {1}: {2}' -f $k, $loc, $h[$loc])
            # The only accepted hit: the replicator password in the replica's master.info
            # (CHANGE MASTER stores it there; a configuration file, not a log; known since phase 3).
            $known = ($k -eq 'secret_maria_replicator_password') -and ($loc -eq 'maria-replica-data') -and ($h[$loc] -match '^master\.info$')
            if (-not $known) { $dataBad += ('{0}: {1}: {2}' -f $k, $loc, $h[$loc]) }
        }
    }
}
Write-Result (($sl.Res.Count -ge 10) -and ($textBad.Count -eq 0)) ('no long-lived secret from secrets\ ({0} values) and not lab_rogue''s password is in any audit log, text log, docker log or the store (pgAudit redacts the postgres-run CREATE/ALTER ROLE ... PASSWORD of the setup scripts, server_audit masks root''s IDENTIFIED BY and PASSWORD(...))' -f ($lived.Count - 1)) ($(if ($textBad.Count) { 'FOUND: ' + ($textBad -join '; ') } else { 'searched: ' + (($lived.Keys | Sort-Object) -join ', ') }))
Note 'ALTERED: the former check accepted MariaDB passwords in mariadb-bin.* and maria-replica-relay.* (KNOWN LEAK); now only master.info (replicator) is accepted.'
Write-Result ($dataBad.Count -eq 0) 'Maria: LEAK ABSENT: no long-lived MariaDB password (app1_runtime, app1_migrator, replicator, session_sweeper, initial bao_admin, lab_rogue) is in any binary log or relay log; the only clear text in a data directory is the replicator password in the replica''s master.info (configuration, known since phase 3)' ((@($dataHits | ForEach-Object { 'hit ' + $_ }) + @($dataBad | ForEach-Object { 'UNEXPECTED ' + $_ })) -join "`n")

# =============================================================================================
Write-Host ''
Write-Host '== Root credential rotation =='
# PostgreSQL: rotate-root (ALTER ROLE bao_admin ... PASSWORD, scram-sha-256).
$w = Start-StoreWatch @('"source":"pg-primary"', '"user":"bao_admin"', '"audit_command":"ALTER ROLE"', 'bao_admin', 'PASSWORD') 'audit.jsonl'
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
$r = BaoRoot @('write', '-force', 'database/rotate-root/app1-pg')
$fw = Wait-StoreWatch $w
$recs = @($fw.Objects | Where-Object { [string]$_.timestamp -ge $t0 })
$rec = $recs | Select-Object -Last 1
$chk = Invoke-Reader @'
echo "ALTER ROLE bao_admin records: $(grep -h 'ALTER ROLE' /l/*.json | grep -F 'bao_admin' | grep -c PASSWORD), of them with a quoted password literal: $(grep -h 'ALTER ROLE' /l/*.json | grep -F 'bao_admin' | grep -c "PASSWORD '")"
'@ @{} @(($P2Project + '_pg-primary-log:/l:ro'))
$c2 = Get-Creds $alice.Token 'app1-pg-ro'
Write-Result (($r.Code -eq 0) -and ($null -ne $rec) -and ($rec.statement -match 'PASSWORD <REDACTED>') -and ($chk.Out -match 'records: [1-9]\d*, of them with a quoted password literal: 0') -and ($null -ne $c2.User)) 'PG: rotate-root is audited (ALTER ROLE by bao_admin, password <REDACTED>); no bao_admin statement in the log has a password literal; OpenBao still issues credentials' ((Show-Record $rec) + "`n" + $chk.Out.Trim() + "`nafter rotation: " + $c2.User)

# MariaDB, connection app1-maria (bao_admin on the PRIMARY): phase 4 uses SET PASSWORD =
# PASSWORD(...) from the very first rotate-root (phase4-setup.ps1 passes it to phase2-setup.ps1).
# The reproduction with the phase 2/3 statement (ALTER USER ... IDENTIFIED BY), which left a
# clear-text (rotated-away) bao_admin password in the binlog, now runs only with
# -LeakAndPurgeTest, which purges it again.
$p23Rotation = "ALTER USER '{{username}}'@'10.81.4.10' IDENTIFIED BY '{{password}}';"
$p4Rotation = "SET PASSWORD = PASSWORD('{{password}}')"
$binlogProbe = @'
lit="$(for f in $(ls /m/mariadb-bin.[0-9]* | sort); do grep -a -o "ALTER USER 'bao_admin'@'10.81.4.10' IDENTIFIED BY '[^']*'" "$f"; done | tail -n 1 | sed -E "s/.*IDENTIFIED BY '([^']*)'$/\1/")"
last="$(for f in $(ls /m/mariadb-bin.[0-9]* | sort); do grep -a -o -E "ALTER USER 'bao_admin'@'10\.81\.4\.10' IDENTIFIED BY '[^']*'|SET PASSWORD FOR 'bao_admin'@'10\.81\.4\.10'='[^']*'" "$f"; done | tail -n 1 | sed -E "s/IDENTIFIED BY '[^']*'/IDENTIFIED BY '<clear-text literal>'/; s/='\*[0-9A-F]{40}'/='*<41-char native hash>'/")"
echo "latest bao_admin password statement in the binlog: $last"
echo "bao_admin password statements with a clear-text literal in the binlog: $(cat /m/mariadb-bin.[0-9]* | grep -a -c "ALTER USER 'bao_admin'@'10.81.4.10' IDENTIFIED BY '")"
if [ -n "$lit" ]; then
  echo "latest ALTER USER literal: found, ${#lit} characters"
  if MYSQL_PWD="$lit" mariadb -h maria-primary -u bao_admin --ssl-ca=/ca/ca.crt --ssl-verify-server-cert --connect-timeout=5 -N -B -e "SELECT 'LOGIN_OK'" 2>/dev/null | grep -q LOGIN_OK; then
    echo "login as bao_admin with that literal: SUCCEEDED"
  else
    echo "login as bao_admin with that literal: refused"
  fi
else
  echo "latest ALTER USER literal: none"
fi
'@
$probeVols = @(($P2Project + '_maria-data:/m:ro'), ($volCa + ':/ca:ro'))
$w = Start-StoreWatch @('"source":"maria-primary"', '"user":"bao_admin"', 'SET PASSWORD') 'audit.jsonl'
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
$cfgM = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'database/config/app1-maria')).Out
$r = BaoRoot @('write', '-force', 'database/rotate-root/app1-maria')
$p = Invoke-Reader $binlogProbe @{} $probeVols 'mariadb:11.8' ('container:' + (Id 'openbao'))
$fw = Wait-StoreWatch $w
$recs = @($fw.Objects | Where-Object { [string]$_.timestamp -ge $t0 })
$rec = $recs | Select-Object -Last 1
Note 'ALTERED: the phase 2/3 rotation is no longer reproduced here (it leaves clear text behind); see -LeakAndPurgeTest.'
Write-Result (($r.Code -eq 0) -and (@($cfgM.data.root_credentials_rotate_statements) -contains $p4Rotation) -and ($p.Out -match "SET PASSWORD FOR 'bao_admin'@'10\.81\.4\.10'='\*<41-char native hash>'") -and ($p.Out -match 'clear-text literal in the binlog: 0') -and ($p.Out -match 'latest ALTER USER literal: none')) 'Maria (app1-maria, bao_admin on the primary): rotate-root uses SET PASSWORD = PASSWORD(...); the binlog holds only hashes and NO bao_admin password literal at all (not even from the first rotation)' ('root_rotation_statements: ' + (@($cfgM.data.root_credentials_rotate_statements) -join ' | ') + "`n" + $p.Out)
Write-Result (($null -ne $rec) -and ($rec.statement -notmatch "PASSWORD\('[^*]")) 'Maria: server_audit records the rotation by bao_admin with the password masked' (Show-Record $rec)

# MariaDB, connection app1-maria-replica (bao_replica_admin, LOCAL to maria-replica). Re-run of
# what phase4-setup.ps1 does when the account is new (for example after a re-seed), here with a
# KNOWN one-time initial password so that it can be searched for: set it on the replica, hand
# it to OpenBao, check where it works, rotate, search.
Write-Host ''
Write-Host '== bao_replica_admin: initial password, where it can log in, rotation =='
$bra = New-LabPassword
$r0 = Invoke-Docker @('exec', '-e', 'BAO_REPLICA_PW', (Id 'maria-replica'), 'bash', '/opt/phase4/replica-bao-account.sh', 'set-password') @{ BAO_REPLICA_PW = $bra }
$r1 = Invoke-Bao @('write', 'database/config/app1-maria-replica', 'username=bao_replica_admin', 'password=-', 'verify_connection=true') $baoRootToken $bra
Write-Result (($r0.Code -eq 0) -and ($r1.Code -eq 0)) 'bao_replica_admin re-initialised with a one-time password (replica-bao-account.sh set-password, then OpenBao with verify_connection)' ($r0.All + "`n" + $r1.All)
# Logins from OpenBao's own network namespace (10.81.4.10 on bao-admin, 10.81.9.10 on
# bao-replica, an address on access). Only the replica over bao-replica may work. TLS is used,
# but by IP without name verification: the mariadb client cannot check a certificate name other
# than the host it connects to (OpenBao itself verifies the name maria-replica).
$loginScript = @'
try() { if MYSQL_PWD="$BP" mariadb -h "$1" -u bao_replica_admin $2 --connect-timeout=5 -N -B -e "SELECT CONCAT('LOGIN_OK as ', CURRENT_USER())" > /tmp/o 2>&1; then echo "$3: $(cat /tmp/o)"; else echo "$3: refused: $(tr '\n' ' ' < /tmp/o)"; fi; }
try 10.81.9.12 "--ssl --disable-ssl-verify-server-cert" "replica over bao-replica (10.81.9.12)"
try 10.81.5.12 "--ssl --disable-ssl-verify-server-cert" "replica over access (10.81.5.12)"
try maria-primary "--ssl-ca=/ca/ca.crt --ssl-verify-server-cert" "primary over bao-admin (maria-primary)"
'@
$lg = Invoke-Reader $loginScript @{ BP = $bra } @(($volCa + ':/ca:ro')) 'mariadb:11.8' ('container:' + (Id 'openbao'))
Write-Result ($lg.Out -match 'replica over bao-replica \(10\.81\.9\.12\): LOGIN_OK as bao_replica_admin@10\.81\.9\.10') 'control: with the initial password bao_replica_admin logs in to maria-replica from OpenBao over bao-replica (10.81.9.10)' $lg.Out
Assert-Refused 'bao_replica_admin cannot log in to the replica over the access network (host mask is OpenBao''s bao-replica address)' @{ Code = 1; All = (($lg.Out -split "`r?`n") | Where-Object { $_ -match 'over access' }) -join ' ' } "Access denied for user 'bao_replica_admin'@'10\.81\.5\.\d+'"
Assert-Refused 'bao_replica_admin cannot log in to the PRIMARY (the account does not exist there; OpenBao reaches the primary from 10.81.4.10)' @{ Code = 1; All = (($lg.Out -split "`r?`n") | Where-Object { $_ -match 'primary over' }) -join ' ' } "Access denied for user 'bao_replica_admin'@'10\.81\.4\.10'"
$gp = MaSu 'maria-primary' "SHOW GRANTS FOR 'bao_replica_admin'@'10.81.9.10'"
$np = MaVal 'maria-primary' "SELECT COUNT(*) FROM mysql.global_priv WHERE User = 'bao_replica_admin'"
Write-Result (($gp.Code -ne 0) -and ($gp.All -match 'There is no such grant defined') -and ($np -eq '0')) 'bao_replica_admin has no privileges on the primary: no account of that name exists there' ('SHOW GRANTS on maria-primary: ' + $gp.All + "`nmysql.global_priv rows: " + $np)
$w = Start-StoreWatch @('"source":"maria-replica"', '"user":"bao_replica_admin"', 'SET PASSWORD') 'audit.jsonl'
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
$r = BaoRoot @('write', '-force', 'database/rotate-root/app1-maria-replica')
$fw = Wait-StoreWatch $w
$rec = @($fw.Objects | Where-Object { [string]$_.timestamp -ge $t0 }) | Select-Object -Last 1
$lg2 = Invoke-Reader $loginScript @{ BP = $bra } @(($volCa + ':/ca:ro')) 'mariadb:11.8' ('container:' + (Id 'openbao'))
$c5 = Get-Creds $alice.Token 'app1-maria-ro'
Write-Result (($r.Code -eq 0) -and ($lg2.Out -match 'replica over bao-replica \(10\.81\.9\.12\): refused') -and ($null -ne $c5.User) -and ($null -ne $rec) -and ($rec.statement -match 'SET PASSWORD = PASSWORD\(\*\*\*\*\*\)')) 'rotate-root app1-maria-replica: audited on the replica with the password masked; the initial password no longer logs in; OpenBao still issues credentials' ((Show-Record $rec) + "`n" + (($lg2.Out -split "`r?`n") | Where-Object { $_ -match 'bao-replica' }) + "`nafter rotation: " + $c5.User)
$s5 = Search-Values @{ bra = $bra; m5 = $c5.Password }
$hb = Get-HitLocations $s5.Res['bra']
$h5 = Get-HitLocations $s5.Res['m5']
Write-Result (($s5.Res['bra'].Count -ge 13) -and ($hb.Count -eq 0)) 'bao_replica_admin''s initial password is nowhere in clear text: no log, no binlog, no relay log, no data directory, not in the store (SET PASSWORD FOR ... with sql_log_bin = 0; server_audit masks it)' (Format-Hits $s5.Res['bra'])
Write-Result (($s5.Res['m5'].Count -ge 13) -and ($h5.Count -eq 0)) 'Maria: after the rotations a new temp password is nowhere in clear text either (formerly: still in the binlog)' (Format-Hits $s5.Res['m5'])
$rb = Invoke-Reader 'echo "primary binlog: $(cat /m/mariadb-bin.[0-9]* | grep -a -c bao_replica_admin); replica binlog: $(cat /r/maria-replica-bin.[0-9]* | grep -a -c bao_replica_admin); replica relay log: $(cat /r/maria-replica-relay.[0-9]* 2>/dev/null | grep -a -c bao_replica_admin)"' @{} @(($P2Project + '_maria-data:/m:ro'), ($P2Project + '_maria-replica-data:/r:ro'))
Write-Result ($rb.Out -match 'primary binlog: 0; replica binlog: 0; replica relay log: 0') 'no statement about bao_replica_admin (creation, grants, passwords, rotations) is in any binary or relay log' $rb.Out

# =============================================================================================
Write-Host ''
Write-Host '== bao_replica_admin: each privilege is needed (removed one at a time, LAB-ONLY probe accounts on the replica) =='
# lab_probe@localhost gets a variant of the grant set; it then runs the role's statements over
# the socket (sql_log_bin = 0 set at session level, as OpenBao's DSN parameter does). A
# throwaway v-lab-probe-* user has an open session from the replica's own access address while
# the revocation runs. Everything is local to the replica (sql_log_bin = 0) and dropped again.
$privScript = @'
set -u
rootpw="$MYSQL_PWD"; unset MYSQL_PWD
R() { MYSQL_PWD="$rootpw" mariadb --protocol=socket -uroot -N -B "$@"; }
rnd() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }
one() { tr '\n' ' ' | sed -E "s/BY '[^']*'/BY '<r>'/g; s/PASSWORD\('[^']*'\)/PASSWORD(<r>)/g; s/-{5,}//g; s/ +/ /g"; }
MASK='10.81.5.0/255.255.255.0'
variant() {
  name="$1"; glob="$2"; masked="$3"; ppw="$(rnd)"
  R -e "SET SESSION sql_log_bin=0; DROP USER IF EXISTS 'lab_probe'@'localhost'; CREATE USER 'lab_probe'@'localhost' ACCOUNT LOCK; SET PASSWORD FOR 'lab_probe'@'localhost' = PASSWORD('$ppw'); ALTER USER 'lab_probe'@'localhost' ACCOUNT UNLOCK;"
  [ -n "$glob" ] && R -e "SET SESSION sql_log_bin=0; GRANT $glob ON *.* TO 'lab_probe'@'localhost';"
  [ -n "$masked" ] && R -e "SET SESSION sql_log_bin=0; GRANT SELECT ON app1_masked.* TO 'lab_probe'@'localhost' $masked;"
  P() { MYSQL_PWD="$ppw" mariadb --protocol=socket -ulab_probe -N -B "$@" 2>&1; }
  u="v-lab-probe-$(date +%s)-$RANDOM"; tpw="$(rnd)"
  c="$(P -e "SET SESSION sql_log_bin = 0; CREATE USER '$u'@'$MASK' IDENTIFIED BY '$tpw' REQUIRE SSL WITH MAX_USER_CONNECTIONS 2 MAX_STATEMENT_TIME 60 PASSWORD EXPIRE INTERVAL 1 DAY; GRANT SELECT ON app1_masked.* TO '$u'@'$MASK';" | one)"
  ex="$(R -e "SELECT COUNT(*) FROM mysql.user WHERE User='$u'")"
  R -e "SET SESSION sql_log_bin=0; CREATE USER IF NOT EXISTS '$u'@'$MASK' IDENTIFIED BY '$tpw' REQUIRE SSL; GRANT SELECT ON app1_masked.* TO '$u'@'$MASK';"
  ( MYSQL_PWD="$tpw" mariadb -h 10.81.5.12 -u "$u" --ssl --disable-ssl-verify-server-cert -N -B app1_masked -e "SELECT SLEEP(15)" >/dev/null 2>&1 & )
  sleep 1.5
  sb="$(R -e "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER='$u'")"
  rv="$(P -e "SET SESSION sql_log_bin = 0; KILL USER '$u'; DROP USER IF EXISTS '$u'@'$MASK';" | one)"
  sleep 0.5
  sa="$(R -e "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER='$u'")"
  ua="$(R -e "SELECT COUNT(*) FROM mysql.user WHERE User='$u'")"
  ro="$(P -e "SET SESSION sql_log_bin = 0; SET PASSWORD = PASSWORD('$(rnd)');" | one)"
  echo "V|$name|create=${c:-OK}|created=$ex|sessions_before=$sb|revoke=${rv:-OK}|sessions_after=$sa|user_after=$ua|rotate=${ro:-OK}"
  R -e "SET SESSION sql_log_bin=0; KILL USER '$u'; DROP USER IF EXISTS '$u'@'$MASK'; DROP USER IF EXISTS 'lab_probe'@'localhost';"
}
ALL="CREATE USER, READ ONLY ADMIN, BINLOG ADMIN, CONNECTION ADMIN"
variant all "$ALL" "WITH GRANT OPTION"
variant no_create_user "READ ONLY ADMIN, BINLOG ADMIN, CONNECTION ADMIN" "WITH GRANT OPTION"
variant no_read_only_admin "CREATE USER, BINLOG ADMIN, CONNECTION ADMIN" "WITH GRANT OPTION"
variant no_binlog_admin "CREATE USER, READ ONLY ADMIN, CONNECTION ADMIN" "WITH GRANT OPTION"
variant super_not_binlog_admin "CREATE USER, READ ONLY ADMIN, SUPER, CONNECTION ADMIN" "WITH GRANT OPTION"
variant no_connection_admin "CREATE USER, READ ONLY ADMIN, BINLOG ADMIN" "WITH GRANT OPTION"
variant no_grant_option "$ALL" " "
echo "T|in_transaction|$(MYSQL_PWD="$rootpw" mariadb --protocol=socket -uroot -N -B -e "START TRANSACTION; SET SESSION sql_log_bin = 0;" 2>&1 | one)"
echo "T|set_statement_in_transaction|$(MYSQL_PWD="$rootpw" mariadb --protocol=socket -uroot -N -B -e "START TRANSACTION; SET STATEMENT sql_log_bin = 0 FOR DO 1;" 2>&1 | one)"
# What the full grant set also allows: PURGE BINARY LOGS on the replica (BINLOG ADMIN). Shown with
# a purge up to the OLDEST file, which deletes nothing.
ppw="$(rnd)"
R -e "SET SESSION sql_log_bin=0; DROP USER IF EXISTS 'lab_probe'@'localhost'; CREATE USER 'lab_probe'@'localhost' ACCOUNT LOCK; SET PASSWORD FOR 'lab_probe'@'localhost' = PASSWORD('$ppw'); ALTER USER 'lab_probe'@'localhost' ACCOUNT UNLOCK; GRANT $ALL ON *.* TO 'lab_probe'@'localhost';"
first="$(R -e 'SHOW BINARY LOGS' | head -n 1 | cut -f1)"
echo "T|purge_noop|files=$(R -e 'SHOW BINARY LOGS' | wc -l) $(MYSQL_PWD="$ppw" mariadb --protocol=socket -ulab_probe -N -B -e "PURGE BINARY LOGS TO '$first'" 2>&1 | one) files_after=$(R -e 'SHOW BINARY LOGS' | wc -l)"
R -e "SET SESSION sql_log_bin=0; DROP USER IF EXISTS 'lab_probe'@'localhost';"
echo "G|gtid_binlog_state=[$(R -e 'SELECT @@gtid_binlog_state')]"
'@
$pm = Invoke-Docker @('exec', '-e', 'MYSQL_PWD', (Id 'maria-replica'), 'bash', '-c', $privScript) @{ MYSQL_PWD = $mariaRootPw } 240
$pv = @{}
foreach ($l in ($pm.Out -split "`r?`n")) { if ($l -match '^[VT]\|([^|]+)\|(.*)$') { $pv[$Matches[1]] = $Matches[2] } }
function PV { param([string]$K) if ($pv.ContainsKey($K)) { return $pv[$K] } else { return '(no output)' } }
Write-Result ((PV 'all') -match '^create=OK\|created=1\|sessions_before=1\|revoke=OK\|sessions_after=0\|user_after=0\|rotate=OK$') 'control: with all five privileges creation, revocation (KILL USER ends the open session) and the own SET PASSWORD work' (PV 'all')
Write-Result ((PV 'no_create_user') -match 'create=.*the CREATE USER privilege.*\|created=0.*revoke=.*the CREATE USER privilege') 'without CREATE USER: CREATE USER and DROP USER are refused' (PV 'no_create_user')
Write-Result ((PV 'no_read_only_admin') -match 'create=.*running with the --read-only option.*\|created=0.*revoke=.*--read-only option.*rotate=.*--read-only option') 'without READ ONLY ADMIN: creation, DROP USER and the own SET PASSWORD (root rotation) are refused by read_only' (PV 'no_read_only_admin')
Write-Result ((PV 'no_binlog_admin') -match 'create=.*the BINLOG ADMIN privilege.*\|created=0.*revoke=.*BINLOG ADMIN.*sessions_after=1') 'without BINLOG ADMIN: SET SESSION sql_log_bin = 0 is refused, so nothing runs (and nothing is binlogged)' (PV 'no_binlog_admin')
Write-Result ((PV 'super_not_binlog_admin') -match 'create=.*the BINLOG ADMIN privilege') 'SUPER instead of BINLOG ADMIN is NOT enough in MariaDB 11.8 to set sql_log_bin' (PV 'super_not_binlog_admin')
Write-Result ((PV 'no_connection_admin') -match 'create=OK\|created=1\|sessions_before=1\|revoke=OK\|sessions_after=1\|user_after=0') 'without CONNECTION ADMIN: KILL USER returns NO error but kills nothing; the dropped user''s session stays open (silent failure)' (PV 'no_connection_admin')
Write-Result ((PV 'no_grant_option') -match "create=.*Access denied for user 'lab_probe'@'localhost' to database 'app1_masked'") 'without SELECT ON app1_masked.* WITH GRANT OPTION: the GRANT to the temp user is refused' (PV 'no_grant_option')
Write-Result (((PV 'in_transaction') -match 'Cannot modify @@session\.sql_log_bin inside a transaction') -and ((PV 'set_statement_in_transaction') -match 'Cannot modify @@session\.sql_log_bin inside a transaction')) 'inside a transaction (as OpenBao''s plugin runs every statement list) SET SESSION sql_log_bin and SET STATEMENT sql_log_bin=0 FOR ... both fail (Error 1694): hence ?sql_log_bin=0 on the connection' ('SET SESSION: ' + (PV 'in_transaction') + "`nSET STATEMENT: " + (PV 'set_statement_in_transaction'))
Write-Result ((PV 'purge_noop') -match '^files=(\d+)\s*files_after=\1$') 'KNOWN WEAKNESS: the same grants let the account run PURGE BINARY LOGS on the replica (BINLOG ADMIN; shown with a purge that deletes nothing): an OpenBao compromise can delete the replica''s binlogs' ('PURGE BINARY LOGS TO <oldest file> as lab_probe with the full grant set: ' + (PV 'purge_noop'))
Write-Result (($pm.Out -match 'G\|gtid_binlog_state=\[([^\]]*)\]') -and ($Matches[1] -notmatch '\b\d+-2-\d+')) 'the probes left no local GTID in the replica''s binlog' ([regex]::Match($pm.Out, 'G\|.*').Value)

# =============================================================================================
Write-Host ''
Write-Host '== The sql_log_bin guard fails closed =='
$gs0 = MaVal 'maria-replica' 'SELECT @@gtid_binlog_state'
$vc0 = MaVal 'maria-replica' "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'v-%'"
$cg = $null
try {
    [void](BaoRoot @('write', 'database/config/app1-maria-replica', 'connection_url={{username}}:{{password}}@tcp(maria-replica-admin:3306)/', 'verify_connection=true'))
    $cg = Get-Creds $alice.Token 'app1-maria-ro'
} finally {
    [void](BaoRoot @('write', 'database/config/app1-maria-replica', 'connection_url={{username}}:{{password}}@tcp(maria-replica-admin:3306)/?sql_log_bin=0', 'verify_connection=true'))
}
$gs1 = MaVal 'maria-replica' 'SELECT @@gtid_binlog_state'
$vc1 = MaVal 'maria-replica' "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'v-%'"
$cg2 = Get-Creds $alice.Token 'app1-maria-ro'
$url = (ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'database/config/app1-maria-replica')).Out).data.connection_details.connection_url
Write-Result (($null -eq $cg.User) -and ($cg.R.All -match 'Error 1242') -and ($gs0 -eq $gs1) -and ($vc0 -eq $vc1) -and ($null -ne $cg2.User) -and ($url -match '\?sql_log_bin=0$')) 'without ?sql_log_bin=0 on the connection, credential creation FAILS at the guard (Error 1242), creates no user and writes nothing to the replica''s binlog; restored, creation works again' ('without the parameter: ' + (Redact $cg.R.Err.Trim()) + ("`nv- users before/after: {0}/{1}; gtid_binlog_state before [{2}] after [{3}]; restored url {4}; next user {5}" -f $vc0, $vc1, $gs0, $gs1, $url, $cg2.User))
Note 'Measured during development without guard and parameter: the temp user''s CREATE USER (with its password) went into the replica''s binlog with GTID 0-2-n, and the next primary write stopped the replica''s SQL thread: "An attempt was made to binlog GTID 0-1-n which would create an out-of-order sequence number with existing GTID 0-2-m, and gtid strict mode is enabled".'

# =============================================================================================
Write-Host ''
Write-Host '== Credentials to login on the replica; temp users never on the primary; churn; replication health =='
$t0 = Get-Date
$cl = Get-Creds $alice.Token 'app1-maria-ro'
$tc = ((Get-Date) - $t0).TotalSeconds
$vis = -1
do { if ((MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $cl.User)) -eq '1') { $vis = ((Get-Date) - $t0).TotalSeconds; break }; Start-Sleep -Milliseconds 100 } while (((Get-Date) - $t0).TotalSeconds -lt 30)
$lo = -1; $tries = 0
do { $tries++; $x = MaClient $netAccess 'maria-replica' $cl.User 'SELECT 1' $cl.Password; if ($x.Code -eq 0) { $lo = ((Get-Date) - $t0).TotalSeconds; break } } while (((Get-Date) - $t0).TotalSeconds -lt 30)
Write-Result (($vis -ge 0) -and ($lo -ge 0) -and ($tries -eq 1)) ('credentials work on the replica at the first attempt: creds call {0:N2} s, user visible {1:N2} s, first login done {2:N2} s after the request (one throwaway client container, about 1-2 s of it)' -f $tc, $vis, $lo) ('login attempts: ' + $tries)
Add-Measure ('MariaDB credentials -> login on the replica: creds call {0:N2} s; user present when the call returns (first poll {1:N2} s); first login (incl. client container start) {2:N2} s; no replication lag any more' -f $tc, $vis, $lo)
[void](BaoRoot @('lease', 'revoke', $cl.Lease))

$samples = New-Object System.Collections.ArrayList
function Sample-Primary { [void]$samples.Add((MaVal 'maria-primary' "SELECT COUNT(*) FROM mysql.global_priv WHERE User LIKE 'v-%'")) }
$churn = @(); $emails = @()
$tCh = Get-Date
for ($i = 1; $i -le $ChurnUsers; $i++) {
    $c = Get-Creds $alice.Token 'app1-maria-ro'
    if ($c.User) { $churn += $c }
    Sample-Primary
    if (($i % 5) -eq 0) {
        $em = ('p4-churn-{0}-{1}@example.test' -f $stamp, $i)
        try { $resp = Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:8080/laravel/api/customers' -Method Post -Body (@{ email = $em; full_name = 'Phase4 Churn' } | ConvertTo-Json -Compress) -ContentType 'application/json' -TimeoutSec 30; if ($resp.StatusCode -eq 201) { $emails += $em } } catch { }
    }
}
$live = MaVal 'maria-replica' "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'v-jwt-%'"
foreach ($c in $churn) { [void](BaoRoot @('lease', 'revoke', $c.Lease)) }
$deadline = (Get-Date).AddSeconds(90)
do { Sample-Primary; $leftC = 0; foreach ($c in $churn) { if ((MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $c.User)) -ne '0') { $leftC++ } }; if ($leftC -eq 0) { break }; Start-Sleep -Seconds 2 } while ((Get-Date) -lt $deadline)
$chSec = [int]((Get-Date) - $tCh).TotalSeconds
$nonZero = @($samples | Where-Object { $_ -ne '0' })
Write-Result (($churn.Count -eq $ChurnUsers) -and ($leftC -eq 0) -and ($nonZero.Count -eq 0) -and ($samples.Count -ge $ChurnUsers)) ('churn: {0} temp users created and revoked on the replica in {1} s; mysql.global_priv on the PRIMARY sampled {2} times during their leases: never a v- account' -f $churn.Count, $chSec, $samples.Count) ('v-jwt users on the replica at the peak: {0}; left after revoke: {1}; primary samples: {2}' -f $live, $leftC, ($samples -join ','))
$pp = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
$wait = MaVal 'maria-replica' ("SELECT MASTER_GTID_WAIT('{0}', 30)" -f $pp)
$rs = @{}
foreach ($l in ((Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Id 'maria-replica'), 'mariadb', '--protocol=socket', '-uroot', '-e', 'SHOW REPLICA STATUS\G') @{ MYSQL_PWD = $mariaRootPw }).Out -split "`r?`n")) { if ($l -match '^\s*([A-Za-z_]+):\s?(.*)$') { $rs[$Matches[1]] = $Matches[2].Trim() } }
$gr = MaVal 'maria-replica' "SELECT CONCAT('gtid_slave_pos=', @@gtid_slave_pos, ' gtid_binlog_state=[', @@gtid_binlog_state, ']')"
$seen = 0; foreach ($em in $emails) { if ((MaVal 'maria-replica' ("SELECT COUNT(*) FROM app1.customers WHERE email = '{0}'" -f $em)) -eq '1') { $seen++ } }
$ok = ($wait -eq '0') -and ($rs['Slave_IO_Running'] -eq 'Yes') -and ($rs['Slave_SQL_Running'] -eq 'Yes') -and (-not $rs['Last_IO_Error']) -and (-not $rs['Last_SQL_Error']) -and ($rs['Seconds_Behind_Master'] -eq '0') -and
      ($gr -match ('gtid_slave_pos=' + [regex]::Escape($pp) + ' ')) -and ($gr -notmatch '\b\d+-2-\d+') -and ($emails.Count -ge [Math]::Floor($ChurnUsers / 5)) -and ($seen -eq $emails.Count)
Write-Result $ok 'after the churn replication is healthy under gtid_strict_mode: IO and SQL threads running, no error, caught up to the primary''s GTID, no local GTID on the replica, and the application''s writes made during the churn are on the replica' (('primary gtid_binlog_pos {0}; MASTER_GTID_WAIT {1}; IO {2}, SQL {3}, Seconds_Behind_Master {4}, Last_IO_Error [{5}], Last_SQL_Error [{6}]; replica {7}; laravel rows written {8}, on the replica {9}' -f $pp, $wait, $rs['Slave_IO_Running'], $rs['Slave_SQL_Running'], $rs['Seconds_Behind_Master'], $rs['Last_IO_Error'], $rs['Last_SQL_Error'], $gr, $emails.Count, $seen))
$bn = Invoke-Reader 'echo "temp-user names in binary/relay logs: primary $(cat /m/mariadb-bin.[0-9]* | grep -a -o -E "v-(jwt|oidc|lab)-[A-Za-z0-9._-]+" | sort -u | wc -l), replica binlog $(cat /r/maria-replica-bin.[0-9]* | grep -a -o -E "v-(jwt|oidc|lab)-[A-Za-z0-9._-]+" | sort -u | wc -l), relay $(cat /r/maria-replica-relay.[0-9]* 2>/dev/null | grep -a -o -E "v-(jwt|oidc|lab)-[A-Za-z0-9._-]+" | sort -u | wc -l)"' @{} @(($P2Project + '_maria-data:/m:ro'), ($P2Project + '_maria-replica-data:/r:ro'))
Write-Result ($bn.Out -match 'primary 0, replica binlog 0, relay 0') 'no temp-user name (v-jwt-*, v-oidc-*, v-lab-*) appears in any binary or relay log of either server' $bn.Out

# =============================================================================================
Write-Host ''
Write-Host '== Revocation on the replica ends the session at once, with and without the sweeper =='
function Start-MaSleep { param($C, [string]$Tag)
    $n = 'p4rev-' + $Tag + '-' + $stamp
    [void]$script:Containers.Add($n)
    [void](Invoke-Docker @('run', '-d', '--name', $n, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD', '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', 'maria-replica', '-u', $C.User, '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert', '--skip-reconnect', '-N', '-B', 'app1_masked', '-e', 'SELECT SLEEP(50); SELECT ''STILL ALIVE'';') @{ MYSQL_PWD = $C.Password })
    $id = '0'; $dl = (Get-Date).AddSeconds(30)
    do { $id = MaVal 'maria-replica' ("SELECT COALESCE(MAX(ID), 0) FROM information_schema.PROCESSLIST WHERE USER = '{0}'" -f $C.User); if ($id -ne '0') { break }; Start-Sleep -Milliseconds 300 } while ((Get-Date) -lt $dl)
    return @{ Name = $n; Id = $id }
}
function Measure-RevokeGone { param($C, $S)
    $t = Get-Date
    [void](BaoRoot @('lease', 'revoke', $C.Lease))
    $gone = -1; $dl = $t.AddSeconds(30)
    do { if ((MaVal 'maria-replica' ("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = {0}" -f $S.Id)) -eq '0') { $gone = [Math]::Round(((Get-Date) - $t).TotalSeconds, 1); break }; Start-Sleep -Milliseconds 200 } while ((Get-Date) -lt $dl)
    return $gone
}
$swSince = (Get-Date).ToUniversalTime().AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
$r = Compose @('stop', 'maria-sweeper')
$cA = Get-Creds $alice.Token 'app1-maria-ro'
$sA = Start-MaSleep $cA 'nosweeper'
$gA = Measure-RevokeGone $cA $sA
$r2 = Compose @('start', 'maria-sweeper')
[void](Invoke-Docker @('wait', $sA.Name) @{} 30)
$logA = (Invoke-Docker @('logs', $sA.Name)).All
Write-Result (($r.Code -eq 0) -and ($sA.Id -ne '0') -and ($gA -ge 0) -and ($gA -le 5) -and ($logA -match 'Lost connection|server has gone away|Connection was killed') -and ($logA -notmatch 'STILL ALIVE') -and ($r2.Code -eq 0)) ('with maria-sweeper STOPPED, "bao lease revoke" ended the open replica session in {0} s (KILL USER in the revocation statement; limit 5 s); sweeper started again' -f $gA) ('connection id {0}; client saw: {1}' -f $sA.Id, (($logA -split "`r?`n" | Where-Object { $_ }) -join ' '))
Add-Measure ('revoke -> MariaDB replica session gone, sweeper stopped: {0} s (formerly: never, until the sweeper ran)' -f $gA)
Start-Sleep -Seconds 3
$cB = Get-Creds $alice.Token 'app1-maria-ro'
$sB = Start-MaSleep $cB 'withsweeper'
$gB = Measure-RevokeGone $cB $sB
Start-Sleep -Seconds 2
$swLog = (Invoke-Docker @('logs', '--since', $swSince, (Id 'maria-sweeper'))).All
Write-Result (($sB.Id -ne '0') -and ($gB -ge 0) -and ($gB -le 5) -and ($swLog -notmatch ('id=' + $sA.Id + ' ')) -and ($swLog -notmatch ('id=' + $sB.Id + ' '))) ('with the sweeper running the session also ended in {0} s, by the revocation statement: the sweeper logged no kill for either session (it stays as a second line of defence)' -f $gB) ('maria-sweeper log since the stop: ' + (($swLog -split "`r?`n" | Where-Object { $_ } | Select-Object -Last 3) -join ' | '))
Add-Measure ('revoke -> MariaDB replica session gone, sweeper running: {0} s (phase 3 design: 1.6 to 9.9 s, by the sweeper)' -f $gB)

# =============================================================================================
Write-Host ''
Write-Host '== Revoke while maria-replica is stopped =='
# Measured behaviour: OpenBao cannot reach the replica. An asynchronous "bao lease revoke" (the
# default, also used by token revocation and TTL expiry) is queued and retried with growing
# delays (about 20 s, 40 s, 80 s, ...; after 6 failed attempts the lease becomes irrevocable).
# "bao lease revoke -sync" fails and is NOT retried; the lease keeps its TTL.
# ALTERED (revocation backstops): formerly, until a revocation succeeded, the user existed on the
# restarted replica and CAN LOG IN (measured 31 to 57 s; "KNOWN GAP" below). Now the replica's
# init_file drops every local v- user at each start before it accepts connections (also the
# -sync-revoked user, whose lease is still valid), and the queued revocation is completed by
# OpenBao's retry or by the lease reconciler. tests\revocation-checks.ps1 proves the order.
$cQ = Get-Creds $alice.Token 'app1-maria-ro'
$cS = Get-Creds $alice.Token 'app1-maria-ro'
$since = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$tl = New-Object System.Collections.ArrayList
$tS = Get-Date
function TL { param([string]$T) $line = ('{0,6:N1} s  {1}' -f ((Get-Date) - $tS).TotalSeconds, $T); [void]$tl.Add($line) }
$r = Compose @('stop', 'maria-replica'); TL ('maria-replica stopped (exit {0})' -f $r.Code)
$rq = BaoRoot @('lease', 'revoke', $cQ.Lease); TL ('bao lease revoke (async) {0}: exit {1}: {2}' -f $cQ.User, $rq.Code, ($rq.All -replace '\s+', ' '))
$rsy = BaoRoot @('lease', 'revoke', '-sync', $cS.Lease); TL ('bao lease revoke -sync {0}: exit {1}: {2}' -f $cS.User, $rsy.Code, (($rsy.All -replace '\s+', ' ') -replace '^(.{0,220}).*$', '$1'))
$lq = ConvertFrom-JsonOrNull (BaoRoot @('lease', 'lookup', '-format=json', $cQ.Lease)).Out
$ls = ConvertFrom-JsonOrNull (BaoRoot @('lease', 'lookup', '-format=json', $cS.Lease)).Out
TL ('lease lookup: async-revoked ttl {0} (expire_time set to the revoke time); -sync-revoked ttl {1}' -f $lq.data.ttl, $ls.data.ttl)
Start-Sleep -Seconds 10
$r = Compose @('start', 'maria-replica'); $tUp = Get-Date; TL ('maria-replica start (exit {0})' -f $r.Code)
$h = ''; $dl = (Get-Date).AddSeconds(120)
do { Start-Sleep -Seconds 1; $h = (Invoke-Docker @('inspect', '-f', '{{.State.Health.Status}}', (Id 'maria-replica'))).Out.Trim() } while (($h -ne 'healthy') -and ((Get-Date) -lt $dl))
$hS = [int]((Get-Date) - $tUp).TotalSeconds
$qRows = MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $cQ.User)
TL ('maria-replica {0}; async-revoked user rows: {1}' -f $h, $qRows)
$gapLogin = 'not tried (already gone)'
if ($qRows -ne '0') { $x = MaClient $netAccess 'maria-replica' $cQ.User 'SELECT 1' $cQ.Password; if ($x.Code -eq 0) { $gapLogin = 'LOGIN WORKED' } else { $gapLogin = 'refused: ' + ($x.All -replace '\s+', ' ') }; TL ('login with the async-revoked credentials: ' + $gapLogin) }
$xr = MaClient $netAccess 'maria-replica' $cQ.User 'SELECT 1' $cQ.Password
TL ('login with the async-revoked credentials right after healthy: exit {0}: {1}' -f $xr.Code, (($xr.All -replace '\s+', ' ') -replace '^(.{0,140}).*$', '$1'))
$purge = (Invoke-Docker @('exec', (Id 'maria-replica'), 'sh', '-c', 'ls -1t /var/log/mariadb-audit/backstop/startup-purge-*.log | head -n 1 | xargs cat')).Out.Trim()
TL ('startup purge: ' + $purge)
$qGone = $null; $dl = $tUp.AddSeconds($RevokeRetryWaitSeconds)
do { if ((BaoRoot @('lease', 'lookup', $cQ.Lease)).Code -ne 0) { $qGone = Get-Date; break }; Start-Sleep -Seconds 2 } while ((Get-Date) -lt $dl)
$qGoneS = -1; if ($qGone) { $qGoneS = [int]($qGone - $tUp).TotalSeconds; TL ('async-revoked lease gone ({0} s after the start; OpenBao''s retry or the lease reconciler)' -f $qGoneS) } else { TL 'async-revoked lease NOT gone within the bound' }
$lqa = BaoRoot @('lease', 'lookup', $cQ.Lease)
$sRows = MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $cS.User)
$lsa = ConvertFrom-JsonOrNull (BaoRoot @('lease', 'lookup', '-format=json', $cS.Lease)).Out
TL ('-sync-revoked user rows {0} (purged at start); its lease ttl {1} s (still valid: nobody retries a failed -sync revoke)' -f $sRows, $lsa.data.ttl)
$rs2 = BaoRoot @('lease', 'revoke', '-sync', $cS.Lease)
$sRows2 = MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $cS.User)
TL ('second bao lease revoke -sync: exit {0}; user rows {1}' -f $rs2.Code, $sRows2)
$bl = @(((Invoke-Docker @('logs', '--since', $since, (Id 'openbao'))).All -split "`r?`n") | Where-Object { $_ -match 'failed to revoke lease' -and $_ -match [regex]::Escape($cQ.Lease) } | ForEach-Object { ($_ -replace '^(\S+).*?(attempts=\d+ next_attempt=\S+).*$', '$1 $2') })
Note 'ALTERED: formerly the async-revoked user still existed on the restarted replica and could log in until OpenBao''s retry (KNOWN GAP, measured 31 to 57 s); now it must be gone when the replica is healthy (startup purge) and the login refused; the lease is then completed by OpenBao''s retry or by the lease reconciler.'
Write-Result (($rq.Code -eq 0) -and ($lq.data.ttl -le 0) -and ($bl.Count -ge 1) -and ($qRows -eq '0') -and ($xr.Code -ne 0) -and ($xr.All -match ("Access denied for user '" + [regex]::Escape($cQ.User) + "'|Host '10\.81\.5\.\d+' is not allowed to connect")) -and ($purge -match [regex]::Escape($cQ.User)) -and ($null -ne $qGone) -and ($lqa.Code -ne 0)) ('async revoke while the replica is down: queued, the lease stays (ttl <= 0) and OpenBao retries; the replica''s startup purge dropped the user before it accepted connections (login refused); the lease was gone {0} s after the start (bound {1} s)' -f $qGoneS, $RevokeRetryWaitSeconds) ((@($tl) + @($bl | ForEach-Object { 'openbao: failed to revoke ' + $_ })) -join "`n")
Note 'ALTERED: formerly the user of the failed -sync revoke stayed on the restarted replica (rows 1); now the startup purge drops it too (rows 0), while its lease still keeps its full TTL until revoked again.'
Write-Result (($rsy.Code -ne 0) -and ($ls.data.ttl -gt 3000) -and ($sRows -eq '0') -and ($rs2.Code -eq 0) -and ($sRows2 -eq '0')) 'bao lease revoke -sync while the replica is down FAILS and is not retried: the lease keeps its full TTL (only the startup purge removed the user); a second -sync revoke succeeds (DROP USER IF EXISTS)' ''
Write-Host ('       | FORMER GAP CLOSED: login with revoked credentials after the replica start: {0}' -f $(if ($xr.Code -eq 0) { 'LOGIN WORKED' } else { 'refused' })) -ForegroundColor Yellow
Add-Measure ('revoke while maria-replica down: replica healthy {0:N0} s after start; async-revoked user purged at start (rows {1} at healthy), login refused; lease gone {2} s after start; -sync revoke: failed, not retried, lease ttl {3} s' -f $hS, $qRows, $qGoneS, $lsa.data.ttl)
$dl = (Get-Date).AddSeconds(30)
do { Start-Sleep -Seconds 2; $last = ((Invoke-Docker @('logs', '--tail', '1', (Id 'maria-sweeper'))).All) } while (($last -match 'action=error') -and ((Get-Date) -lt $dl))

# =============================================================================================
Write-Host ''
Write-Host '== A re-seeded replica loses temp users; revoking a missing user succeeds =='
$cMiss = Get-Creds $alice.Token 'app1-maria-ro'
[void](MaSu 'maria-replica' ("SET SESSION sql_log_bin = 0; DROP USER '{0}'@'{1}'" -f $cMiss.User, $accessMask))
$rm = BaoRoot @('lease', 'revoke', '-sync', $cMiss.Lease)
$lm = BaoRoot @('lease', 'lookup', $cMiss.Lease)
Write-Result (($null -ne $cMiss.User) -and ($rm.Code -eq 0) -and ($lm.Code -ne 0)) 'user removed on the replica behind OpenBao''s back (as a re-seed does); bao lease revoke -sync still succeeds (KILL USER matches nothing, DROP USER IF EXISTS) and the lease is gone' ('revoke: exit {0}: {1}; lookup afterwards: {2}' -f $rm.Code, ($rm.All -replace '\s+', ' '), ($lm.All -replace '\s+', ' '))

# =============================================================================================
Write-Host ''
Write-Host '== The replica''s seed load is not in its audit log or the store (no password hashes) =='
$seedScript = @'
a="$(ls /a/server_audit.log* | sort -r)"
echo "replica audit lines with INSERT INTO global_priv: $(cat $a | grep -a -i -c -E 'INSERT INTO .?global_priv')"
echo "replica audit lines with a native password hash (*<40 hex>): $(cat $a | grep -a -c -E '\*[0-9A-F]{40}')"
echo "store records from maria-replica with INSERT INTO global_priv: $(grep -F '"source":"maria-replica"' /store/audit.jsonl | grep -i -c -E 'INSERT INTO .?global_priv')"
echo "store records from maria-replica with a native hash: $(grep -F '"source":"maria-replica"' /store/audit.jsonl | grep -c -E '\*[0-9A-F]{40}')"
echo "store records (all sources) with a native hash: $(grep -c -E '\*[0-9A-F]{40}' /store/audit.jsonl)"
echo "first statements in the replica audit log (the seed, run as root in the init server):"
cat $a | grep -a ',QUERY,' | head -n 3 | cut -d, -f3,5,9 | cut -c1-120
echo "first server_audit_logging statement: $(cat $a | grep -a -m1 'server_audit_logging' | cut -d, -f3,4,9 | cut -c1-120)"
'@
$sd = Invoke-Reader $seedScript @{} @(($P2Project + '_maria-replica-audit:/a:ro'), ($volStore + ':/store:ro'))
Write-Result (($sd.Code -eq 0) -and ($sd.Out -match 'audit lines with INSERT INTO global_priv: 0') -and ($sd.Out -match 'audit lines with a native password hash \(\*<40 hex>\): 0') -and ($sd.Out -match 'maria-replica with INSERT INTO global_priv: 0') -and ($sd.Out -match 'maria-replica with a native hash: 0') -and ($sd.Out -match "server_audit_logging = OFF")) 'the seed load (INSERT INTO global_priv with every account''s hash) is in neither the replica''s audit log nor the store; the log shows the seed''s SET GLOBAL server_audit_logging = OFF/ON instead' $sd.Out
# =============================================================================================
Write-Host ''
Write-Host '== Log store isolation and least privilege =='
$all = @((Invoke-Docker @('compose', '-f', $P2ComposeFile, 'ps', '-a', '--format', '{{.Service}} {{.ID}}')).Out -split "`r?`n" | Where-Object { $_.Trim() })
$storeUsers = @(); $sockUsers = @(); $mountLines = @()
foreach ($line in $all) {
    $svc, $cid = $line.Trim() -split '\s+', 2
    $m = (Invoke-Docker @('inspect', '-f', '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}={{.Destination}}:{{if .RW}}rw{{else}}ro{{end}};{{end}}{{end}}', $cid)).Out.Trim()
    $binds = (Invoke-Docker @('inspect', '-f', '{{range .Mounts}}{{.Source}};{{end}}', $cid)).Out.Trim()
    if ($m -match ($P2Project + '_log-store=')) { $storeUsers += $svc }
    if ($binds -match 'docker\.sock') { $sockUsers += $svc }
    $mountLines += ('{0}: {1}' -f $svc, (($m -replace ($P2Project + '_'), '') -replace '[0-9a-f]{64}', '<anonymous>'))
}
$li = (Invoke-Docker @('inspect', '-f', '{{.State.Status}} {{.State.ExitCode}} network_mode={{.HostConfig.NetworkMode}}', (Id 'log-init'))).Out.Trim()
$okUsers = (@($storeUsers | Where-Object { $_ -notin @('fluent-bit', 'log-init') }).Count -eq 0) -and ($storeUsers -contains 'fluent-bit') -and ($li -eq 'exited 0 network_mode=none')
Write-Result ($okUsers -and ($sockUsers.Count -eq 0)) 'log-store is mounted only by fluent-bit (and the one-shot log-init, which only sets ownership and has exited): no database, OpenBao, app or developer-facing container; no container mounts the Docker socket' (('containers mounting log-store: ' + ($storeUsers -join ', ') + ' (log-init: ' + $li + ')') + "`n" + ($mountLines -join "`n"))
$fbm = (Invoke-Docker @('inspect', '-f', '{{range .Mounts}}{{.Name}}={{.Destination}}:{{if .RW}}rw{{else}}ro{{end}};{{end}}', (Id 'fluent-bit'))).Out.Trim() -replace ($P2Project + '_'), ''
$srcRo = ($fbm -match 'pg-primary-log=/src/pg-primary:ro') -and ($fbm -match 'pg-replica-log=/src/pg-replica:ro') -and ($fbm -match 'maria-primary-audit=/src/maria-primary:ro') -and
         ($fbm -match 'maria-replica-audit=/src/maria-replica:ro') -and ($fbm -match 'bao-audit=/src/openbao:ro') -and ($fbm -match 'pg-sweeper-log=/src/pg-sweeper:ro') -and ($fbm -match 'maria-sweeper-log=/src/maria-sweeper:ro') -and
         ($fbm -match 'log-store=/store:rw') -and (($fbm -split ';' | Where-Object { $_ -match ':rw$' }).Count -eq 2)
Write-Result $srcRo 'fluent-bit mounts every database/OpenBao/sweeper log volume READ-ONLY; only log-store and its own state are read-write' ($fbm -replace ';', "`n")
$fbi = (Invoke-Docker @('inspect', '-f', 'network_mode={{.HostConfig.NetworkMode}} networks={{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} ports={{json .HostConfig.PortBindings}}', (Id 'fluent-bit'))).Out.Trim()
Write-Result ($fbi -match '^network_mode=none networks=none user=4001:4000 read_only=true cap_drop=\[ALL\] ports=(\{\}|null)$') 'fluent-bit: no network (network_mode none), non-root 4001:4000, read-only root file system, all capabilities dropped, no published port' $fbi
$r = Invoke-Docker @('run', '--rm', '--network', $netAccess, '--entrypoint', 'getent', 'postgres:17', 'hosts', 'fluent-bit')
Write-Result ($r.Code -ne 0) 'from the access network the name fluent-bit does not resolve (it is on no network)' ('getent hosts fluent-bit: exit {0} {1}' -f $r.Code, $r.All)
$r = Invoke-Reader @'
stat -c '%n owner=%u group=%g mode=%a' /store /store/audit.jsonl /store/alerts.jsonl /src/*
for d in /src/*; do stat -c '%n owner=%u group=%g mode=%a' "$d"/* 2>/dev/null | head -n 2; done
'@ @{} @(($volStore + ':/store:ro'), ($P2Project + '_pg-primary-log:/src/pg-primary-log:ro'), ($P2Project + '_maria-primary-audit:/src/maria-primary-audit:ro'), ($P2Project + '_bao-audit:/src/bao-audit:ro'), ($P2Project + '_pg-sweeper-log:/src/pg-sweeper-log:ro'))
# No source file may be group-writable (middle digit 2, 3, 6 or 7) or readable by others.
$groupW = @($r.Out -split "`r?`n" | Where-Object { ($_ -match '^/src/.*/\S+ .*mode=(\d+)$') -and (($Matches[1].PadLeft(3, '0')[-2] -match '[2367]') -or ($Matches[1][-1] -ne '0')) })
$ok = ($r.Out -match '/store owner=4001 group=4000 mode=750') -and ($r.Out -match '/src/bao-audit owner=100 group=4000 mode=2750') -and ($r.Out -match '/src/bao-audit/audit\.log owner=100 group=4000 mode=640') -and
      ($r.Out -match '/src/pg-primary-log owner=999 group=4000 mode=2750') -and ($r.Out -match 'pg-primary-log/postgresql-[^ ]+\.json owner=999 group=4000 mode=640') -and ($groupW.Count -eq 0)
Write-Result $ok 'ownership: each source directory belongs to its writer with group 4000 (setgid), files group-readable and not group-writable; the store belongs to the shipper (4001)' $r.Out

# =============================================================================================
Write-Host ''
Write-Host '== Tamper resistance =='
foreach ($s in @('maria-primary', 'maria-replica')) {
    Assert-Refused ('{0}: UNINSTALL PLUGIN server_audit fails (FORCE_PLUS_PERMANENT)' -f $s) (MaSu $s 'UNINSTALL PLUGIN server_audit') 'force_plus_permanent|can not be uninstalled|cannot be uninstalled'
}
# ALTERED: $cm was dropped by the maria-replica restart above (startup purge drops every local v-
# user, also those of valid leases, by design), so this check uses a temp user issued now.
Note 'ALTERED: the earlier temp user was purged by the replica restart above (startup purge); a new MariaDB temp user is issued for this check.'
$cmT = Get-Creds $alice.Token 'app1-maria-ro'
Assert-Refused 'Maria replica: the temp user cannot SET GLOBAL server_audit_logging = OFF' (MaClient $netAccess 'maria-replica' $cmT.User 'SET GLOBAL server_audit_logging = OFF' $cmT.Password) 'Access denied.*(SUPER|SYSTEM VARIABLES ADMIN)'
# KNOWN LIMIT: root can switch the plugin's logging off at runtime.
$mk = 'p4off_' + $stamp
$w = Start-StoreWatch @('"source":"maria-replica"', '"user":"root"', 'server_audit_logging') 'audit.jsonl' 15
$r = MaSu 'maria-replica' ("SET GLOBAL server_audit_logging = OFF; SELECT '{0}'; SET GLOBAL server_audit_logging = ON; SELECT @@server_audit_logging" -f $mk)
$fw = Wait-StoreWatch $w 15
Start-Sleep -Seconds 3
$seen = Find-InStore @('"source":"maria-replica"', $mk) 'audit.jsonl' 3
Write-Result (($r.Code -eq 0) -and ($r.Out -match '1\s*$') -and ($seen.Objects.Count -eq 0)) 'Maria: KNOWN LIMIT: root can SET GLOBAL server_audit_logging = OFF; the statement run meanwhile is not audited (logging is back ON)' (('logged around it: ' + (($fw.Objects | ForEach-Object { Show-Record $_ }) -join "`n")) + "`nmarker statement in the store: " + $seen.Objects.Count)

Assert-Refused 'PG replica: the temp user cannot SET pgaudit.log = ''none'' in its session' (PgClient $netAccess ($pgReplicaConn + ' user=' + $cp.User) "SET pgaudit.log = 'none'" $cp.Password) 'permission denied to set parameter "pgaudit\.log"'
Assert-Refused 'PG replica: the temp user cannot SET pgaudit.log_catalog = off either' (PgClient $netAccess ($pgReplicaConn + ' user=' + $cp.User) 'SET pgaudit.log_catalog = off' $cp.Password) 'permission denied to set parameter "pgaudit\.log_catalog"'
$r = PgClient $netAccess ($pgReplicaConn + ' user=' + $cp.User) "SELECT 'set_privilege=' || has_parameter_privilege('pgaudit.log', 'SET') || ',' || has_parameter_privilege('pgaudit.log_level', 'SET') || ',' || has_parameter_privilege('pgaudit.role', 'SET')" $cp.Password
Assert-Works 'PG replica: has_parameter_privilege: no SET privilege on pgaudit.log, log_level, role for the temp user' $r 'set_privilege=false,false,false'
# KNOWN LIMIT: a superuser session can turn pgAudit off for itself (control: without the SET
# the same read is audited, from the postgres role setting).
$mkOn = 'p4suon_' + $stamp
$mk = 'p4suoff_' + $stamp
$w = Start-StoreWatch @('"source":"pg-replica"', '"user":"postgres"', $mkOn) 'audit.jsonl' 15
$r0 = PgSu 'pg-replica' ("SELECT count(*) AS {0} FROM public.customers" -f $mkOn)
$fw = Wait-StoreWatch $w 15
$r = PgSu 'pg-replica' ("SET pgaudit.log = 'none'; SELECT count(*) AS {0} FROM public.customers" -f $mk)
Start-Sleep -Seconds 3
$seen = Find-InStore @('"source":"pg-replica"', $mk) 'audit.jsonl' 3
Write-Result (($r0.Code -eq 0) -and ($fw.Objects.Count -ge 1) -and ($r.Code -eq 0) -and ($seen.Objects.Count -eq 0)) 'PG: KNOWN LIMIT: a superuser can SET pgaudit.log = ''none'' in its session; its base-table read is then not audited (control: audited without the SET; its login still raises superuser_login)' ('control record: ' + (Show-Record ($fw.Objects | Select-Object -First 1)) + "`nmarker statement after SET pgaudit.log = 'none' in the store: " + $seen.Objects.Count)
# ALTER SYSTEM cannot override settings given on the server command line.
$r = PgSu 'pg-primary' "ALTER SYSTEM SET pgaudit.log = 'none'"
$rl = PgSu 'pg-primary' 'SELECT pg_reload_conf()'
Start-Sleep -Seconds 2
$c4 = Get-Creds $alice.Token 'app1-pg-ro'
$f = Find-InStore @('"source":"pg-primary"', '"user":"bao_admin"', '"audit_command":"CREATE ROLE"', [string]$c4.User) 'audit.jsonl' 15
[void](PgSu 'pg-primary' 'ALTER SYSTEM RESET pgaudit.log')
[void](PgSu 'pg-primary' 'SELECT pg_reload_conf()')
Write-Result (($r.Code -eq 0) -and ($null -ne $c4.User) -and ($f.Objects.Count -ge 1)) 'PG: ALTER SYSTEM SET pgaudit.log = ''none'' + reload does not stop auditing (the command-line setting outranks postgresql.auto.conf); reset again' ('ALTER SYSTEM exit {0}; new user {1}; its CREATE ROLE audited: {2}' -f $r.Code, $c4.User, $f.Objects.Count)

# =============================================================================================
Write-Host ''
Write-Host '== Sweeper log is shipped; the MariaDB sweeper still ends orphaned sessions (defence in depth) =='
# PostgreSQL: unchanged (the revocation runs on the primary; the replica session is orphaned and
# the sweeper ends it). MariaDB: OpenBao's revocation now runs KILL USER on the replica itself,
# so a revoked lease leaves nothing for the sweeper. The sweeper still matters for sessions whose
# account disappears WITHOUT a kill: a re-seed of the replica, a revocation statement without
# KILL USER or without CONNECTION ADMIN (measured: KILL USER then silently kills nothing), a DBA's
# DROP USER. Reproduced with a LAB-ONLY v- account created and dropped locally by root.
Note 'ALTERED: the MariaDB half no longer revokes an OpenBao lease (KILL USER would end the session before the sweeper sees it); it drops a local LAB-ONLY v- account without KILL.'
$kp = Get-Creds $alice.Token 'app1-pg-ro'
[void](Wait-OnReplica $kp.User '')
$orphan = 'v-lab-orphan-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + '-' + (-join ((1..4) | ForEach-Object { 'abcdefghjk'[(Get-Random -Maximum 10)] }))
$orphanPw = New-LabPassword
$r = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', '-e', 'P4PW', (Id 'maria-replica'), 'bash', '-c',
    ('mariadb --protocol=socket -uroot -e "SET SESSION sql_log_bin = 0; CREATE USER ''{0}''@''{1}'' REQUIRE SSL ACCOUNT LOCK; SET PASSWORD FOR ''{0}''@''{1}'' = PASSWORD(''$P4PW''); ALTER USER ''{0}''@''{1}'' ACCOUNT UNLOCK; GRANT SELECT ON app1_masked.* TO ''{0}''@''{1}''" 2>&1 | sed -E "s/PASSWORD\(.[^)]*\)/PASSWORD(<redacted>)/"' -f $orphan, $accessMask)) @{ MYSQL_PWD = $mariaRootPw; P4PW = $orphanPw }
$n1 = 'p4sess-pg-' + $stamp; $n2 = 'p4sess-ma-' + $stamp
[void]$script:Containers.Add($n1); [void]$script:Containers.Add($n2)
[void](Invoke-Docker @('run', '-d', '--name', $n1, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD', '--entrypoint', 'psql', 'postgres:17', ($pgReplicaConn + ' user=' + $kp.User), '-X', '-At', '-c', 'SELECT pg_sleep(50)') @{ PGPASSWORD = $kp.Password })
[void](Invoke-Docker @('run', '-d', '--name', $n2, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD', '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', 'maria-replica', '-u', $orphan, '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert', '-N', '-B', 'app1_masked', '-e', 'SELECT SLEEP(50)') @{ MYSQL_PWD = $orphanPw })
Start-Sleep -Seconds 3
$oid = PgVal 'pg-replica' ("SELECT oid FROM pg_roles WHERE rolname = '{0}'" -f $kp.User)
$maOpen = MaVal 'maria-replica' ("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER = '{0}'" -f $orphan)
$wP = Start-StoreWatch @('"source":"pg-sweeper"', '"event":"terminated"', ('usesysid=' + $oid + ' ')) 'audit.jsonl' 45
$wM = Start-StoreWatch @('"source":"maria-sweeper"', '"event":"killed"', ('"user":"' + $orphan + '"')) 'audit.jsonl' 45
[void](BaoRoot @('lease', 'revoke', $kp.Lease))
[void](MaSu 'maria-replica' ("SET SESSION sql_log_bin = 0; DROP USER '{0}'@'{1}'" -f $orphan, $accessMask))
$fp = Wait-StoreWatch $wP 45
$fm = Wait-StoreWatch $wM 45
Write-Result (($r.Code -eq 0) -and ($maOpen -eq '1') -and ($fp.Objects.Count -ge 1) -and ($fm.Objects.Count -ge 1)) 'PG: after a revoke the orphaned replica session is ended by the pg sweeper; Maria: a session whose account was dropped WITHOUT a kill is ended by the maria sweeper; both kill records reach the store' (('maria lab account {0} created locally (exit {1}), open sessions before the drop: {2}' -f $orphan, $r.Code, $maOpen) + "`n" + (Show-Record ($fp.Objects | Select-Object -First 1)) + "`n" + (Show-Record ($fm.Objects | Select-Object -First 1)))

# =============================================================================================
Write-Host ''
Write-Host '== Store format and volume =='
$r = Invoke-Reader 'tail -n 3000 /store/audit.jsonl' @{} @(($volStore + ':/store:ro'))
$lines = @($r.Out -split "`r?`n" | Where-Object { $_.Trim() })
$bad = 0; $missing = @{}
foreach ($l in $lines) {
    $o = ConvertFrom-JsonOrNull $l
    if ($null -eq $o) { $bad++; continue }
    foreach ($k in @('timestamp', 'source', 'engine', 'event')) { if (-not ($o.PSObject.Properties.Name -contains $k) -or (-not $o.$k)) { $missing[$k] = 1 + [int]$missing[$k] } }
}
Write-Result (($lines.Count -gt 100) -and ($bad -eq 0) -and ($missing.Count -eq 0)) ('the last {0} store lines are all valid JSON objects with timestamp, source, engine and event' -f $lines.Count) ('invalid: {0}; missing keys: {1}' -f $bad, (($missing.Keys | ForEach-Object { '{0}={1}' -f $_, $missing[$_] }) -join ' '))

# Bytes per developer query (one session: connect, one SELECT, disconnect), source log and store.
# MariaDB connection ids start again after a server restart (this script restarts maria-replica),
# so the store records are matched by connection id AND user.
$volScript = @'
pg_src=$(grep -h "\"session_id\":\"$PGSESS\"" /pgr/*.json | wc -c)
pg_store=$(grep -F "\"session_id\":\"$PGSESS\"" /store/audit.jsonl | grep -F '"source":"pg-replica"' | wc -c)
pg_lines=$(grep -F "\"session_id\":\"$PGSESS\"" /store/audit.jsonl | grep -F '"source":"pg-replica"' | wc -l)
ma_src=$(grep -h ",$MAUSER,[^,]*,$MACONN," /mar/server_audit.log | wc -c)
ma_store=$(grep -F "\"connection_id\":\"$MACONN\"" /store/audit.jsonl | grep -F '"source":"maria-replica"' | grep -F "\"user\":\"$MAUSER\"" | wc -c)
ma_lines=$(grep -F "\"connection_id\":\"$MACONN\"" /store/audit.jsonl | grep -F '"source":"maria-replica"' | grep -F "\"user\":\"$MAUSER\"" | wc -l)
echo "pg session $PGSESS: source $pg_src bytes, store $pg_store bytes in $pg_lines records"
echo "maria connection $MACONN: source $ma_src bytes, store $ma_store bytes in $ma_lines records"
'@
$vq = Invoke-Reader $volScript @{ PGSESS = [string]$recPg.session_id; MAUSER = $cm.User; MACONN = [string]$recMa.connection_id } @(($volStore + ':/store:ro'), ($P2Project + '_pg-replica-log:/pgr:ro'), ($P2Project + '_maria-replica-audit:/mar:ro'))
Write-Result ($vq.Out -match 'pg session \S+: source [1-9]\d* bytes, store [1-9]\d* bytes' -and $vq.Out -match 'maria connection \d+: source [1-9]\d* bytes') 'volume of one developer session with one query, per engine (source log and store)' $vq.Out
Add-Measure ('per developer session with one query: ' + (($vq.Out.Trim() -split "`r?`n") -join '; '))

# Bytes per application request on the primaries (records of the app accounts only).
$appScript = @'
a=$(grep -h '"user":"app1_runtime"' /pgp/*.json | wc -c)
b=$(grep -h ',app1_runtime,' /map/server_audit.log | wc -c)
c=$(grep -F '"user":"app1_runtime"' /store/audit.jsonl | grep -F '"source":"pg-primary"' | wc -c)
d=$(grep -F '"user":"app1_runtime"' /store/audit.jsonl | grep -F '"source":"maria-primary"' | wc -c)
echo "$a $b $c $d"
'@
$appVols = @(($volStore + ':/store:ro'), ($P2Project + '_pg-primary-log:/pgp:ro'), ($P2Project + '_maria-primary-audit:/map:ro'))
$before = ((Invoke-Reader $appScript @{} $appVols).Out.Trim() -split '\s+') | ForEach-Object { [long]$_ }
$okReq = 0
foreach ($i in 1..$AppRequests) {
    foreach ($app in @('dotnet', 'laravel')) {
        try { $resp = Invoke-WebRequest -UseBasicParsing -Uri ('http://localhost:8080/' + $app + '/api/customers') -TimeoutSec 30; if ($resp.StatusCode -eq 200) { $okReq++ } } catch { }
    }
}
Start-Sleep -Seconds 5
$after = ((Invoke-Reader $appScript @{} $appVols).Out.Trim() -split '\s+') | ForEach-Object { [long]$_ }
$d = @(); for ($i = 0; $i -lt 4; $i++) { $d += [Math]::Round(($after[$i] - $before[$i]) / [double]$AppRequests, 0) }
Write-Result ($okReq -eq (2 * $AppRequests)) ('{0} GET /api/customers requests per application answered 200; audit bytes per request measured' -f $AppRequests) ('per request: PG primary source {0} B, store {2} B (dotnet: pooled connection, ddl/role classes only); MariaDB primary source {1} B, store {3} B (laravel: one connection per request, CONNECT/DISCONNECT only, queries of app1_runtime excluded)' -f $d[0], $d[1], $d[2], $d[3])
Add-Measure ('per application request: PG primary {0} B source / {2} B store; MariaDB primary {1} B source / {3} B store' -f $d[0], $d[1], $d[2], $d[3])
$sz = Invoke-Reader 'wc -c /store/audit.jsonl /store/alerts.jsonl; du -sb /s/* | sed "s#/s/##"' @{} @(($volStore + ':/store:ro'), ($P2Project + '_pg-primary-log:/s/pg-primary-log:ro'), ($P2Project + '_pg-replica-log:/s/pg-replica-log:ro'), ($P2Project + '_maria-primary-audit:/s/maria-primary-audit:ro'), ($P2Project + '_maria-replica-audit:/s/maria-replica-audit:ro'), ($P2Project + '_bao-audit:/s/bao-audit:ro'))
Note ('sizes now: ' + (($sz.Out.Trim() -split "`r?`n") -join '; '))
$ms = (Invoke-Docker @('stats', '--no-stream', '--format', '{{.Name}} {{.MemUsage}}', (Id 'fluent-bit'), (Id 'pg-primary'), (Id 'pg-replica'), (Id 'maria-primary'), (Id 'maria-replica'))).Out.Trim() -replace ($P2Project + '-'), ''
Add-Measure ('memory: ' + (($ms -split "`r?`n") -join '; '))

# =============================================================================================
if ($LeakAndPurgeTest) {
    Write-Host ''
    Write-Host '== OPT-IN (-LeakAndPurgeTest): reproduce the OLD MariaDB leaks, then remediate: rotate, FLUSH, PURGE BINARY LOGS =='
    # (1) The old temp-user path: CREATE USER ... IDENTIFIED BY '<pw>' run on the primary, the
    #     statement shape OpenBao used in phases 2 and 3.
    $oldPw = New-LabPassword
    [void](MaSu 'maria-primary' ("DROP USER IF EXISTS 'lab_oldpath'@'{0}'" -f $accessMask))
    $r = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', '-e', 'P4PW', (Id 'maria-primary'), 'bash', '-c',
        ('mariadb --protocol=socket -uroot -e "CREATE USER ''lab_oldpath''@''{0}'' IDENTIFIED BY ''$P4PW'' REQUIRE SSL; GRANT SELECT ON app1_masked.* TO ''lab_oldpath''@''{0}''" 2>&1 | sed -E "s/BY .[^ ]*/BY <redacted>/"' -f $accessMask)) @{ MYSQL_PWD = $mariaRootPw; P4PW = $oldPw }
    $pp = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
    [void](MaVal 'maria-replica' ("SELECT MASTER_GTID_WAIT('{0}', 30)" -f $pp))
    $so = Search-Values @{ old = $oldPw }
    $ho = $so.Res['old']
    Write-Result (($r.Code -eq 0) -and ($ho['maria-data'] -match 'mariadb-bin\.\d+') -and ($ho['maria-replica-data'] -match 'maria-replica-relay\.\d+') -and ($ho['maria-replica-data'] -match 'maria-replica-bin\.\d+') -and (@($textLocs | Where-Object { $ho[$_] }).Count -eq 0)) 'OLD PATH, LEAK REPRODUCED: CREATE USER ... IDENTIFIED BY on the primary puts the password in clear text into the primary''s binlog, the replica''s relay log and (log_slave_updates) the replica''s binlog; server_audit masks it' (Format-Hits $ho)
    # (2) The phase 2/3 bao_admin rotation statement.
    try {
        [void](BaoRoot @('write', 'database/config/app1-maria', ('root_rotation_statements=' + $p23Rotation)))
        $r = BaoRoot @('write', '-force', 'database/rotate-root/app1-maria')
        $p = Invoke-Reader $binlogProbe @{} $probeVols 'mariadb:11.8' ('container:' + (Id 'openbao'))
        Write-Result (($r.Code -eq 0) -and ($p.Out -match 'IDENTIFIED BY .<clear-text literal>') -and ($p.Out -match 'with that literal: SUCCEEDED')) 'OLD PATH, LEAK REPRODUCED: with the phase 2/3 root_rotation_statements (ALTER USER ... IDENTIFIED BY) the new bao_admin password is in the binlog in clear text, and it logs in' $p.Out
    } finally {
        [void](BaoRoot @('write', 'database/config/app1-maria', ('root_rotation_statements=' + $p4Rotation)))
    }
    # (3) Remediation for passwords already in binlogs: rotate every affected password with a
    #     hash-only statement, then remove the old binlogs once the replica has applied them.
    $r1 = BaoRoot @('write', '-force', 'database/rotate-root/app1-maria')
    $newPw = New-LabPassword
    $r2 = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', '-e', 'P4PW', (Id 'maria-primary'), 'bash', '-c',
        ('mariadb --protocol=socket -uroot -e "SET PASSWORD FOR ''lab_oldpath''@''{0}'' = PASSWORD(''$P4PW'')"' -f $accessMask)) @{ MYSQL_PWD = $mariaRootPw; P4PW = $newPw }
    $steps = @()
    $steps += ('rotated: bao_admin (rotate-root, SET PASSWORD form) exit {0}; lab_oldpath (SET PASSWORD FOR) exit {1}' -f $r1.Code, $r2.Code)
    [void](MaSu 'maria-primary' 'FLUSH BINARY LOGS')
    $curP = (MaVal 'maria-primary' 'SHOW MASTER STATUS').Split("`t")[0]
    $pp = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
    $wt = MaVal 'maria-replica' ("SELECT MASTER_GTID_WAIT('{0}', 30)" -f $pp)
    $steps += ('primary: FLUSH BINARY LOGS -> current {0}; replica applied up to {1}: MASTER_GTID_WAIT={2}' -f $curP, $pp, $wt)
    $pr = MaSu 'maria-primary' ("PURGE BINARY LOGS TO '{0}'" -f $curP)
    $steps += ('primary: PURGE BINARY LOGS TO ''{0}'': exit {1} {2}; files now: {3}' -f $curP, $pr.Code, $pr.All, ((MaVal 'maria-primary' 'SHOW BINARY LOGS') -replace '\s+', ' '))
    [void](MaSu 'maria-replica' 'FLUSH RELAY LOGS')
    # A primary write after the relay-log switch lets the SQL thread leave the old relay log,
    # which relay_log_purge then deletes.
    [void](MaSu 'maria-primary' ("DROP USER IF EXISTS 'lab_oldpath'@'{0}'" -f $accessMask))
    $pp = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
    [void](MaVal 'maria-replica' ("SELECT MASTER_GTID_WAIT('{0}', 30)" -f $pp))
    [void](MaSu 'maria-replica' 'FLUSH BINARY LOGS')
    $curR = (MaVal 'maria-replica' 'SHOW MASTER STATUS').Split("`t")[0]
    $prr = MaSu 'maria-replica' ("PURGE BINARY LOGS TO '{0}'" -f $curR)
    Start-Sleep -Seconds 2
    $steps += ('replica: FLUSH RELAY LOGS, FLUSH BINARY LOGS, PURGE BINARY LOGS TO ''{0}'': exit {1} {2}; relay_log_purge={3}' -f $curR, $prr.Code, $prr.All, (MaVal 'maria-replica' 'SELECT @@relay_log_purge'))
    $sa = Search-Values @{ old = $oldPw; new = $newPw }
    $p = Invoke-Reader $binlogProbe @{} $probeVols 'mariadb:11.8' ('container:' + (Id 'openbao'))
    $rsx = @{}
    foreach ($l in ((Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Id 'maria-replica'), 'mariadb', '--protocol=socket', '-uroot', '-e', 'SHOW REPLICA STATUS\G') @{ MYSQL_PWD = $mariaRootPw }).Out -split "`r?`n")) { if ($l -match '^\s*([A-Za-z_]+):\s?(.*)$') { $rsx[$Matches[1]] = $Matches[2].Trim() } }
    $ok = ($pr.Code -eq 0) -and ($prr.Code -eq 0) -and ((Get-HitLocations $sa.Res['old']).Count -eq 0) -and ((Get-HitLocations $sa.Res['new']).Count -eq 0) -and ($p.Out -match 'latest ALTER USER literal: none') -and ($rsx['Slave_IO_Running'] -eq 'Yes') -and ($rsx['Slave_SQL_Running'] -eq 'Yes')
    Write-Result $ok 'REMEDIATION: after rotating the affected passwords and PURGE BINARY LOGS on the primary and the replica (relay logs purged by relay_log_purge), neither the leaked nor the new password is anywhere; no bao_admin literal is left; replication still runs' (($steps -join "`n") + "`nold: " + ((Format-Hits $sa.Res['old']) -replace "`n", '; ') + "`nnew: " + ((Format-Hits $sa.Res['new']) -replace "`n", '; ') + "`n" + $p.Out)
}
# =============================================================================================
# Cleanup: revoke every token this run created (and with it all leases), remove clients.
foreach ($tk in $script:Tokens) { [void](Invoke-Bao @('token', 'revoke', '-self') $tk) }
foreach ($c in $script:Containers) { [void](Invoke-Docker @('rm', '-f', $c)) }
Start-Sleep -Seconds 3
$left = PgVal 'pg-primary' "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-jwt-%'"
$leftM = MaVal 'maria-replica' "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'v-jwt-%'"
$leftMP = MaVal 'maria-primary' "SELECT COUNT(*) FROM mysql.global_priv WHERE User LIKE 'v-%'"
Write-Host ''
Write-Host ('cleanup: test tokens revoked, client containers removed; remaining v-jwt-* users: pg-primary {0}, maria-replica {1}; v- accounts on maria-primary: {2}' -f $left, $leftM, $leftMP)
Write-Host ''
Write-Host 'Measurements:'
foreach ($m in $script:Measure) { Write-Host ('  ' + $m) }
Write-Host ''
Write-Host ('Summary: {0} passed, {1} failed' -f $script:Pass, $script:Fail)
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
