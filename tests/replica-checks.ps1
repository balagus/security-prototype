[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # Allowed time for the sweeper to end a session = sweep interval (read from the sweeper
    # containers) + this margin.
    [int]$MarginSeconds = 10,
    # Seconds to wait for a replica to catch up (new users, app rows, restart).
    [int]$ReplicaWaitSeconds = 60,
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype',
    [string]$BaoSecretPrefix = 'openbao',
    # OpenBao creates the MariaDB temp users on maria-replica ONLY, with sql_log_bin=0
    # (docs/DECISIONS.md D6). They never replicate, and the revocation statement's KILL USER runs
    # on the replica itself; the MariaDB assertions expect that and print why (NOTE lines).
    # -MariaTempUsersOnReplica:$false checks a stack that creates them on the primary instead.
    [switch]$MariaTempUsersOnReplica = $true,
    # Bound for OpenBao's revocation retry after a replica outage (temp users on the replica;
    # measured retry delays about 20 s, 40 s, 80 s, ...).
    [int]$RevokeRetryWaitSeconds = 200
)

# Read replica checks (docs/DECISIONS.md D5, D7) against the RUNNING, configured stack
# (compose.yaml after scripts\setup.ps1): replicas, the pg_hba split, temp users on the replicas only, and
# the replica session sweepers. Windows PowerShell 5.1 compatible. One PASS/FAIL line per
# check; exit 0 only if all pass.
#
# Same rules as hardening-checks.ps1 and jit-access-checks.ps1: a negative check passes only if its
# error text matches the control under test (the real text is printed), and positive controls
# show the tool and path work. The developer is played by throwaway postgres:17 / mariadb:11.8
# client containers on the access network.
#
# This script stops and starts the sweepers once (control case) and the replicas once (revoke
# while the replica is down), and briefly repoints MariaDB replication at the primary's IP
# address to prove that the replica verifies the primary's certificate. It leaves everything
# running. Takes about 4 minutes.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.yaml' }
$LabComposeFile = $ComposeFile
$LabProject = $Project
$LabBaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $root 'scripts\lib.ps1')

$netAccess = $LabProject + '_access'
$netPg = $LabProject + '_app1-pg'
$netMaria = $LabProject + '_app1-maria'
$netPgRepl = $LabProject + '_pg-repl'
$netMariaRepl = $LabProject + '_maria-repl'
$volCa = $LabProject + '_pki-ca'
$accessMask = '10.81.5.0/255.255.255.0'
$realmFile = Join-Path $LabRoot 'config\keycloak\lab-realm.json'

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
function Assert-Refused {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -ne 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, $Result.All)
    if (-not $ok) { $detail = $detail + ("`n(expected a failure matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}
function Assert-Works {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -eq 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, $Result.All)
    if (-not $ok) { $detail = $detail + ("`n(expected success matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}
function Note { param([string]$Text) Write-Host ('       | ' + $Text) }
function Add-Measure { param([string]$Text) [void]$script:Measure.Add($Text); Note ('measured: ' + $Text) }

# --- identities (as in jit-access-checks.ps1) -----------------------------------------------------
$realm = [System.IO.File]::ReadAllText($realmFile, $LabUtf8NoBom) | ConvertFrom-Json
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
$baoRootToken = Read-LabSecret $LabBaoRootTokenName
function BaoRoot { param([string[]]$A) Invoke-Bao $A $baoRootToken }

# --- database access -----------------------------------------------------------------------------
$mariaRootPw = Read-LabSecret 'maria_root_password'
$ids = @{}
function Id { param([string]$S) if (-not $ids.ContainsKey($S)) { $ids[$S] = Get-LabContainerId $S }; return $ids[$S] }
# Local superuser on a server (socket; peer auth / root password from the secret).
function PgSu { param([string]$S, [string]$Sql) Invoke-Docker @('exec', '-u', 'postgres', (Id $S), 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', 'app1', '-c', $Sql) }
function MaSu { param([string]$S, [string]$Sql) Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Id $S), 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mariaRootPw } }
# SHOW REPLICA STATUS of maria-replica as a hashtable (vertical output needs the column names, so no -N).
function Get-ReplStatus {
    $x = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Id 'maria-replica'), 'mariadb', '--protocol=socket', '-uroot', '-e', 'SHOW REPLICA STATUS\G') @{ MYSQL_PWD = $mariaRootPw }
    $h = @{}
    foreach ($l in ($x.Out -split "`r?`n")) { if ($l -match '^\s*([A-Za-z_]+):\s?(.*)$') { $h[$Matches[1]] = $Matches[2].Trim() } }
    return $h
}
function PgVal { param([string]$S, [string]$Sql) return (PgSu $S $Sql).Out.Trim() }
function MaVal { param([string]$S, [string]$Sql) return (MaSu $S $Sql).Out.Trim() }
# Where the MariaDB temp users live (default: the replica only).
$maTempHost = 'maria-primary'
if ($MariaTempUsersOnReplica) { $maTempHost = 'maria-replica' }
function Note-Altered { param([string]$Text) Write-Host ('       | NOTE (temp users on maria-replica): ' + $Text) -ForegroundColor Yellow }
# Throwaway clients.
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
function Tcp {
    param([string]$Net, [string]$HostName, [int]$Port)
    Invoke-Docker @('run', '--rm', '--network', $Net, '--entrypoint', 'bash', 'postgres:17', '-c',
        'timeout 5 bash -c ''exec 3<>"/dev/tcp/$0/$1"'' "$1" "$2" && echo "bash /dev/tcp connected to $1:$2"', 'probe', $HostName, [string]$Port)
}
function New-LabPassword { $a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; return -join (1..28 | ForEach-Object { $a[(Get-Random -Maximum $a.Length)] }) }

$pgReplicaConn = 'host=pg-replica dbname=app1 sslmode=verify-full sslrootcert=/ca/ca.crt'
$pgPrimaryConn = 'host=pg-primary dbname=app1 sslmode=verify-full sslrootcert=/ca/ca.crt'

# Waits (bounded) until a temp user exists on the replica; returns seconds or -1.
function Wait-OnReplica {
    param([string]$PgUser, [string]$MariaUser, [datetime]$Since)
    $deadline = (Get-Date).AddSeconds($ReplicaWaitSeconds)
    $pgAt = $null; $maAt = $null
    while ((Get-Date) -lt $deadline) {
        if ($PgUser -and (-not $pgAt) -and ((PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $PgUser)) -eq '1')) { $pgAt = Get-Date }
        if ($MariaUser -and (-not $maAt) -and ((MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $MariaUser)) -eq '1')) { $maAt = Get-Date }
        if (((-not $PgUser) -or $pgAt) -and ((-not $MariaUser) -or $maAt)) { break }
        Start-Sleep -Milliseconds 200
    }
    $p = -1; $m = -1
    if ($pgAt) { $p = ($pgAt - $Since).TotalSeconds }
    if ($maAt) { $m = ($maAt - $Since).TotalSeconds }
    return @{ Pg = $p; Maria = $m }
}

# Long-lived developer sessions on the replicas (several statements, each below the 60 s
# statement limits of the temp users). Return the container name.
function Start-PgSession {
    param([string]$Tag, $C, [int]$Sleeps = 3)
    $n = 'p3sess-' + $Tag + '-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    [void]$script:Containers.Add($n)
    $a = @('run', '-d', '--name', $n, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD', '--entrypoint', 'psql', 'postgres:17',
        ($pgReplicaConn + ' user=' + $C.User), '-X', '-At', '-c', "SELECT 'session open as ' || current_user || ' pid=' || pg_backend_pid()")
    for ($i = 0; $i -lt $Sleeps; $i++) { $a += @('-c', 'SELECT pg_sleep(50)') }
    $a += @('-c', ("SELECT 'STILL ALIVE after {0} s'" -f (50 * $Sleeps)))
    [void](Invoke-Docker $a @{ PGPASSWORD = $C.Password })
    return $n
}
function Start-MariaSession {
    param([string]$Tag, $C, [int]$Sleeps = 3)
    $n = 'p3sess-' + $Tag + '-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    [void]$script:Containers.Add($n)
    [void](Invoke-Docker @('run', '-d', '--name', $n, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD', '--entrypoint', 'mariadb', 'mariadb:11.8',
        '-h', 'maria-replica', '-u', $C.User, '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert', '--skip-reconnect', '-N', '-B', 'app1_masked',
        '-e', ("SELECT CONCAT('session open as ', CURRENT_USER(), ' id=', CONNECTION_ID()); " + ('SELECT SLEEP(50); ' * $Sleeps) + ("SELECT 'STILL ALIVE after {0} s';" -f (50 * $Sleeps)))) @{ MYSQL_PWD = $C.Password })
    return $n
}
# Server-side session ids on the replicas (0 = none yet).
function Get-PgPid { param([string]$User)
    $deadline = (Get-Date).AddSeconds(30)
    do { $v = PgVal 'pg-replica' ("SELECT coalesce(max(pid), 0) FROM pg_stat_activity WHERE usename = '{0}'" -f $User); if ($v -ne '0') { return [int]$v }; Start-Sleep -Milliseconds 300 } while ((Get-Date) -lt $deadline)
    return 0
}
function Get-MaId { param([string]$User)
    $deadline = (Get-Date).AddSeconds(30)
    do { $v = MaVal 'maria-replica' ("SELECT COALESCE(MAX(ID), 0) FROM information_schema.PROCESSLIST WHERE USER = '{0}'" -f $User); if ($v -ne '0') { return [long]$v }; Start-Sleep -Milliseconds 300 } while ((Get-Date) -lt $deadline)
    return 0
}
function Test-PgPidAlive { param([int]$P) return ((PgVal 'pg-replica' ("SELECT count(*) FROM pg_stat_activity WHERE pid = {0}" -f $P)) -eq '1') }
function Test-MaIdAlive { param([long]$I) return ((MaVal 'maria-replica' ("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = {0}" -f $I)) -eq '1') }
# Polls both sessions until gone or timeout; returns seconds from $T0 to disappearance (-1 = still alive).
function Wait-SessionsGone {
    param([int]$PgPid, [long]$MaId, [datetime]$T0, [int]$Seconds)
    $deadline = $T0.AddSeconds($Seconds)
    $pgGone = $null; $maGone = $null
    while ((Get-Date) -lt $deadline) {
        if (($PgPid -gt 0) -and (-not $pgGone) -and (-not (Test-PgPidAlive $PgPid))) { $pgGone = Get-Date }
        if (($MaId -gt 0) -and (-not $maGone) -and (-not (Test-MaIdAlive $MaId))) { $maGone = Get-Date }
        if ((($PgPid -le 0) -or $pgGone) -and (($MaId -le 0) -or $maGone)) { break }
        Start-Sleep -Milliseconds 300
    }
    $p = -1; $m = -1
    if ($pgGone) { $p = [Math]::Round(($pgGone - $T0).TotalSeconds, 1) }
    if ($maGone) { $m = [Math]::Round(($maGone - $T0).TotalSeconds, 1) }
    return @{ Pg = $p; Maria = $m }
}
function Get-Logs { param([string]$Name) return (Invoke-Docker @('logs', $Name)).All }
# Only lines written since this script started (earlier runs and jit-access-checks.ps1 also cause kills).
$scriptStart = (Get-Date).ToUniversalTime().AddSeconds(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
function Get-SweeperLog { param([string]$Svc) return (Invoke-Docker @('logs', '--since', $scriptStart, (Id $Svc))).All }
function Compose { param([string[]]$A) Invoke-Docker (@('compose', '-f', $LabComposeFile) + $A) @{} 180 }

Write-Host ('Replica checks: compose file {0}, project {1}' -f $LabComposeFile, $LabProject)
foreach ($s in @('pg-primary', 'maria-primary', 'pg-replica', 'maria-replica', 'pg-sweeper', 'maria-sweeper', 'openbao', 'keycloak')) { [void](Id $s) }
$st = Get-BaoStatus
if (($null -eq $st.Obj) -or $st.Obj.sealed) { throw 'OpenBao is sealed or not answering. Run scripts\setup.ps1 (or scripts\unseal.ps1).' }
$interval = 60
foreach ($e in (ConvertFrom-Json (Invoke-Docker @('inspect', '-f', '{{json .Config.Env}}', (Id 'pg-sweeper'))).Out)) { if ($e -match '^SWEEP_INTERVAL_SECONDS=(\d+)$') { $interval = [int]$Matches[1] } }
$bound = $interval + $MarginSeconds
Write-Host ('sweep interval {0} s (lab value; the proposal says 60 s for production); allowed time to end a session: {1} s' -f $interval, $bound)
# Clock offset Docker VM - Windows host (OpenBao lease expiry times are in VM time).
$h0 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$vm = [double]::Parse((PgVal 'pg-replica' 'SELECT extract(epoch FROM clock_timestamp())'), [System.Globalization.CultureInfo]::InvariantCulture)
$h1 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$skew = [Math]::Round($vm - (($h0 + $h1) / 2000.0), 2)
Write-Host ('clock offset Docker VM minus host: {0} s (+/- {1} s), used to convert lease expiry times' -f $skew, [Math]::Round(($h1 - $h0) / 2000.0, 2))

# =============================================================================================
Write-Host ''
Write-Host '== Topology: networks, addresses, published ports =='

$nets = @{}
foreach ($s in @('pg-primary', 'maria-primary', 'pg-replica', 'maria-replica', 'pg-sweeper', 'maria-sweeper', 'openbao', 'keycloak')) {
    $nets[$s] = (Invoke-Docker @('inspect', '-f', '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}', (Id $s))).Out.Trim() -replace ($LabProject + '_'), ''
}
$d = ($nets.Keys | Sort-Object | ForEach-Object { '{0}: {1}' -f $_, $nets[$_] }) -join "`n"
$ok = ($nets['pg-primary'] -notmatch 'access=') -and ($nets['maria-primary'] -notmatch 'access=') -and
      ($nets['pg-primary'] -match 'pg-repl=10\.81\.7\.10') -and ($nets['maria-primary'] -match 'maria-repl=10\.81\.8\.10') -and
      ($nets['pg-primary'] -match 'bao-admin=') -and ($nets['maria-primary'] -match 'bao-admin=')
Write-Result $ok 'primaries are NOT on the access network; on their replication network (fixed .10) and on bao-admin' $d
$ok = ($nets['pg-replica'] -match 'access=10\.81\.5\.11') -and ($nets['pg-replica'] -match 'pg-repl=10\.81\.7\.11') -and ($nets['pg-replica'] -notmatch 'app1-pg|bao-admin|lab') -and
      ($nets['maria-replica'] -match 'access=10\.81\.5\.12') -and ($nets['maria-replica'] -match 'maria-repl=10\.81\.8\.11') -and ($nets['maria-replica'] -notmatch 'app1-maria|bao-admin|lab')
if ($MariaTempUsersOnReplica) {
    Note-Altered 'maria-replica must be on bao-replica (10.81.9.12), OpenBao''s admin path for creating temp users there; not on bao-admin, app1-maria or lab'
    $ok = $ok -and ($nets['maria-replica'] -match 'bao-replica=10\.81\.9\.12') -and (@($nets['maria-replica'].Split(' ') | Where-Object { $_ }).Count -eq 3)
    Write-Result $ok 'replicas: access + their replication network, maria-replica also on bao-replica (OpenBao only), fixed addresses' ''
} else {
    Write-Result ($ok -and ($nets['maria-replica'] -notmatch 'bao-replica')) 'replicas: access + their replication network only, fixed addresses' ''
}
$ok = ($nets['pg-sweeper'] -eq 'access=10.81.5.21') -and ($nets['maria-sweeper'] -eq 'access=10.81.5.22') -and
      ($nets['openbao'] -match 'access=') -and ($nets['openbao'] -match 'bao-admin=10\.81\.4\.10') -and ($nets['keycloak'] -match 'access=')
Write-Result $ok 'sweepers only on access at fixed .21/.22; OpenBao (bao-admin 10.81.4.10) and Keycloak also on access' ''
$pb = @()
foreach ($s in @('pg-primary', 'maria-primary', 'pg-replica', 'maria-replica', 'pg-sweeper', 'maria-sweeper')) { $pb += ('{0}: {1}' -f $s, (Invoke-Docker @('inspect', '-f', '{{json .HostConfig.PortBindings}}', (Id $s))).Out.Trim()) }
$ok = -not (($pb -join "`n") -match ': \{"')
Write-Result $ok 'no database, replica or sweeper port is published to the host' ($pb -join "`n")

Assert-Works 'control: from the access network pg-replica:5432 is reachable' (Tcp $netAccess 'pg-replica' 5432) 'connected'
Assert-Works 'control: from the access network maria-replica:3306 is reachable' (Tcp $netAccess 'maria-replica' 3306) 'connected'
$noName = 'Name or service not known|Temporary failure in name resolution|getaddrinfo'
$noRoute = 'Network is unreachable|timed out|No route to host|Connection timed out'
Assert-Refused 'from the access network pg-primary does not resolve' (Tcp $netAccess 'pg-primary' 5432) $noName
Assert-Refused 'from the access network maria-primary does not resolve' (Tcp $netAccess 'maria-primary' 3306) $noName
Assert-Refused 'from the access network pg-primary is unreachable by IP (10.81.7.10, its pg-repl address)' (Tcp $netAccess '10.81.7.10' 5432) $noRoute
Assert-Refused 'from the access network maria-primary is unreachable by IP (10.81.8.10, its maria-repl address)' (Tcp $netAccess '10.81.8.10' 3306) $noRoute

# =============================================================================================
Write-Host ''
Write-Host '== Replication: running, TLS, seeded, application rows arrive =='

$r = PgSu 'pg-primary' "SELECT 'app=' || r.application_name || ' addr=' || host(r.client_addr) || ' user=' || r.usename || ' state=' || r.state || ' sync=' || r.sync_state || ' ssl=' || s.ssl || ' ' || s.version || ' slot=' || (SELECT slot_name || ':active=' || active FROM pg_replication_slots WHERE active_pid = r.pid) FROM pg_stat_replication r JOIN pg_stat_ssl s ON s.pid = r.pid"
Assert-Works 'PG: primary streams to pg-replica (10.81.7.11) as replicator over TLS through slot pg_replica' $r 'app=pg-replica addr=10\.81\.7\.11 user=replicator state=streaming sync=async ssl=true TLSv1\.[23] slot=pg_replica:active=true'
$r = PgSu 'pg-replica' "SELECT 'in_recovery=' || pg_is_in_recovery() || ' receiver=' || status || ' hot_standby_feedback=' || current_setting('hot_standby_feedback') || ' max_standby_streaming_delay=' || current_setting('max_standby_streaming_delay') || ' conninfo: ' || conninfo FROM pg_stat_wal_receiver"
Assert-Works 'PG: replica is a hot standby, receiver streaming with sslmode=verify-full; hot_standby_feedback off, max_standby_streaming_delay 30s' $r 'in_recovery=true receiver=streaming hot_standby_feedback=off max_standby_streaming_delay=30s conninfo: .*sslmode=verify-full.*host=pg-primary|in_recovery=true receiver=streaming hot_standby_feedback=off max_standby_streaming_delay=30s conninfo: .*host=pg-primary.*sslmode=verify-full'
# Same libpq settings as the walreceiver, from the replica's own network namespace: by service
# name the primary's certificate verifies; by IP address verify-full refuses.
$replPw = Read-LabSecret 'pg_replicator_password'
$replConn = 'port=5432 user=replicator replication=true sslmode=verify-full sslrootcert=/pki-ca/ca.crt connect_timeout=5'
$r = Invoke-Docker @('run', '--rm', '--network', ('container:' + (Id 'pg-replica')), '-v', ($volCa + ':/pki-ca:ro'), '-e', 'PGPASSWORD', '--entrypoint', 'psql', 'postgres:17', ('host=pg-primary ' + $replConn), '-X', '-At', '-c', 'IDENTIFY_SYSTEM') @{ PGPASSWORD = $replPw }
Assert-Works 'PG: control: a replication connection as replicator from the replica''s address to pg-primary (verify-full) works' $r '^\d+\|1\|'
$r = Invoke-Docker @('run', '--rm', '--network', ('container:' + (Id 'pg-replica')), '-v', ($volCa + ':/pki-ca:ro'), '-e', 'PGPASSWORD', '--entrypoint', 'psql', 'postgres:17', ('host=10.81.7.10 ' + $replConn), '-X', '-At', '-c', 'IDENTIFY_SYSTEM') @{ PGPASSWORD = $replPw }
Assert-Refused 'PG: the same replication connection by IP is refused by certificate verification (verify-full checks the name)' $r 'server certificate for "pg-primary".*does not match host name "10\.81\.7\.10"'

$f = Get-ReplStatus
$d = ('Master_Host={0} Master_User={1} IO={2} SQL={3} Using_Gtid={4} Master_SSL_Allowed={5} Master_SSL_CA_File={6} Master_SSL_Verify_Server_Cert={7} Seconds_Behind_Master={8} Last_IO_Error=[{9}] Last_SQL_Error=[{10}] Gtid_IO_Pos={11}' -f
    $f['Master_Host'], $f['Master_User'], $f['Slave_IO_Running'], $f['Slave_SQL_Running'], $f['Using_Gtid'], $f['Master_SSL_Allowed'], $f['Master_SSL_CA_File'], $f['Master_SSL_Verify_Server_Cert'], $f['Seconds_Behind_Master'], $f['Last_IO_Error'], $f['Last_SQL_Error'], $f['Gtid_IO_Pos'])
$ok = ($f['Slave_IO_Running'] -eq 'Yes') -and ($f['Slave_SQL_Running'] -eq 'Yes') -and ($f['Using_Gtid'] -eq 'Slave_Pos') -and ($f['Master_SSL_Allowed'] -eq 'Yes') -and
      ($f['Master_SSL_Verify_Server_Cert'] -eq 'Yes') -and ($f['Master_Host'] -eq 'maria-primary') -and ($f['Master_User'] -eq 'replicator') -and (-not $f['Last_IO_Error']) -and (-not $f['Last_SQL_Error'])
Write-Result $ok 'Maria: replica IO and SQL threads running, GTID (slave_pos), TLS with server certificate verification' $d
$r = MaSu 'maria-replica' "SELECT CONCAT('read_only=', @@read_only, ' server_id=', @@server_id, ' gtid_strict_mode=', @@gtid_strict_mode, ' log_bin=', @@log_bin)"
Assert-Works 'Maria: replica has read_only=ON (server_id 2, gtid_strict_mode)' $r 'read_only=(1|ON) server_id=2 gtid_strict_mode=(1|ON)'
$r = MaSu 'maria-primary' "SHOW GRANTS FOR 'replicator'@'10.81.8.11'"
$shown = $r.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'"
$ok = ($r.Code -eq 0) -and ($r.Out -match 'REPLICATION SLAVE') -and ($r.Out -match 'REQUIRE SSL') -and ((MaVal 'maria-primary' "SELECT COUNT(*) FROM mysql.user WHERE User = 'replicator'") -eq '1')
Write-Result $ok 'Maria: replicator exists only for the replica''s address 10.81.8.11, REQUIRE SSL' $shown
$r = Invoke-Docker @('run', '--rm', '--network', $netMariaRepl, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD', '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', 'maria-primary', '-u', 'replicator', '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert', '--connect-timeout=5', '-N', '-e', 'SELECT 1') @{ MYSQL_PWD = (Read-LabSecret 'maria_replicator_password') }
Assert-Refused 'Maria: replicator with the right password from another maria-repl address is refused (host)' $r "Host '10\.81\.8\.\d+' is not allowed to connect|Access denied for user 'replicator'@'10\.81\.8\.\d+'"

# Certificate verification of the replication IO thread itself: point it at the primary's IP
# address (not in the certificate), observe the TLS error, then restore and wait for catch-up.
$gtidBefore = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
[void](MaSu 'maria-replica' "STOP REPLICA; CHANGE MASTER TO MASTER_HOST = '10.81.8.10'; START REPLICA;")
$ioErr = ''
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    $x = Get-ReplStatus
    if ($x['Last_IO_Error']) { $ioErr = $x['Last_IO_Error']; break }
    Start-Sleep -Seconds 1
}
$ioState = $x['Slave_IO_Running']
[void](MaSu 'maria-replica' "STOP REPLICA; CHANGE MASTER TO MASTER_HOST = 'maria-primary'; START REPLICA;")
$ok = ($ioErr -match 'certificate|Hostname verification|SSL|TLS') -and ($ioState -ne 'Yes')
Write-Result $ok 'Maria: with MASTER_HOST set to the primary''s IP the IO thread refuses the connection (certificate name check)' ('Slave_IO_Running={0}; Last_IO_Error: {1}' -f $ioState, $ioErr)
$back = MaVal 'maria-replica' ("SELECT MASTER_GTID_WAIT('{0}', 30)" -f $gtidBefore)
$x = Get-ReplStatus
$ok = ($back -eq '0') -and ($x['Slave_IO_Running'] -eq 'Yes') -and ($x['Slave_SQL_Running'] -eq 'Yes') -and ($x['Master_Host'] -eq 'maria-primary')
Write-Result $ok 'Maria: restored to MASTER_HOST=maria-primary, replication running and caught up' ('MASTER_GTID_WAIT({0}) = {1}' -f $gtidBefore, $back)

# Seed: every account of the primary is on the replica (they came with the mysql database).
$localOnly = ''
if ($MariaTempUsersOnReplica) {
    Note-Altered 'accounts that exist on the replica only by design are left out of the comparison: bao_replica_admin (OpenBao''s local account), revocation_backstop (locked definer of the replica-local expiry backstop event, created by the replica''s init_file) and v-* temp users (created there with sql_log_bin=0)'
    $localOnly = " AND User NOT IN ('bao_replica_admin', 'revocation_backstop') AND User NOT LIKE 'v-%'"
}
$pa = (MaVal 'maria-primary' ("SELECT GROUP_CONCAT(CONCAT(User, '@', Host) ORDER BY User, Host SEPARATOR ' ') FROM mysql.user WHERE User NOT IN ('healthcheck')" + $localOnly))
$ra = (MaVal 'maria-replica' ("SELECT GROUP_CONCAT(CONCAT(User, '@', Host) ORDER BY User, Host SEPARATOR ' ') FROM mysql.user WHERE User NOT IN ('healthcheck')" + $localOnly))
Write-Result (($pa -eq $ra) -and ($ra -match 'app1_runtime@10\.81\.3\.0/255\.255\.255\.0') -and ($ra -match 'bao_admin@10\.81\.4\.10') -and ($ra -match 'root@localhost')) 'Maria: the replica has exactly the primary''s accounts (seeded with the mysql database, later ones replicated)' ('primary: ' + $pa + "`nreplica: " + $ra)
$ss = MaVal 'maria-replica' 'SELECT @@gtid_slave_pos'
$pb2 = MaVal 'maria-primary' 'SELECT @@gtid_binlog_pos'
Write-Result ($ss -eq $pb2) 'Maria: replica gtid_slave_pos equals the primary''s gtid_binlog_pos (caught up)' ('primary gtid_binlog_pos {0}; replica gtid_slave_pos {1}' -f $pb2, $ss)

# A row written through each application on the primary appears on the replica.
$stamp = (Get-Date).ToString('yyyyMMddHHmmssfff')
foreach ($b in @(@{ N = 'dotnet'; E = 'PG' }, @{ N = 'laravel'; E = 'Maria' })) {
    $email = ('p3-repl-{0}-{1}@example.test' -f $b.N, $stamp)
    $t0 = Get-Date
    $status = 0
    try { $resp = Invoke-WebRequest -UseBasicParsing -Uri ('http://localhost:8080/' + $b.N + '/api/customers') -Method Post -Body (@{ email = $email; full_name = 'Replica Check' } | ConvertTo-Json -Compress) -ContentType 'application/json' -TimeoutSec 30; $status = [int]$resp.StatusCode } catch { $status = -1 }
    $t1 = Get-Date
    $seen = $null
    $deadline = $t1.AddSeconds($ReplicaWaitSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($b.E -eq 'PG') { $v = PgVal 'pg-replica' ("SELECT count(*) FROM public.customers WHERE email = '{0}'" -f $email) } else { $v = MaVal 'maria-replica' ("SELECT COUNT(*) FROM app1.customers WHERE email = '{0}'" -f $email) }
        if ($v -eq '1') { $seen = Get-Date; break }
        Start-Sleep -Milliseconds 100
    }
    $lag = -1; if ($seen) { $lag = [Math]::Round(($seen - $t1).TotalSeconds, 2) }
    Write-Result (($status -eq 201) -and ($null -ne $seen)) ('{0}: a customer POSTed through {1}-api (primary) appears on the replica' -f $b.E, $b.N) ('POST status {0}; visible on the replica {1} s after the API answered (poll interval 0.1 s plus docker exec overhead)' -f $status, $lag)
    Add-Measure ('{0} app row primary->replica: {1} s' -f $b.E, $lag)
}

# =============================================================================================
Write-Host ''
Write-Host '== Temporary credentials: work on the replicas, rejected on the primaries =='
$alice = Connect-Bao 'alice'
Write-Result ($null -ne $alice.Token) 'alice logs in to OpenBao (jwt)' ('exit {0}' -f $alice.R.Code)
# Each user is polled for on its replica right after its own creds call returns.
$cp = Get-Creds $alice.Token 'app1-pg-ro'
$w1 = Wait-OnReplica $cp.User '' $cp.At
$cm = Get-Creds $alice.Token 'app1-maria-ro'
$w2 = Wait-OnReplica '' $cm.User $cm.At
$w = @{ Pg = $w1.Pg; Maria = $w2.Maria }
if ($MariaTempUsersOnReplica) {
    Note-Altered 'OpenBao creates the MariaDB temp user on maria-replica itself (not on the primary); the "replication lag" below is then just the time to see it there'
    $onP = MaVal 'maria-primary' ("SELECT COUNT(*) FROM mysql.global_priv WHERE User = '{0}'" -f $cm.User)
    Write-Result (($null -ne $cp.User) -and ($null -ne $cm.User) -and ($onP -eq '0')) 'alice reads database/creds/app1-pg-ro (user created on pg-primary) and app1-maria-ro (user created on maria-replica only; 0 rows on maria-primary)' ('pg {0}; maria {1}; rows on maria-primary: {2}' -f $cp.User, $cm.User, $onP)
} else {
    Write-Result (($null -ne $cp.User) -and ($null -ne $cm.User)) 'alice reads database/creds/app1-pg-ro and app1-maria-ro (OpenBao creates the users on the PRIMARIES)' ('pg {0}; maria {1}' -f $cp.User, $cm.User)
}
Write-Result (($w.Pg -ge 0) -and ($w.Maria -ge 0)) 'both users reach the replicas (bounded wait for replication lag)' ('pg-replica after {0:N2} s, maria-replica after {1:N2} s (from the end of the creds call to the first poll that saw the user; one poll = one docker exec, about 0.3-0.5 s on this host, so this is an upper bound)' -f $w.Pg, $w.Maria)
Add-Measure ('new credentials visible on replica: pg {0:N2} s, maria {1:N2} s' -f $w.Pg, $w.Maria)
$pgU = ' user=' + $cp.User
$r = PgClient $netAccess ($pgReplicaConn + $pgU) "SELECT 'user=' || current_user || ' standby=' || pg_is_in_recovery() || ' ssl=' || s.ssl FROM pg_stat_ssl s WHERE s.pid = pg_backend_pid()" $cp.Password
Assert-Works 'PG: alice''s credentials log in on pg-replica (verify-full) from the access network' $r ('user=' + [regex]::Escape($cp.User) + ' standby=true ssl=true')
$r = MaClient $netAccess 'maria-replica' $cm.User "SELECT CONCAT('user=', CURRENT_USER(), ' server_id=', @@server_id, ' read_only=', @@read_only, ' tls=', (SELECT VARIABLE_VALUE FROM information_schema.SESSION_STATUS WHERE VARIABLE_NAME = 'Ssl_version'))" $cm.Password
Assert-Works 'Maria: alice''s credentials log in on maria-replica (CA + server cert verification) from the access network' $r ('user=' + [regex]::Escape($cm.User) + '@10\.81\.5\.0/255\.255\.255\.0 server_id=2 read_only=(1|ON) tls=TLSv1\.[23]')

$r = PgClient $netAccess ($pgReplicaConn + $pgU) "SELECT string_agg(email || ':' || full_name, ' ') FROM debug.customers" $cp.Password
Write-Result (($r.Code -eq 0) -and ($r.Out -match 'al\*\*\*:A\*\*\*') -and ($r.Out -notmatch '@')) 'PG replica: masked view debug.customers is readable and masked' ('exit {0}: {1}' -f $r.Code, $r.All)
$r = MaClient $netAccess 'maria-replica' $cm.User "SELECT GROUP_CONCAT(CONCAT(email, ':', full_name) SEPARATOR ' ') FROM app1_masked.customers" $cm.Password
Write-Result (($r.Code -eq 0) -and ($r.Out -match 'al\*\*\*:A\*\*\*') -and ($r.Out -notmatch '@')) 'Maria replica: masked view app1_masked.customers is readable and masked' ('exit {0}: {1}' -f $r.Code, $r.All)
Assert-Refused 'PG replica: base table public.customers is refused' (PgClient $netAccess ($pgReplicaConn + $pgU) 'SELECT email FROM public.customers LIMIT 1' $cp.Password) 'permission denied for table customers'
Assert-Refused 'Maria replica: base table app1.customers is refused' (MaClient $netAccess 'maria-replica' $cm.User 'SELECT email FROM app1.customers LIMIT 1' $cm.Password) 'SELECT command denied to user'
Assert-Refused 'PG replica: INSERT is refused (hot standby is read-only)' (PgClient $netAccess ($pgReplicaConn + $pgU) "INSERT INTO public.customers (email, full_name) VALUES ('x@x.test', 'X')" $cp.Password) 'cannot execute INSERT in a read-only transaction'
Assert-Refused 'Maria replica: INSERT is refused' (MaClient $netAccess 'maria-replica' $cm.User "INSERT INTO app1.customers (email, full_name) VALUES ('x@x.test', 'X')" $cm.Password) 'INSERT command denied to user|running with the --read-only option'
# The read-only refusal hides the privilege layer, so check it where it is defined (primary).
$r = PgSu 'pg-primary' ("SELECT 'insert=' || has_table_privilege('{0}', 'public.customers', 'INSERT') || ' update=' || has_table_privilege('{0}', 'public.orders', 'UPDATE') || ' select_base=' || has_table_privilege('{0}', 'public.customers', 'SELECT') || ' select_view=' || has_table_privilege('{0}', 'debug.customers', 'SELECT')" -f $cp.User)
Assert-Works 'PG: privilege layer (on the primary catalog, replicated): no INSERT/UPDATE/SELECT on base tables, SELECT on the view' $r 'insert=false update=false select_base=false select_view=true'
$r = MaSu 'maria-replica' ("SHOW GRANTS FOR '{0}'@'{1}'" -f $cm.User, $accessMask)
$grantLines = @($r.Out -split "`r?`n" | Where-Object { $_ -match '^GRANT' })
Write-Result (($grantLines.Count -eq 2) -and ($r.Out -match 'GRANT SELECT ON `app1_masked`\.\*') -and ($r.Out -notmatch 'INSERT|UPDATE|DELETE|`app1`\.')) 'Maria: privilege layer on the replica: SELECT on app1_masked.* only' ($r.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'")

# Same credentials against the primaries.
Note ('MariaDB host mask of temp users: ''{0}'' (the access subnet). The primary is on app1-maria 10.81.3.0/24, bao-admin 10.81.4.0/24 and maria-repl 10.81.8.0/24 only, so no connection to it can ever come from an address the mask matches.' -f $accessMask)
Assert-Refused 'PG primary: alice''s credentials from the access network: pg-primary does not resolve' (PgClient $netAccess ($pgPrimaryConn + $pgU) 'SELECT 1' $cp.Password) 'could not translate host name "pg-primary"'
Assert-Refused 'Maria primary: alice''s credentials from the access network: maria-primary does not resolve' (MaClient $netAccess 'maria-primary' $cm.User 'SELECT 1' $cm.Password) "Unknown server host 'maria-primary'|Name or service not known|Temporary failure in name resolution"
Assert-Refused 'PG primary: alice''s credentials from app1-pg (reaches the primary) are rejected by pg_hba (+debug_ro reject)' (PgClient $netPg ($pgPrimaryConn + $pgU) 'SELECT 1' $cp.Password) ('pg_hba\.conf rejects connection for host "10\.81\.2\.\d+", user "' + [regex]::Escape($cp.User) + '"')
Assert-Refused 'PG primary: alice''s credentials from pg-repl (reaches the primary) are rejected by pg_hba' (PgClient $netPgRepl ($pgPrimaryConn + $pgU) 'SELECT 1' $cp.Password) ('pg_hba\.conf rejects connection for host "10\.81\.7\.\d+", user "' + [regex]::Escape($cp.User) + '"')
Assert-Refused 'Maria primary: alice''s credentials from app1-maria (reaches the primary) are refused at authentication (host mask)' (MaClient $netMaria 'maria-primary' $cm.User 'SELECT 1' $cm.Password) ("Access denied for user '" + [regex]::Escape($cm.User) + "'@'10\.81\.3\.\d+'")
Assert-Refused 'Maria primary: alice''s credentials from maria-repl (reaches the primary) are refused at authentication (host mask)' (MaClient $netMariaRepl 'maria-primary' $cm.User 'SELECT 1' $cm.Password) ("Access denied for user '" + [regex]::Escape($cm.User) + "'@'10\.81\.8\.\d+'|Host '10\.81\.8\.\d+' is not allowed to connect")

# =============================================================================================
Write-Host ''
Write-Host '== pg_hba split and the bao_admin trap =='
$r = PgSu 'pg-primary' "SELECT string_agg(line_number || ':' || type || ':' || array_to_string(database, ',') || ':' || array_to_string(user_name, ',') || ':' || coalesce(address, '') || ':' || auth_method, ' / ' ORDER BY rule_number) FROM pg_hba_file_rules"
$hba = $r.Out.Trim()
$iBao = $hba.IndexOf(':bao_admin:'); $iRej = $hba.IndexOf('+debug_ro:all:reject')
$ok = ($r.Code -eq 0) -and ($hba -notmatch '10\.81\.5\.0') -and ($hba -notmatch '\+debug_ro:[^/]*scram') -and ($iBao -ge 0) -and ($iRej -gt $iBao) -and ($hba -match 'hostssl:replication:replicator:10\.81\.7\.11:scram-sha-256')
Write-Result $ok 'PG primary pg_hba: no access-network line, +debug_ro only rejected, bao_admin line before that reject, replicator only from 10.81.7.11' ($hba -replace ' / ', "`n")
$r = PgSu 'pg-primary' "SELECT 'member=' || pg_has_role('bao_admin', 'debug_ro', 'MEMBER') || ' usage=' || pg_has_role('bao_admin', 'debug_ro', 'USAGE') || ' set=' || pg_has_role('bao_admin', 'debug_ro', 'SET') || ' admin=' || (SELECT admin_option || ' inherit=' || inherit_option || ' set_opt=' || set_option FROM pg_auth_members WHERE roleid = 'debug_ro'::regrole AND member = 'bao_admin'::regrole)"
Assert-Works 'PG: bao_admin IS a member of debug_ro for pg_hba (+debug_ro) although it cannot use it (ADMIN only, INHERIT/SET false)' $r 'member=true usage=false set=false admin=true inherit=false set_opt=false'
Assert-Refused 'PG replica: bao_admin from the access network is rejected by the replica''s explicit bao_admin line (not by a password check)' (PgClient $netAccess ($pgReplicaConn + ' user=bao_admin') 'SELECT 1' 'not-the-password') 'pg_hba\.conf rejects connection for host "10\.81\.5\.\d+", user "bao_admin"'
$r = PgSu 'pg-replica' "SELECT string_agg(line_number || ':' || array_to_string(user_name, ',') || ':' || coalesce(address, '') || ':' || auth_method, ' / ' ORDER BY rule_number) FROM pg_hba_file_rules"
Write-Result (($r.Out -match '3:bao_admin:all:reject / 4:\+debug_ro:10\.81\.5\.0:scram-sha-256 / 5:session_sweeper:10\.81\.5\.21:scram-sha-256')) 'PG replica pg_hba: bao_admin reject, then +debug_ro from the access subnet, then the sweeper from 10.81.5.21' ($r.All -replace ' / ', "`n")
$r = PgClient $netAccess 'host=pg-replica port=5432 user=replicator replication=true sslmode=verify-full sslrootcert=/ca/ca.crt' 'IDENTIFY_SYSTEM' $replPw
Assert-Refused 'PG replica: replication connections are rejected (replicator from the access network)' $r 'pg_hba\.conf rejects replication connection'
$r = PgClient $netPgRepl 'host=pg-primary port=5432 user=replicator replication=true sslmode=verify-full sslrootcert=/ca/ca.crt' 'IDENTIFY_SYSTEM' $replPw
Assert-Refused 'PG primary: replicator from another pg-repl address is rejected by pg_hba' $r 'pg_hba\.conf rejects replication connection for host "10\.81\.7\.\d+", user "replicator"'
$r = PgClient $netPgRepl ($pgPrimaryConn + ' user=session_sweeper') 'SELECT 1' (Read-LabSecret 'pg_session_sweeper_password')
Assert-Refused 'PG primary: session_sweeper (correct password) is rejected by the primary''s pg_hba' $r 'pg_hba\.conf rejects connection for host "10\.81\.7\.\d+", user "session_sweeper"'

# =============================================================================================
Write-Host ''
Write-Host '== Replicas refuse writes, also for accounts with write grants =='
$r = PgSu 'pg-replica' "INSERT INTO public.customers (email, full_name) VALUES ('p3-ro@x.test', 'RO')"
Assert-Refused 'PG replica: even the superuser (local socket) cannot INSERT' $r 'cannot execute INSERT in a read-only transaction'
$probePw = New-LabPassword
[void](PgSu 'pg-primary' 'DROP ROLE IF EXISTS lab_rw_probe')
$r = Invoke-Docker @('exec', '-u', 'postgres', '-e', 'P3PW', (Id 'pg-primary'), 'bash', '-c', 'printf "%s" "\set pw ''$P3PW''
CREATE ROLE lab_rw_probe LOGIN PASSWORD :''pw'';
GRANT debug_ro TO lab_rw_probe;
GRANT USAGE ON SCHEMA public TO lab_rw_probe;
GRANT INSERT, UPDATE ON public.customers TO lab_rw_probe;" | psql -X -q -v ON_ERROR_STOP=1 -d app1') @{ P3PW = $probePw }
[void](Wait-OnReplica 'lab_rw_probe' '' (Get-Date))
$r2 = PgClient $netAccess ($pgReplicaConn + ' user=lab_rw_probe') "SELECT 'insert_priv=' || has_table_privilege('public.customers', 'INSERT')" $probePw
$r3 = PgClient $netAccess ($pgReplicaConn + ' user=lab_rw_probe') "INSERT INTO public.customers (email, full_name) VALUES ('p3-ro@x.test', 'RO')" $probePw
Write-Result (($r.Code -eq 0) -and ($r2.Out -match 'insert_priv=true') -and ($r3.Code -ne 0) -and ($r3.All -match 'cannot execute INSERT in a read-only transaction')) 'PG replica: a LAB-ONLY probe role WITH INSERT on public.customers is refused by the standby' ('probe created on primary: exit {0}; on replica {1}; INSERT: {2}' -f $r.Code, $r2.All, $r3.All)
[void](PgSu 'pg-primary' 'REVOKE ALL ON public.customers FROM lab_rw_probe; REVOKE USAGE ON SCHEMA public FROM lab_rw_probe; DROP ROLE lab_rw_probe')

[void](MaSu 'maria-primary' ("DROP USER IF EXISTS 'lab_rw_probe'@'{0}'" -f $accessMask))
$r = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', '-e', 'P3PW', (Id 'maria-primary'), 'bash', '-c',
    # SET PASSWORD FOR is binlogged as a hash; CREATE USER ... IDENTIFIED BY would put the probe's
    # password into the binary log in clear text (found by the binlog pattern scan in audit-checks.ps1).
    ('mariadb --protocol=socket -uroot -e "CREATE USER ''lab_rw_probe''@''{0}'' REQUIRE SSL ACCOUNT LOCK; SET PASSWORD FOR ''lab_rw_probe''@''{0}'' = PASSWORD(''$P3PW''); ALTER USER ''lab_rw_probe''@''{0}'' ACCOUNT UNLOCK; GRANT SELECT, INSERT, UPDATE ON app1.* TO ''lab_rw_probe''@''{0}''"' -f $accessMask)) @{ MYSQL_PWD = $mariaRootPw; P3PW = $probePw }
$deadline = (Get-Date).AddSeconds($ReplicaWaitSeconds)
while (((MaVal 'maria-replica' "SELECT COUNT(*) FROM mysql.user WHERE User = 'lab_rw_probe'") -ne '1') -and ((Get-Date) -lt $deadline)) { Start-Sleep -Milliseconds 300 }
$r2 = MaClient $netAccess 'maria-replica' 'lab_rw_probe' 'SHOW GRANTS' $probePw 'app1'
$r3 = MaClient $netAccess 'maria-replica' 'lab_rw_probe' 'UPDATE app1.customers SET full_name = full_name WHERE 1 = 0' $probePw 'app1'
Write-Result (($r.Code -eq 0) -and ($r2.Out -match 'INSERT, UPDATE ON `app1`') -and ($r3.Code -ne 0) -and ($r3.All -match 'running with the --read-only option')) 'Maria replica: a LAB-ONLY probe account WITH INSERT/UPDATE on app1.* is refused by read_only' ('grants on replica: {0}' -f (($r2.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'") + "`nUPDATE: " + $r3.All))
[void](MaSu 'maria-primary' ("DROP USER IF EXISTS 'lab_rw_probe'@'{0}'" -f $accessMask))
# Accounts with READ ONLY ADMIN (root has it through ALL PRIVILEGES) are not stopped by
# read_only. A statement that matches no row shows it without changing data.
$r = MaSu 'maria-replica' "UPDATE app1.customers SET full_name = full_name WHERE 1 = 0; SELECT CONCAT('root UPDATE accepted on the read_only replica, rows=', ROW_COUNT())"
$g = MaVal 'maria-replica' "SHOW GRANTS FOR 'root'@'localhost'"
Write-Result (($r.Code -eq 0) -and ($r.Out -match 'accepted')) 'Maria replica: KNOWN LIMIT: root (ALL PRIVILEGES includes READ ONLY ADMIN) bypasses read_only (root is socket-only)' ($r.All + "`n" + ($g -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'"))

# =============================================================================================
Write-Host ''
Write-Host '== Sweeper accounts: least privilege =='
$r = PgSu 'pg-primary' "SELECT 'super=' || rolsuper || ' createrole=' || rolcreaterole || ' replication=' || rolreplication || ' bypassrls=' || rolbypassrls || ' member_of=' || coalesce((SELECT string_agg(b.rolname, ',' ORDER BY b.rolname) FROM pg_auth_members m JOIN pg_roles b ON b.oid = m.roleid WHERE m.member = r.oid), '-') || ' read_all_stats=' || pg_has_role(r.oid, 'pg_read_all_stats', 'USAGE') || ' connect_app1=' || has_database_privilege(r.oid, 'app1', 'CONNECT') FROM pg_roles r WHERE rolname = 'session_sweeper'"
Assert-Works 'PG: session_sweeper is a member of pg_signal_backend only (no pg_read_all_stats), CONNECT on app1' $r 'super=false createrole=false replication=false bypassrls=false member_of=pg_signal_backend read_all_stats=false connect_app1=true'
$r = MaSu 'maria-primary' "SHOW GRANTS FOR 'session_sweeper'@'10.81.5.22'"
$gl = @($r.Out -split "`r?`n" | Where-Object { $_ -match '^GRANT' })
Write-Result (($gl.Count -eq 2) -and ($r.Out -match 'GRANT PROCESS, CONNECTION ADMIN ON \*\.\* TO `session_sweeper`@`10\.81\.5\.22`.*REQUIRE SSL') -and ($r.Out -match 'GRANT SELECT \(`User`\) ON `mysql`\.`user` TO')) 'Maria: session_sweeper has PROCESS, CONNECTION ADMIN and SELECT (User) ON mysql.user only, host 10.81.5.22, REQUIRE SSL' ($r.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'")
$r = Invoke-Docker @('exec', (Id 'maria-sweeper'), 'mariadb', '--defaults-extra-file=/tmp/sweeper.cnf', '-N', '-B', '-e', 'SELECT authentication_string FROM mysql.user LIMIT 1')
Assert-Refused 'Maria: the sweeper cannot read password hashes (column grant on the mysql.user view)' $r "SELECT command denied to user 'session_sweeper'@'10\.81\.5\.22' for column 'authentication_string'"
$r = Invoke-Docker @('exec', (Id 'maria-sweeper'), 'mariadb', '--defaults-extra-file=/tmp/sweeper.cnf', '-N', '-B', '-e', 'SELECT COUNT(*) FROM mysql.global_priv')
Assert-Refused 'Maria: the sweeper cannot read mysql.global_priv' $r 'SELECT command denied to user'
Assert-Refused 'sweeper containers cannot reach the primaries (pg-sweeper -> 10.81.7.10:5432)' (Invoke-Docker @('exec', (Id 'pg-sweeper'), 'bash', '-c', 'timeout 5 bash -c "exec 3<>/dev/tcp/10.81.7.10/5432" && echo connected')) $noRoute

# =============================================================================================
Write-Host ''
Write-Host '== Sweeper: open replica sessions end after revocation =='
# Long-lived controls for the whole sweeper section: a valid temp user session per engine,
# and the replication processes. None of them may be touched.
$keep = Connect-Bao 'alice'
$kp = Get-Creds $keep.Token 'app1-pg-ro'
$km = Get-Creds $keep.Token 'app1-maria-ro'
[void](Wait-OnReplica $kp.User $km.User $kp.At)
$keepPgC = Start-PgSession 'keep-pg' $kp 12
$keepMaC = Start-MariaSession 'keep-ma' $km 12
$keepPg = Get-PgPid $kp.User
$keepMa = Get-MaId $km.User
$walRecv = PgVal 'pg-replica' 'SELECT pid FROM pg_stat_wal_receiver'
$walSend = PgVal 'pg-primary' "SELECT pid FROM pg_stat_replication WHERE application_name = 'pg-replica'"
$maRepl = MaVal 'maria-replica' "SELECT GROUP_CONCAT(ID ORDER BY ID) FROM information_schema.PROCESSLIST WHERE USER = 'system user' AND COMMAND IN ('Slave_IO', 'Slave_SQL')"
$maDump = MaVal 'maria-primary' "SELECT GROUP_CONCAT(ID) FROM information_schema.PROCESSLIST WHERE COMMAND LIKE 'Binlog Dump%'"
$baoPg = PgVal 'pg-primary' "SELECT coalesce(string_agg(pid::text, ',' ORDER BY pid), '-') FROM pg_stat_activity WHERE usename = 'bao_admin'"
$appPg = PgVal 'pg-primary' "SELECT coalesce(string_agg(pid::text, ',' ORDER BY pid), '-') FROM pg_stat_activity WHERE usename = 'app1_runtime'"
Note ('controls: kept sessions pg pid {0} ({1}), maria id {2} ({3}); walreceiver pid {4}; walsender pid {5}; maria replica threads {6}; primary binlog dump {7}; bao_admin pids {8}; app1_runtime pids {9}' -f $keepPg, $kp.User, $keepMa, $km.User, $walRecv, $walSend, $maRepl, $maDump, $baoPg, $appPg)
Write-Result (($keepPg -gt 0) -and ($keepMa -gt 0)) 'control: a valid (not revoked) temp session is open on each replica' ''

$tok = Connect-Bao 'alice'
$vp = Get-Creds $tok.Token 'app1-pg-ro'
$vm = Get-Creds $tok.Token 'app1-maria-ro'
[void](Wait-OnReplica $vp.User $vm.User $vp.At)
$oidRevoke = PgVal 'pg-primary' ("SELECT oid FROM pg_roles WHERE rolname = '{0}'" -f $vp.User)
$cPg = Start-PgSession 'rev-pg' $vp
$cMa = Start-MariaSession 'rev-ma' $vm
$pPid = Get-PgPid $vp.User
$mId = Get-MaId $vm.User
Write-Result (($pPid -gt 0) -and ($mId -gt 0)) 'control: an open session for each temp user on the replicas before revocation' ('pg pid {0} ({1}, oid {2}); maria id {3} ({4})' -f $pPid, $vp.User, $oidRevoke, $mId, $vm.User)
$t0 = Get-Date
$r1 = BaoRoot @('lease', 'revoke', $vp.Lease)
$r2 = BaoRoot @('lease', 'revoke', $vm.Lease)
Write-Result (($r1.Code -eq 0) -and ($r2.Code -eq 0)) 'bao lease revoke for both leases' ('{0}; {1}' -f $r1.All, $r2.All)
$g = Wait-SessionsGone $pPid $mId $t0 ($bound + 15)
$dropAt = PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $vp.User)
$swPg = Get-SweeperLog 'pg-sweeper'
$swMa = Get-SweeperLog 'maria-sweeper'
$lp = Get-Logs $cPg; $lm = Get-Logs $cMa
$ok = ($g.Pg -ge 0) -and ($g.Pg -le $bound) -and ($swPg -match ('action=terminated pid={0} usesysid={1} role=- reason=role-dropped' -f $pPid, $oidRevoke)) -and ($lp -match 'terminating connection due to administrator command') -and ($lp -notmatch 'STILL ALIVE')
Write-Result $ok ('PG: the replica session ended {0} s after "bao lease revoke" (limit {1} s), killed by the sweeper' -f $g.Pg, $bound) (($swPg -split "`n" | Where-Object { $_ -match ('pid=' + $pPid + ' ') }) -join "`n")
if ($MariaTempUsersOnReplica) {
    Note-Altered 'the MariaDB session is ended by KILL USER in OpenBao''s revocation statement, which runs on the replica itself; the sweeper must find nothing to kill for it'
    $swLine = (($swMa -split "`n" | Where-Object { $_ -match ('id=' + $mId + ' ') }) -join "`n")
    $ok = ($g.Maria -ge 0) -and ($g.Maria -le $bound) -and (-not $swLine) -and ($lm -match 'Lost connection|server has gone away|Connection was killed') -and ($lm -notmatch 'STILL ALIVE')
    Write-Result $ok ('Maria: the replica session ended {0} s after "bao lease revoke" (limit {1} s), killed by the revocation statement (no sweeper record)' -f $g.Maria, $bound) ('sweeper lines for id {0}: {1}; client saw: {2}' -f $mId, $(if ($swLine) { $swLine } else { 'none' }), (($lm -split "`n" | Select-Object -Last 2) -join ' '))
} else {
    $ok = ($g.Maria -ge 0) -and ($g.Maria -le $bound) -and ($swMa -match ('action=killed id={0} user={1} ' -f $mId, [regex]::Escape($vm.User))) -and ($lm -match 'Lost connection|server has gone away|Connection was killed') -and ($lm -notmatch 'STILL ALIVE')
    Write-Result $ok ('Maria: the replica session ended {0} s after "bao lease revoke" (limit {1} s), killed by the sweeper' -f $g.Maria, $bound) (($swMa -split "`n" | Where-Object { $_ -match ('id=' + $mId + ' ') }) -join "`n")
}
Add-Measure ('revoke -> replica session gone: pg {0} s, maria {1} s (interval {2} s)' -f $g.Pg, $g.Maria, $interval)
Assert-Refused 'PG replica: a new login with the revoked credentials fails' (PgClient $netAccess ($pgReplicaConn + ' user=' + $vp.User) 'SELECT 1' $vp.Password) ('pg_hba\.conf rejects connection .*user "' + [regex]::Escape($vp.User) + '"|password authentication failed')
Assert-Refused 'Maria replica: a new login with the revoked credentials fails' (MaClient $netAccess 'maria-replica' $vm.User 'SELECT 1' $vm.Password) ("Access denied for user '" + [regex]::Escape($vm.User) + "'")

# =============================================================================================
Write-Host ''
Write-Host '== Sweeper: open replica sessions end after TTL expiry (no revoke) =='
$etok = Connect-Bao 'alice'
$ep = Get-Creds $etok.Token 'app1-pg-ro'
$em = Get-Creds $etok.Token 'app1-maria-ro'
[void](Wait-OnReplica $ep.User $em.User $ep.At)
$oidExpire = PgVal 'pg-primary' ("SELECT oid FROM pg_roles WHERE rolname = '{0}'" -f $ep.User)
$cPg = Start-PgSession 'exp-pg' $ep
$cMa = Start-MariaSession 'exp-ma' $em
$pPid = Get-PgPid $ep.User
$mId = Get-MaId $em.User
$exp = @{}
foreach ($c in @($ep, $em)) {
    $r = Invoke-Bao @('lease', 'renew', '-format=json', '-increment=20s', $c.Lease) $etok.Token
    $lk = ConvertFrom-JsonOrNull (BaoRoot @('lease', 'lookup', '-format=json', $c.Lease)).Out
    # expire_time comes from OpenBao's clock (Docker VM); convert to host time.
    $exp[$c.User] = [DateTime]::Parse(([string]$lk.data.expire_time -replace '(\.\d{7})\d+', '$1')).ToLocalTime().AddSeconds(-$skew)
}
$vu = PgVal 'pg-replica' ("SELECT rolvaliduntil FROM pg_roles WHERE rolname = '{0}'" -f $ep.User)
Write-Result (($pPid -gt 0) -and ($mId -gt 0)) 'sessions open; both leases renewed with -increment=20s' ('pg pid {0} lease expires {1:HH:mm:ss}; VALID UNTIL on the replica now {2}; maria id {3} lease expires {4:HH:mm:ss}' -f $pPid, $exp[$ep.User], $vu, $mId, $exp[$em.User])
$expAt = $exp[$ep.User]; if ($exp[$em.User] -gt $expAt) { $expAt = $exp[$em.User] }
$g = Wait-SessionsGone $pPid $mId $exp[$ep.User] ([int](($expAt - $exp[$ep.User]).TotalSeconds) + $bound + 30)
$gm = $g.Maria
if ($gm -ge 0) { $gm = [Math]::Round($gm - ($exp[$em.User] - $exp[$ep.User]).TotalSeconds, 1) }
$swPg = Get-SweeperLog 'pg-sweeper'
$swMa = Get-SweeperLog 'maria-sweeper'
$pgLine = (($swPg -split "`n" | Where-Object { $_ -match ('pid=' + $pPid + ' ') }) -join "`n")
$ok = ($g.Pg -ge 0) -and ($g.Pg -le $bound) -and ($pgLine -match 'action=terminated')
Write-Result $ok ('PG: the replica session ended {0} s after the lease expiry time (limit {1} s)' -f $g.Pg, $bound) $pgLine
$maLine = (($swMa -split "`n" | Where-Object { $_ -match ('id=' + $mId + ' ') }) -join "`n")
if ($MariaTempUsersOnReplica) {
    Note-Altered 'at expiry OpenBao runs the revocation statement on the replica, so KILL USER ends the MariaDB session; no sweeper record is expected'
    $ok = ($gm -ge 0) -and ($gm -le $bound) -and (-not $maLine)
    Write-Result $ok ('Maria: the replica session ended {0} s after the lease expiry time (limit {1} s), by the revocation statement' -f $gm, $bound) ('sweeper lines for id {0}: {1}' -f $mId, $(if ($maLine) { $maLine } else { 'none' }))
} else {
    $ok = ($gm -ge 0) -and ($gm -le $bound) -and ($maLine -match 'action=killed')
    Write-Result $ok ('Maria: the replica session ended {0} s after the lease expiry time (limit {1} s)' -f $gm, $bound) $maLine
}
Add-Measure ('TTL expiry -> replica session gone: pg {0} s, maria {1} s (pg reason: {2})' -f $g.Pg, $gm, ([regex]::Match($pgLine, 'reason=\S+').Value))
$a = PgVal 'pg-primary' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $ep.User); $b = MaVal $maTempHost ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $em.User)
if ($MariaTempUsersOnReplica) { Note-Altered 'the expired MariaDB user is looked for on maria-replica, where it lived' }
Write-Result (($a -eq '0') -and ($b -eq '0')) ('OpenBao dropped both expired users (pg-primary, {0})' -f $maTempHost) ('pg rows {0}, maria rows {1}' -f $a, $b)

# =============================================================================================
Write-Host ''
Write-Host '== Sweeper, PostgreSQL VALID UNTIL branch (lease expired, role not dropped) =='
# Simulates a lease whose revocation did not happen (OpenBao down, irrevocable lease): the role
# still exists everywhere, only its VALID UNTIL has passed.
$vtok = Connect-Bao 'alice'
$xp = Get-Creds $vtok.Token 'app1-pg-ro'
[void](Wait-OnReplica $xp.User '' $xp.At)
$cPg = Start-PgSession 'vu-pg' $xp
$pPid = Get-PgPid $xp.User
$t0 = Get-Date
[void](PgSu 'pg-primary' ("ALTER ROLE ""{0}"" VALID UNTIL '2000-01-01 00:00:00+00'" -f $xp.User))
$g = Wait-SessionsGone $pPid 0 $t0 ($bound + 15)
$still = PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $xp.User)
$line = ((Get-SweeperLog 'pg-sweeper') -split "`n" | Where-Object { $_ -match ('pid=' + $pPid + ' ') }) -join "`n"
$ok = ($g.Pg -ge 0) -and ($g.Pg -le $bound) -and ($still -eq '1') -and ($line -match ('role=' + [regex]::Escape($xp.User) + ' reason=valid-until-passed'))
Write-Result $ok ('PG: a session of an existing v- role whose VALID UNTIL has passed was ended {0} s later (role still present on the replica: {1})' -f $g.Pg, $still) $line
[void](BaoRoot @('lease', 'revoke', $xp.Lease))

# =============================================================================================
Write-Host ''
Write-Host '== Control: with the sweepers stopped, sessions survive revocation =='
$r = Compose @('stop', 'pg-sweeper', 'maria-sweeper')
Write-Result ($r.Code -eq 0) 'sweepers stopped' $r.All
$ctok = Connect-Bao 'alice'
$sp = Get-Creds $ctok.Token 'app1-pg-ro'
$sm = Get-Creds $ctok.Token 'app1-maria-ro'
[void](Wait-OnReplica $sp.User $sm.User $sp.At)
$oidCtl = PgVal 'pg-primary' ("SELECT oid FROM pg_roles WHERE rolname = '{0}'" -f $sp.User)
$cPg = Start-PgSession 'ctl-pg' $sp
$cMa = Start-MariaSession 'ctl-ma' $sm
$pPid = Get-PgPid $sp.User
$mId = Get-MaId $sm.User
$t0 = Get-Date
[void](BaoRoot @('lease', 'revoke', $sp.Lease))
[void](BaoRoot @('lease', 'revoke', $sm.Lease))
if ($MariaTempUsersOnReplica) { $gNoSw = Wait-SessionsGone 0 $mId $t0 30 }
$lsn = PgVal 'pg-primary' 'SELECT pg_current_wal_lsn()'
$deadline = $t0.AddSeconds($ReplicaWaitSeconds)
do { Start-Sleep -Milliseconds 300; $gone = (PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE oid = {0}" -f $oidCtl)) -eq '0' } while ((-not $gone) -and ((Get-Date) -lt $deadline))
$dropPg = [Math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
$replayed = PgVal 'pg-replica' ("SELECT pg_last_wal_replay_lsn() >= '{0}'::pg_lsn" -f $lsn)
$deadline = $t0.AddSeconds($ReplicaWaitSeconds)
do { Start-Sleep -Milliseconds 300; $goneM = (MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $sm.User)) -eq '0' } while ((-not $goneM) -and ((Get-Date) -lt $deadline))
$dropMa = [Math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
Add-Measure ('revoke -> user dropped on replica (replication of DROP): pg {0} s, maria {1} s' -f $dropPg, $dropMa)
Write-Result ($gone -and ($replayed -eq 't')) ('PG: DROP ROLE replayed on the standby although a session of that role is open (role gone after {0} s; replay not blocked: replay LSN >= primary LSN after the drop = {1})' -f $dropPg, $replayed) ''
if ($MariaTempUsersOnReplica) {
    Note-Altered 'nothing is replicated for MariaDB temp users: OpenBao''s DROP USER runs on the replica itself, and KILL USER before it ends the session even with the sweeper stopped'
    Write-Result $goneM ('Maria: DROP USER ran on the replica itself (user gone {0} s after revoke)' -f $dropMa) ''
    $okNs = ($gNoSw.Maria -ge 0) -and ($gNoSw.Maria -le 10)
    Write-Result $okNs ('Maria: with the sweeper STOPPED the open replica session ended {0} s after "bao lease revoke" (KILL USER in the revocation statement; limit 10 s)' -f $gNoSw.Maria) ''
    Add-Measure ('revoke -> MariaDB replica session gone with the sweeper stopped: {0} s' -f $gNoSw.Maria)
} else {
    Write-Result $goneM ('Maria: DROP USER replicated although a session of that user is open (gone after {0} s)' -f $dropMa) ''
}
Start-Sleep -Seconds $bound
$r = PgSu 'pg-replica' ("SELECT 'pid=' || pid || ' usesysid=' || usesysid || ' usename=' || coalesce(usename, 'NULL') || ' role_exists=' || EXISTS (SELECT 1 FROM pg_roles WHERE oid = usesysid) || ' state=' || state FROM pg_stat_activity WHERE pid = {0}" -f $pPid)
Write-Result (($r.Out -match ('pid={0} usesysid={1} usename=NULL role_exists=false' -f $pPid, $oidCtl))) ('PG: without the sweeper the session is still open {0} s after revocation; its usename is NULL, only usesysid identifies it' -f [int]((Get-Date) - $t0).TotalSeconds) $r.All
$alive = Test-MaIdAlive $mId
$r = MaSu 'maria-replica' ("SELECT CONCAT('id=', ID, ' user=', USER, ' account_exists=', EXISTS (SELECT 1 FROM mysql.user u WHERE u.User = p.USER), ' command=', COMMAND) FROM information_schema.PROCESSLIST p WHERE ID = {0}" -f $mId)
if ($MariaTempUsersOnReplica) {
    Note-Altered 'the MariaDB control case (session survives revocation without the sweeper) does not apply: KILL USER runs on the replica; the session must be gone'
    Write-Result (-not $alive) ('Maria: {0} s after revocation the session is still gone, sweeper stopped' -f [int]((Get-Date) - $t0).TotalSeconds) ('processlist row: ' + $(if ($r.Out) { $r.Out } else { 'none' }))
} else {
    Write-Result ($alive -and ($r.Out -match 'account_exists=0')) ('Maria: without the sweeper the session is still open {0} s after revocation, its account is gone' -f [int]((Get-Date) - $t0).TotalSeconds) $r.All
}
$t1 = Get-Date
$r = Compose @('start', 'pg-sweeper', 'maria-sweeper')
if ($MariaTempUsersOnReplica) {
    $g = Wait-SessionsGone $pPid 0 $t1 ($bound + 15)
    Note-Altered 'only the PostgreSQL session was orphaned; the MariaDB one ended at revocation'
    Write-Result (($g.Pg -ge 0) -and ($g.Pg -le $bound)) ('after "docker compose start" of the sweepers the orphaned PG session ended ({0} s after the start command)' -f $g.Pg) ('start: ' + $r.All)
    Add-Measure ('sweeper start -> orphaned sessions gone: pg {0} s (maria: none orphaned)' -f $g.Pg)
} else {
    $g = Wait-SessionsGone $pPid $mId $t1 ($bound + 15)
    Write-Result (($g.Pg -ge 0) -and ($g.Pg -le $bound) -and ($g.Maria -ge 0) -and ($g.Maria -le $bound)) ('after "docker compose start" of the sweepers both sessions ended (pg {0} s, maria {1} s after the start command)' -f $g.Pg, $g.Maria) ('start: ' + $r.All)
    Add-Measure ('sweeper start -> orphaned sessions gone: pg {0} s, maria {1} s' -f $g.Pg, $g.Maria)
}

# =============================================================================================
Write-Host ''
Write-Host '== The sweepers left everything else alone =='
$walRecv2 = PgVal 'pg-replica' 'SELECT pid FROM pg_stat_wal_receiver'
$walSend2 = PgVal 'pg-primary' "SELECT pid FROM pg_stat_replication WHERE application_name = 'pg-replica'"
$maRepl2 = MaVal 'maria-replica' "SELECT GROUP_CONCAT(ID ORDER BY ID) FROM information_schema.PROCESSLIST WHERE USER = 'system user' AND COMMAND IN ('Slave_IO', 'Slave_SQL')"
$maDump2 = MaVal 'maria-primary' "SELECT GROUP_CONCAT(ID) FROM information_schema.PROCESSLIST WHERE COMMAND LIKE 'Binlog Dump%'"
$okKeep = (Test-PgPidAlive $keepPg) -and (Test-MaIdAlive $keepMa)
Write-Result $okKeep 'the valid temp sessions (one per engine, open through every sweep above) are still open' ('pg pid {0}, maria id {1}' -f $keepPg, $keepMa)
Write-Result (($walRecv -eq $walRecv2) -and ($walSend -eq $walSend2) -and ($walRecv -ne '')) 'PG replication untouched: same walreceiver pid on the replica and walsender pid on the primary' ('walreceiver {0} -> {1}; walsender {2} -> {3}' -f $walRecv, $walRecv2, $walSend, $walSend2)
Write-Result (($maRepl -eq $maRepl2) -and ($maRepl -ne '')) 'Maria replication threads on the replica untouched (same connection ids; ids before the MASTER_HOST test above are not compared)' ('replica IO/SQL threads {0} -> {1}; primary binlog dump {2} -> {3}' -f $maRepl, $maRepl2, $maDump, $maDump2)
# Every kill the sweepers logged during this run must be one of this run's revoked/expired users.
$swPg = Get-SweeperLog 'pg-sweeper'; $swMa = Get-SweeperLog 'maria-sweeper'
$myOids = @($oidRevoke, $oidExpire, $oidCtl)
$badPg = @(($swPg -split "`n") | Where-Object { $_ -match 'action=terminated' } | Where-Object { ($_ -match 'usesysid=(\d+)') -and ($myOids -notcontains $Matches[1]) -and ($_ -notmatch ('role=' + [regex]::Escape($xp.User))) })
$myMa = @($vm.User, $em.User, $sm.User)
$badMa = @(($swMa -split "`n") | Where-Object { $_ -match 'action=killed' } | Where-Object { ($_ -match 'user=(\S+)') -and ($myMa -notcontains $Matches[1]) })
$allPg = @(($swPg -split "`n") | Where-Object { $_ -match 'action=terminated' }).Count
$allMa = @(($swMa -split "`n") | Where-Object { $_ -match 'action=killed' }).Count
Write-Result (($badPg.Count -eq 0) -and ($badMa.Count -eq 0) -and ($swPg -notmatch 'role=(session_sweeper|replicator|bao_admin|app1_runtime|app1_migrator|postgres) ') -and ($swMa -notmatch 'user=(session_sweeper|replicator|bao_admin|app1_runtime|app1_migrator|root|system) ')) 'sweeper logs (since container start) name only this run''s revoked/expired temp users: no application, replication, OpenBao, superuser or own session' ('pg kill lines {0}, maria kill lines {1}; unexpected: {2}' -f $allPg, $allMa, (($badPg + $badMa) -join ' | '))
Note ('primary sessions (sweepers cannot reach the primaries at all): bao_admin pids {0} -> {1}; app1_runtime pids {2} -> {3}' -f $baoPg, (PgVal 'pg-primary' "SELECT coalesce(string_agg(pid::text, ',' ORDER BY pid), '-') FROM pg_stat_activity WHERE usename = 'bao_admin'"), $appPg, (PgVal 'pg-primary' "SELECT coalesce(string_agg(pid::text, ',' ORDER BY pid), '-') FROM pg_stat_activity WHERE usename = 'app1_runtime'"))
# Sweeper session visibility without pg_read_all_stats (why the query does not use backend_type).
$r = Invoke-Docker @('exec', '-e', 'PGPASSFILE=/tmp/pgpass', (Id 'pg-sweeper'), 'psql', 'host=pg-replica dbname=app1 user=session_sweeper sslmode=verify-full sslrootcert=/pki-ca/ca.crt', '-X', '-At', '-c',
    ("SELECT 'pid=' || pid || ' usesysid=' || coalesce(usesysid::text, 'NULL') || ' backend_type=' || coalesce(backend_type, 'NULL') || ' backend_start=' || coalesce(backend_start::text, 'NULL') || ' query=' || coalesce(query, 'NULL') FROM pg_stat_activity WHERE pid = {0}" -f $keepPg))
Assert-Works 'PG: as session_sweeper, another role''s session shows pid and usesysid but backend_type/backend_start NULL (so they cannot be used without pg_read_all_stats)' $r ('pid={0} usesysid=\d+ backend_type=NULL backend_start=NULL query=<insufficient privilege>' -f $keepPg)

# =============================================================================================
Write-Host ''
Write-Host '== Revoke while the replicas are stopped =='
$dtok = Connect-Bao 'alice'
$dp = Get-Creds $dtok.Token 'app1-pg-ro'
$dm = Get-Creds $dtok.Token 'app1-maria-ro'
[void](Wait-OnReplica $dp.User $dm.User $dp.At)
$markerBefore = (Invoke-Docker @('exec', (Id 'pg-replica'), 'cat', '/var/lib/postgresql/data/replica-bootstrap.done')).Out.Trim()
$r = Compose @('stop', 'pg-replica', 'maria-replica')
Write-Result ($r.Code -eq 0) ('replicas stopped while {0} and {1} exist on them' -f $dp.User, $dm.User) $r.All
[void](BaoRoot @('lease', 'revoke', $dp.Lease))
[void](BaoRoot @('lease', 'revoke', $dm.Lease))
$a = PgVal 'pg-primary' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $dp.User)
if ($MariaTempUsersOnReplica) {
    Note-Altered 'the MariaDB user exists only on the stopped replica: OpenBao cannot run the revocation, keeps the lease and retries with backoff (it is not dropped "on the primary")'
    $lk = BaoRoot @('lease', 'lookup', '-format=json', $dm.Lease)
    $lo = ConvertFrom-JsonOrNull $lk.Out
    Write-Result (($a -eq '0') -and ($lk.Code -eq 0)) 'revoked while the replicas were down: PG user dropped on the primary; the MariaDB lease is still known to OpenBao (revocation queued and retried)' ('pg rows on pg-primary {0}; maria lease lookup exit {1}, ttl {2}, expire_time {3}' -f $a, $lk.Code, $lo.data.ttl, $lo.data.expire_time)
} else {
    $b = MaVal 'maria-primary' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $dm.User)
    Write-Result (($a -eq '0') -and ($b -eq '0')) 'revoked while the replicas were down: users dropped on the primaries' ('pg rows {0}, maria rows {1}' -f $a, $b)
}
$t0 = Get-Date
$r = Compose @('start', 'pg-replica', 'maria-replica')
$deadline = $t0.AddSeconds(180)
$hp = ''; $hm = ''
do { Start-Sleep -Seconds 2
    $hp = (Invoke-Docker @('inspect', '-f', '{{.State.Health.Status}}', (Id 'pg-replica'))).Out.Trim()
    $hm = (Invoke-Docker @('inspect', '-f', '{{.State.Health.Status}}', (Id 'maria-replica'))).Out.Trim()
} while ((($hp -ne 'healthy') -or ($hm -ne 'healthy')) -and ((Get-Date) -lt $deadline))
$up = [int]((Get-Date) - $t0).TotalSeconds
$a = PgVal 'pg-replica' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $dp.User); $b = MaVal 'maria-replica' ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $dm.User)
if ($MariaTempUsersOnReplica) {
    # Without the revocation backstops the revoked user would still exist on the restarted replica
    # until OpenBao's next retry, and a login in that gap WORKED (measured 31 to 57 s).
    # maria-replica's init_file drops every local v- user at each start
    # before it accepts connections, and the lease is completed by OpenBao's retry or by the lease
    # reconciler. The order (purge before the first connection) is proven by
    # tests\revocation-checks.ps1.
    Note-Altered 'the revoked MariaDB user must already be gone when the replica is healthy (startup purge in the replica''s init_file, before the listener opens; without it a login gap of 31 to 57 s was measured). Then the lease must disappear (OpenBao''s retry or the lease reconciler)'
    $gapLogin = 'not tried (already gone)'
    if ($b -ne '0') { $gl = MaClient $netAccess 'maria-replica' $dm.User 'SELECT 1' $dm.Password; if ($gl.Code -eq 0) { $gapLogin = 'LOGIN WORKED' } else { $gapLogin = 'refused: ' + $gl.All } }
    Write-Result (($hp -eq 'healthy') -and ($hm -eq 'healthy') -and ($a -eq '0') -and ($b -eq '0')) ('replicas started again, healthy after {0} s; the revoked PG user is gone there, and the revoked MariaDB user was already purged at the replica''s start' -f $up) ('pg-replica {0}, maria-replica {1}; pg rows {2}; maria rows right after healthy {3}; login with the revoked MariaDB credentials: {4}' -f $hp, $hm, $a, $b, $gapLogin)
    $gone = $null
    $deadline = $t0.AddSeconds($RevokeRetryWaitSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((BaoRoot @('lease', 'lookup', $dm.Lease)).Code -ne 0) { $gone = Get-Date; break }
        Start-Sleep -Seconds 2
    }
    $gs = -1; if ($gone) { $gs = [int]($gone - $t0).TotalSeconds }
    Write-Result ($null -ne $gone) ('Maria: the queued revocation completed {0} s after the start command (OpenBao''s retry or the lease reconciler; bound {1} s); the lease is gone' -f $gs, $RevokeRetryWaitSeconds) ''
    Add-Measure ('revoke while maria-replica down: replica healthy {0} s after start, revoked user already purged at start (rows {1}); lease gone {2} s after start; login in the former gap: {3}' -f $up, $b, $gs, $gapLogin)
} else {
    Write-Result (($hp -eq 'healthy') -and ($hm -eq 'healthy') -and ($a -eq '0') -and ($b -eq '0')) ('replicas started again, healthy after {0} s, the revoked users are gone there too' -f $up) ('pg-replica {0}, maria-replica {1}; pg rows {2}, maria rows {3}' -f $hp, $hm, $a, $b)
}
Assert-Refused 'PG replica: the user revoked during the outage cannot log in' (PgClient $netAccess ($pgReplicaConn + ' user=' + $dp.User) 'SELECT 1' $dp.Password) ('pg_hba\.conf rejects connection .*user "' + [regex]::Escape($dp.User) + '"|password authentication failed')
$maDeniedRe = "Access denied for user '" + [regex]::Escape($dm.User) + "'"
if ($MariaTempUsersOnReplica) {
    # After the startup purge no v- account for the access network may be left at all; MariaDB then
    # refuses before authentication with 1130 "Host ... is not allowed to connect" (no account
    # matches the client host) instead of 1045 "Access denied". Both are a refusal of the user.
    Note-Altered 'the refusal may also be 1130 "Host ... is not allowed to connect": after the startup purge no account matches the client''s access-network address'
    $maDeniedRe = $maDeniedRe + "|Host '10\.81\.5\.\d+' is not allowed to connect"
}
Assert-Refused 'Maria replica: the user revoked during the outage cannot log in' (MaClient $netAccess 'maria-replica' $dm.User 'SELECT 1' $dm.Password) $maDeniedRe
$markerAfter = (Invoke-Docker @('exec', (Id 'pg-replica'), 'cat', '/var/lib/postgresql/data/replica-bootstrap.done')).Out.Trim()
$lg = (Invoke-Docker @('logs', '--since', $t0.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), (Id 'pg-replica'))).All
Write-Result (($markerBefore -ne '') -and ($markerBefore -eq $markerAfter) -and ($lg -match 'already bootstrapped') -and ($lg -notmatch 'pg_basebackup from')) 'PG replica restart is idempotent: no new clone, it resumed streaming from its slot' ('marker: {0}' -f $markerAfter)
$lg = (Invoke-Docker @('logs', '--since', $t0.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), (Id 'maria-replica'))).All
$x = Get-ReplStatus
Write-Result (($lg -notmatch '20-replica-seed') -and ($x['Slave_IO_Running'] -eq 'Yes') -and ($x['Slave_SQL_Running'] -eq 'Yes') -and ($x['Using_Gtid'] -eq 'Slave_Pos')) 'Maria replica restart: no new seed, replication resumed from its GTID position' ('Gtid_IO_Pos=' + $x['Gtid_IO_Pos'])
$swUp = $false
$deadline = (Get-Date).AddSeconds(30)
do { Start-Sleep -Seconds 2; $swUp = ((Get-SweeperLog 'pg-sweeper') -split "`n" | Select-Object -Last 1) -notmatch 'action=error' -and (((Get-SweeperLog 'maria-sweeper') -split "`n" | Select-Object -Last 1) -notmatch 'action=error') } while ((-not $swUp) -and ((Get-Date) -lt $deadline))
Write-Result $swUp 'sweepers reconnected to the restarted replicas (last log line is not an error)' ((((Get-SweeperLog 'pg-sweeper') -split "`n" | Select-Object -Last 2) + ((Get-SweeperLog 'maria-sweeper') -split "`n" | Select-Object -Last 2)) -join "`n")

# =============================================================================================
Write-Host ''
Write-Host '== Optional: report-only stale-user detector on the primaries (scripts\stale-users.ps1) =='
$stale = Join-Path $LabRoot 'scripts\stale-users.ps1'
$staleArgs = @()
if ($MariaTempUsersOnReplica) {
    Note-Altered 'the MariaDB part of the detector reads maria-replica (-MariaHost maria-replica), where the temp users live'
    $staleArgs = @('-MariaHost', 'maria-replica')
    # The replica restart above purged the kept MariaDB user (startup purge drops every local v-
    # user, also those of valid leases), so the "kept" MariaDB user is issued again here.
    Note-Altered 'the kept MariaDB user was dropped by the replica restart above (startup purge, by design); a new one is issued for the detector checks'
    $km = Get-Creds $keep.Token 'app1-maria-ro'
}
$out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $stale -ComposeFile $LabComposeFile -Project $LabProject @staleArgs | Out-String); $code = $LASTEXITCODE
Write-Result (($code -eq 0) -and ($out -match '0 stale')) 'with the real limits (max_ttl 4h + 15 min) none of this run''s fresh users is reported' ('exit {0}: {1}' -f $code, $out)
# Limit 0 + margin 0: every existing v- user is "stale"; the kept users must be listed and stay.
$out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $stale -ComposeFile $LabComposeFile -Project $LabProject -MaxTtlMinutes 0 -MarginMinutes 0 @staleArgs | Out-String); $code = $LASTEXITCODE
$a = PgVal 'pg-primary' ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $kp.User); $b = MaVal $maTempHost ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $km.User)
Write-Result (($code -eq 3) -and ($out -match ('STALE engine=postgresql role=' + [regex]::Escape($kp.User) + ' created')) -and ($out -match ('STALE engine=mariadb account=' + [regex]::Escape($km.User) + '@')) -and ($a -eq '1') -and ($b -eq '1')) 'with limit 0 it reports existing v- users (parsed creation time) and drops nothing' ('exit {0}: {1}after the report: pg rows {2}, maria rows {3}' -f $code, $out, $a, $b)
# PostgreSQL VALID UNTIL branch: an expired-but-not-dropped role (failed revocation).
[void](PgSu 'pg-primary' ("ALTER ROLE ""{0}"" VALID UNTIL '2000-01-01 00:00:00+00'" -f $kp.User))
$out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $stale -ComposeFile $LabComposeFile -Project $LabProject @staleArgs | Out-String); $code = $LASTEXITCODE
Write-Result (($code -eq 3) -and ($out -match ('role=' + [regex]::Escape($kp.User) + ' VALID UNTIL 2000-01-01T00:00:00Z passed')) -and ($out -match '1 stale')) 'with the real limits it reports a role whose VALID UNTIL has passed (revocation that never happened)' ('exit {0}: {1}' -f $code, $out)

# =============================================================================================
# Cleanup: revoke every token this run created (and with it all leases), remove clients.
foreach ($tk in $script:Tokens) { [void](Invoke-Bao @('token', 'revoke', '-self') $tk) }
foreach ($c in $script:Containers) { [void](Invoke-Docker @('rm', '-f', $c)) }
Start-Sleep -Seconds 3
$left = PgVal 'pg-primary' "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-jwt-%'"
$leftM = MaVal $maTempHost "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'v-jwt-%'"
Write-Host ''
Write-Host ('cleanup: test tokens revoked, client containers removed; remaining v-jwt-* users: pg {0} (pg-primary), maria {1} ({2})' -f $left, $leftM, $maTempHost)
Write-Host ''
Write-Host 'Measurements:'
foreach ($m in $script:Measure) { Write-Host ('  ' + $m) }
Write-Host ''
Write-Host ('Summary: {0} passed, {1} failed' -f $script:Pass, $script:Fail)
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
