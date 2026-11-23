[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # How long to wait for the stack (migrations, Keycloak, replica clone/seed) after "up -d".
    [int]$WaitSeconds = 420,
    # Phase 5 runs this script against its own stack (scripts\phase5-setup.ps1). The defaults are
    # the phase 4 stack. The reconciler credentials are secrets\<BaoSecretPrefix>_reconciler_*.
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype-phase4',
    [string]$BaoSecretPrefix = 'openbao_phase4'
)

# Phase 4 setup: takes a fresh "docker compose -f compose.phase4.yaml up -d --build" to a fully
# configured state. Idempotent: safe to run again at any time (it also unseals OpenBao).
#   1. scripts\phase3-setup.ps1 against the phase 4 stack (which runs phase2-setup.ps1 first):
#      database access setup on the primaries, OpenBao init/unseal/configuration, sweeper
#      accounts, replicas caught up. The phase 4 OpenBao instance keeps its unseal key and root
#      token in secrets\openbao_phase4_unseal_key / _root_token (LAB-ONLY).
#   2. MariaDB: hash-only root rotation of bao_admin, and temp users on the REPLICA only (design
#      4.E, binlog password leak): OpenBao's local replica account bao_replica_admin
#      (config/mariadb/phase4/replica-bao-account.sh), the OpenBao connection
#      app1-maria-replica (sql_log_bin=0 on every session) and the role app1-maria-ro pointed at it
#   3. per-role pgAudit settings on pg-primary (config/postgres/phase4-audit-roles.sh; they
#      replicate), now that session_sweeper exists
#   4. revocation backstops (design 5.4): checks maria-replica's expiry backstop event (from its
#      init_file) and sets up the OpenBao lease reconciler (AppRole lease-reconciler, policy
#      config/openbao/lease-reconciler.hcl, credentials in secrets\openbao_phase4_reconciler_*),
#      and checks the PostgreSQL replica deny list (watcher running in pg-replica, descriptor
#      volume owned by the reconciler's uid, pg_hba line 2 loaded)
#   5. shows that the audit plugins are loaded on all four servers and that the shipper writes
#      the store
# The MariaDB passwords set on the primary by the init and setup scripts use the phase 4
# variants in config/mariadb/phase4/ (SET PASSWORD FOR: the binlog holds only hashes).
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compose = if ($ComposeFile) { (Resolve-Path $ComposeFile).Path } else { Join-Path $root 'compose.phase4.yaml' }
$project = $Project
$baoPrefix = $BaoSecretPrefix
$composeName = Split-Path -Leaf $compose

# Phase 4: hash-only root rotation for app1-maria from the very first rotate-root, and the role
# app1-maria-ro is left to step 2 below (phase2-setup.ps1 does not point it at the primary).
$MariaRootRotationPhase4 = "SET PASSWORD = PASSWORD('{{password}}')"
& (Join-Path $PSScriptRoot 'phase3-setup.ps1') -TimeoutSeconds $TimeoutSeconds -WaitSeconds $WaitSeconds -ComposeFile $compose -Project $project -BaoSecretPrefix $baoPrefix -MariaTempUsersOnReplica -MariaRootRotationStatement $MariaRootRotationPhase4

$P2ComposeFile = $compose
$P2Project = $project
$P2BaoSecretPrefix = $baoPrefix
. (Join-Path $PSScriptRoot 'phase2-lib.ps1')

function Step { param([string]$Text) Write-Host ''; Write-Host ('== ' + $Text + ' ==') }
function Assert-Ok {
    param($Result, [string]$What)
    if ($Result.Code -ne 0) { throw ('{0} failed (exit {1}): {2}' -f $What, $Result.Code, $Result.All) }
    return $Result
}

# ---------------------------------------------------------------------------------------------
Step 'MariaDB root rotation without the clear-text password in the binary log'
# Measured in phase 4: MariaDB writes CREATE USER / ALTER USER ... IDENTIFIED BY '<password>'
# to the binary log VERBATIM (server_audit masks it, the binlog does not), and the replica
# copies it into its relay log. For the long-lived bao_admin password that is the worst case:
# the phase 2/3 root_rotation_statements (ALTER USER ... IDENTIFIED BY) put every rotated
# bao_admin password into the binlog in clear text. SET PASSWORD = PASSWORD('...') for the
# CURRENT user is binlogged as "SET PASSWORD FOR ...='*<hash>'" and needs no extra privilege.
# Phase 2/3 keep their statement. Phase 4 passes the SET PASSWORD form to phase2-setup.ps1, so
# it is in place before the first rotate-root; it is set here again and rotated once more (also
# on stacks set up before that), so the current bao_admin password is in no log in clear text.
# Temp users cannot use SET PASSWORD FOR (bao_admin would need UPDATE on mysql.*); they are
# created on the replica instead, with sql_log_bin = 0 (next step).
$baoRoot = Read-P2Secret $P2BaoRootTokenName
Assert-Ok (Invoke-Bao @('write', 'database/config/app1-maria', ('root_rotation_statements=' + $MariaRootRotationPhase4), 'allowed_roles=lab-probe-maria-basetable,lab-probe-maria-masked') $baoRoot) 'set root_rotation_statements' | Out-Null
Write-Host ('database/config/app1-maria: root_rotation_statements={0}; allowed_roles: the LAB-ONLY probe roles only (app1-maria-ro uses app1-maria-replica)' -f $MariaRootRotationPhase4)
Assert-Ok (Invoke-Bao @('write', '-force', 'database/rotate-root/app1-maria') $baoRoot) 'rotate-root app1-maria' | Out-Null
Write-Host 'database/rotate-root/app1-maria: bao_admin password rotated (binlog holds only the hash)'

# ---------------------------------------------------------------------------------------------
Step 'MariaDB temp users on the replica only (no binary log, never on the primary)'
# Why: every CREATE USER ... IDENTIFIED BY '<password>' that OpenBao ran on the primary was
# written verbatim to the primary's binlog and the replica's relay log. Created on the replica
# with sql_log_bin = 0, a temp user is in no binary log and never exists on the primary.
#
# sql_log_bin = 0 comes from the CONNECTION, not from the statements: OpenBao's MySQL plugin
# runs creation, revocation and rotation statements inside a transaction, and MariaDB refuses
# "SET SESSION sql_log_bin" there (measured: Error 1694 "Cannot modify @@session.sql_log_bin
# inside a transaction"; SET STATEMENT sql_log_bin=0 FOR ... fails the same way). The Go MySQL
# driver turns every unknown DSN parameter into "SET <name>=<value>" right after connecting,
# so "?sql_log_bin=0" in connection_url sets it on every pooled session before any transaction.
# Each statement list starts with a guard that FAILS (Error 1242 "Subquery returns more than 1
# row") if the session still logs to the binlog, so a connection_url without the parameter
# cannot silently write local GTIDs into the replica's binlog. Measured without guard and
# parameter: the local CREATE USER got GTID 0-2-n in the replica's binlog, and the next primary
# write stopped replication ("out-of-order sequence number ... gtid strict mode").
$MariaUsernameTemplate = '{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 40) (.RoleName | truncate 16) (unix_time) (random 4) | truncate 80 }}'
$AccessHostMask = '10.81.5.0/255.255.255.0'
$Guard = 'SET @sql_log_bin_must_be_0 = (SELECT 1 UNION ALL SELECT 1 FROM DUAL WHERE @@session.sql_log_bin <> 0)'
$ReplicaCreation = $Guard + '; ' +
    "CREATE USER '{{name}}'@'" + $AccessHostMask + "' IDENTIFIED BY '{{password}}' REQUIRE SSL " +
    "WITH MAX_USER_CONNECTIONS 2 MAX_STATEMENT_TIME 60 PASSWORD EXPIRE INTERVAL 1 DAY; " +
    "GRANT SELECT ON app1_masked.* TO '{{name}}'@'" + $AccessHostMask + "';"
# KILL USER ends the temp user's open sessions on the replica at once (it is local now); the
# sweeper stays as a second line. DROP USER IF EXISTS: revoking a user that a re-seed of the
# replica already removed succeeds.
$ReplicaRevocation = $Guard + '; ' + "KILL USER '{{name}}'; DROP USER IF EXISTS '{{name}}'@'" + $AccessHostMask + "';"
$ReplicaRootRotation = $Guard + "; SET PASSWORD = PASSWORD('{{password}}')"
$ReplicaFields = @(
    'plugin_name=mysql-database-plugin',
    'connection_url={{username}}:{{password}}@tcp(maria-replica-admin:3306)/?sql_log_bin=0',
    'tls_ca=@/pki-ca/ca.crt',
    'tls_server_name=maria-replica',
    'allowed_roles=app1-maria-ro',
    ('username_template=' + $MariaUsernameTemplate),
    ('root_rotation_statements=' + $ReplicaRootRotation),
    'verify_connection=true')

function New-InitialPassword {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $sb = New-Object System.Text.StringBuilder
    $b = New-Object byte[] 1
    while ($sb.Length -lt 32) { $rng.GetBytes($b); if ($b[0] -lt 248) { [void]$sb.Append($alphabet[$b[0] % 62]) } }
    $rng.Dispose()
    return $sb.ToString()
}

$mR = Get-P2ContainerId 'maria-replica'
$mP = Get-P2ContainerId 'maria-primary'
$r = Assert-Ok (Invoke-Docker @('exec', $mR, 'bash', '/opt/phase4/replica-bao-account.sh', 'ensure')) 'bao_replica_admin on maria-replica'
Write-Host ('maria-replica: ' + $r.All.Trim())
$accountCreated = $r.Out -match 'created'
$cfgExists = (Invoke-Bao @('read', '-format=json', 'database/config/app1-maria-replica') $baoRoot).Code -eq 0
$needInit = $accountCreated -or (-not $cfgExists)
if (-not $needInit) {
    # Everything except the credential; OpenBao keeps the rotated password and verifies it.
    $u = Invoke-Bao (@('write', 'database/config/app1-maria-replica') + $ReplicaFields) $baoRoot
    if ($u.Code -eq 0) {
        Write-Host 'database/config/app1-maria-replica: updated (bao_replica_admin password unchanged, connection verified)'
    } else {
        Write-Host ('database/config/app1-maria-replica: the stored password no longer works (replica re-seeded?): {0}' -f $u.Err.Trim())
        $needInit = $true
    }
}
if ($needInit) {
    # A fresh random initial password, never stored in a file: set on the replica (local,
    # sql_log_bin = 0, server_audit masks it), handed to OpenBao on stdin, then rotated at once.
    $pw = New-InitialPassword
    Assert-Ok (Invoke-Docker @('exec', '-e', 'BAO_REPLICA_PW', $mR, 'bash', '/opt/phase4/replica-bao-account.sh', 'set-password') @{ BAO_REPLICA_PW = $pw }) 'bao_replica_admin initial password' | Out-Null
    Assert-Ok (Invoke-Bao (@('write', 'database/config/app1-maria-replica') + $ReplicaFields + @('username=bao_replica_admin', 'password=-')) $baoRoot $pw) 'write database/config/app1-maria-replica' | Out-Null
    $pw = $null
    Write-Host 'database/config/app1-maria-replica: written with a one-time initial password (connection verified)'
    Assert-Ok (Invoke-Bao @('write', '-force', 'database/rotate-root/app1-maria-replica') $baoRoot) 'rotate-root app1-maria-replica' | Out-Null
    Write-Host 'database/rotate-root/app1-maria-replica: bao_replica_admin password rotated (only OpenBao knows it)'
}
Assert-Ok (Invoke-Bao @('write', 'database/roles/app1-maria-ro', 'db_name=app1-maria-replica', 'default_ttl=1h', 'max_ttl=4h',
        ('creation_statements=' + $ReplicaCreation), ('revocation_statements=' + $ReplicaRevocation)) $baoRoot) 'role app1-maria-ro' | Out-Null
Write-Host 'database/roles/app1-maria-ro: db_name=app1-maria-replica (default_ttl 1h, max_ttl 4h)'
$g = Assert-Ok (Invoke-Docker @('exec', $mR, 'bash', '/opt/phase4/replica-bao-account.sh', 'show')) 'show bao_replica_admin'
Write-Host ('maria-replica grants: ' + (($g.Out.Trim() -split "`r?`n") -join '; '))
$mrPw = Read-P2Secret 'maria_root_password'
function MaVal { param([string]$Id, [string]$Sql) (Assert-Ok (Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', $Id, 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mrPw }) $Sql).Out.Trim() }
$onPrimary = MaVal $mP "SELECT COUNT(*) FROM mysql.global_priv WHERE User = 'bao_replica_admin'"
$bin = MaVal $mR "SELECT CONCAT('log_bin=', @@log_bin, ' log_slave_updates=', @@log_slave_updates, ' gtid_binlog_pos=', @@gtid_binlog_pos, ' gtid_slave_pos=', @@gtid_slave_pos)"
if ($onPrimary -ne '0') { throw 'bao_replica_admin exists on maria-primary; it must be local to the replica' }
if ($bin -match '\b\d+-2-\d+') { throw ('maria-replica has local GTIDs (server_id 2) in its binlog: ' + $bin) }
Write-Host ('maria-primary: bao_replica_admin rows {0}; maria-replica: {1} (no local GTID)' -f $onPrimary, $bin)

# ---------------------------------------------------------------------------------------------
Step 'pgAudit role settings (design 4.E)'
$pgP = Get-P2ContainerId 'pg-primary'
$pgR = Get-P2ContainerId 'pg-replica'
$r = Assert-Ok (Invoke-Docker @('exec', '-u', 'postgres', $pgP, 'bash', '/opt/phase4/audit-roles.sh')) 'pgAudit role settings'
Write-Host $r.All
$deadline = (Get-Date).AddSeconds(60)
$ok = $false
while ((Get-Date) -lt $deadline) {
    $x = Invoke-Docker @('exec', '-u', 'postgres', $pgR, 'psql', '-X', '-At', '-d', 'postgres', '-c', "SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole WHERE r.rolname = 'session_sweeper' AND 'pgaudit.log_catalog=off' = ANY (s.setconfig)")
    if ($x.Out.Trim() -eq '1') { $ok = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ok) { throw 'pg-replica does not show the replicated session_sweeper pgAudit setting' }
Write-Host 'pg-replica: role settings replicated'

# ---------------------------------------------------------------------------------------------
Step 'Revocation backstops (design 5.4: revocation depends on the replica being reachable)'
# (a) maria-replica: startup purge and expiry backstop event come from its init_file at every
#     start (config/mariadb/phase4/replica-init.sql.tmpl); only shown here.
$ev = MaVal $mR "SELECT CONCAT(EVENT_SCHEMA, '.', EVENT_NAME, ' ', STATUS, ' every ', INTERVAL_VALUE, ' ', INTERVAL_FIELD, ' definer ', DEFINER, '; event_scheduler=', @@event_scheduler, '; secure_file_priv=', @@secure_file_priv) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = 'replica_local' AND EVENT_NAME = 'revocation_backstop'"
# The definer must be the locked least-privilege account: an ALTER EVENT without a DEFINER clause
# silently makes the altering user (e.g. root) the definer (measured). A restart of maria-replica
# re-creates the event from the init_file.
if ($ev -notmatch 'ENABLED every \d+ SECOND definer revocation_backstop@localhost;') { throw ('maria-replica: expiry backstop event missing, disabled or with another definer: [' + $ev + ']. Restart maria-replica (its init_file re-creates the event) and see docker compose -f ' + $composeName + ' logs maria-replica.') }
Write-Host ('maria-replica: ' + $ev)
$bs = Invoke-Docker @('exec', $mR, 'sh', '-c', 'ls -1t /var/log/mariadb-audit/backstop/startup-purge-*.log | head -n 1 | xargs cat')
Write-Host ('maria-replica: last startup purge: ' + $bs.Out.Trim())

# (b) OpenBao lease reconciler: AppRole lease-reconciler with policy lease-reconciler
#     (config/openbao/lease-reconciler.hcl). Batch tokens (no storage write per login), no default
#     policy, secret ID and tokens bound to the reconciler's fixed address on bao-reconciler.
#     LAB-ONLY credential delivery: role ID and secret ID in secrets\openbao_phase4_reconciler_*
#     (Docker secrets of the lease-reconciler container). A new secret ID is issued at every run
#     and all older ones are destroyed.
$ReconcilerIp = '10.81.10.20'
$auths = ConvertFrom-JsonOrNull (Assert-Ok (Invoke-Bao @('auth', 'list', '-format=json') $baoRoot) 'auth list').Out
if ($auths.PSObject.Properties.Name -contains 'approle/') { Write-Host 'auth approle/: already enabled' } else {
    Assert-Ok (Invoke-Bao @('auth', 'enable', 'approle') $baoRoot) 'auth enable approle' | Out-Null
    Write-Host 'auth approle/: enabled'
}
Assert-Ok (Invoke-Bao @('policy', 'write', 'lease-reconciler', '/openbao/setup/lease-reconciler.hcl') $baoRoot) 'policy lease-reconciler' | Out-Null
Assert-Ok (Invoke-Bao @('write', 'auth/approle/role/lease-reconciler', 'token_policies=lease-reconciler', 'token_no_default_policy=true',
        'token_type=batch', 'token_ttl=300', 'token_max_ttl=300', ('token_bound_cidrs=' + $ReconcilerIp + '/32'),
        ('secret_id_bound_cidrs=' + $ReconcilerIp + '/32'), 'secret_id_ttl=0', 'secret_id_num_uses=0', 'bind_secret_id=true') $baoRoot) 'approle role lease-reconciler' | Out-Null
Write-Host ('auth/approle/role/lease-reconciler: policy lease-reconciler only (no default), batch tokens 300 s, secret ID and tokens bound to {0}/32' -f $ReconcilerIp)
$roleId = (Assert-Ok (Invoke-Bao @('read', '-field=role_id', 'auth/approle/role/lease-reconciler/role-id') $baoRoot) 'read role-id').Out.Trim()
$sid = ConvertFrom-JsonOrNull (Assert-Ok (Invoke-Bao @('write', '-f', '-format=json', 'auth/approle/role/lease-reconciler/secret-id') $baoRoot) 'new secret-id').Out
if (($null -eq $sid) -or (-not $sid.data.secret_id)) { throw 'no secret_id returned' }
Write-P2Secret ($baoPrefix + '_reconciler_role_id') $roleId
Write-P2Secret ($baoPrefix + '_reconciler_secret_id') ([string]$sid.data.secret_id)
$newAcc = [string]$sid.data.secret_id_accessor
$sid = $null
$accs = ConvertFrom-JsonOrNull (Invoke-Bao @('list', '-format=json', 'auth/approle/role/lease-reconciler/secret-id') $baoRoot).Out
$destroyed = 0
foreach ($a in @($accs)) {
    if ($a -and ($a -ne $newAcc)) { Assert-Ok (Invoke-Bao @('write', 'auth/approle/role/lease-reconciler/secret-id-accessor/destroy', ('secret_id_accessor=' + $a)) $baoRoot) 'destroy old secret-id' | Out-Null; $destroyed++ }
}
Write-Host ('secrets\openbao_phase4_reconciler_role_id and _secret_id written (new secret ID; {0} older secret ID(s) destroyed)' -f $destroyed)
$since = (Get-Date).ToUniversalTime().AddSeconds(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
Assert-Ok (Invoke-Docker @('compose', '-f', $P2ComposeFile, 'up', '-d', '--force-recreate', '--no-deps', 'lease-reconciler') @{} 120) 'recreate lease-reconciler' | Out-Null
$rc = Get-P2ContainerId 'lease-reconciler'
$deadline = (Get-Date).AddSeconds(90)
$lg = ''
while ((Get-Date) -lt $deadline) {
    $lg = (Invoke-Docker @('logs', '--since', $since, $rc)).All
    if ($lg -match 'action=ready') { break }
    Start-Sleep -Seconds 2
}
if ($lg -notmatch 'action=ready') { throw ('lease-reconciler did not log in: ' + (($lg -split "`r?`n" | Select-Object -Last 3) -join ' | ')) }
Write-Host ('lease-reconciler: ' + (($lg -split "`r?`n" | Where-Object { $_ -match 'action=(start|ready)' }) -join ' | '))

# (c) PostgreSQL replica deny list (design 5.4): the reconciler writes a descriptor per pending or
#     irrevocable app1-pg-ro lease into the volume pg-deny; pg-replica's watcher
#     (config/postgres/pg-deny-watcher.sh, started by its entrypoint under tini -s) turns it into
#     a pg_hba reject. Nothing to configure here; only checked.
# The watcher derives the temp role names of a lease from this template (role name cut to
# PG_DENY_ROLE_TRUNCATE = 12 characters, then unix_time, then 4 random characters at the end).
# A different template would make it deny nothing: refuse to continue.
$pgCfg = ConvertFrom-JsonOrNull (Assert-Ok (Invoke-Bao @('read', '-format=json', 'database/config/app1-pg') $baoRoot) 'read database/config/app1-pg').Out
$tpl = [string]$pgCfg.data.connection_details.username_template
if ($tpl -notmatch '^\{\{ printf "v-%s-%s-%s-%s" \(\.DisplayName \| truncate 30\) \(\.RoleName \| truncate 12\) \(unix_time\) \(random 4\) \| truncate 63 \}\}$') { throw ('database/config/app1-pg username_template is not the one the pg-replica deny list expects: ' + $tpl) }
Write-Host ('database/config/app1-pg username_template: ' + $tpl + ' (as the pg-replica deny list expects)')
$dw = $null
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    $dw = Invoke-Docker @('exec', $pgR, 'sh', '-c', 'echo "watchers=$(ps -eo args | grep -c "^bash /opt/replica/pg-deny-watcher.sh watch$") supervisors=$(ps -eo args | grep -c "^bash /opt/replica/pg-deny-watcher.sh supervise$") heartbeat_age=$(( $(date +%s) - $(stat -c %Y /var/lib/postgresql/pg-deny/heartbeat) ))s descriptors=$(ls -1A /pg-deny | wc -l) descriptor_dir=$(stat -c %u:%g:%a /pg-deny) deny_list=$(grep -v "^#" /var/lib/postgresql/pg-deny/denied_roles | tr "\n" " ")"')
    if ($dw.Out -match 'watchers=1 supervisors=1 ') { break }
    Start-Sleep -Seconds 2
}
if ($dw.Out -notmatch 'watchers=1 supervisors=1 heartbeat_age=\d+s descriptors=\d+ descriptor_dir=100:1000:755 ') { throw ('pg-replica: deny-list watcher not running or descriptor volume wrong: ' + $dw.All + '. See docker compose -f ' + $composeName + ' logs pg-replica.') }
$hl = Assert-Ok (Invoke-Docker @('exec', '-u', 'postgres', $pgR, 'psql', '-X', '-At', '-d', 'postgres', '-c', "SELECT 'pg_hba line ' || line_number || ': ' || array_to_string(user_name, ',') || ' ' || auth_method || coalesce(' ERROR ' || error, '') FROM pg_hba_file_rules WHERE line_number = 2")) 'pg_hba_file_rules'
if ($hl.Out -notmatch '^pg_hba line 2: /\^\$.* reject$') { throw ('pg-replica: unexpected deny line in pg_hba: ' + $hl.Out.Trim()) }
Write-Host ('pg-replica deny list: ' + $dw.Out.Trim() + '; ' + $hl.Out.Trim())

# ---------------------------------------------------------------------------------------------
Step 'Audit plugins loaded'
foreach ($s in @('pg-primary', 'pg-replica')) {
    $r = Assert-Ok (Invoke-Docker @('exec', '-u', 'postgres', (Get-P2ContainerId $s), 'psql', '-X', '-At', '-d', 'postgres', '-c',
            "SELECT 'shared_preload_libraries=' || current_setting('shared_preload_libraries') || ' log_destination=' || current_setting('log_destination') || ' log_connections=' || current_setting('log_connections') || ' (this postgres session: pgaudit.log=' || current_setting('pgaudit.log') || ', from the role setting; the server-wide value is checked by tests\phase4-checks.ps1 as a temp user)'")) ($s + ' settings')
    Write-Host ('{0}: {1}' -f $s, $r.Out.Trim())
}
$mrPw = Read-P2Secret 'maria_root_password'
foreach ($s in @('maria-primary', 'maria-replica')) {
    $r = Assert-Ok (Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Get-P2ContainerId $s), 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e',
            "SELECT CONCAT('server_audit ', PLUGIN_STATUS, ' ', LOAD_OPTION, ' logging=', @@server_audit_logging, ' events=', @@server_audit_events, ' general_log=', @@general_log, ' slow_query_log=', @@slow_query_log) FROM information_schema.PLUGINS WHERE PLUGIN_NAME = 'SERVER_AUDIT'") @{ MYSQL_PWD = $mrPw }) ($s + ' settings')
    Write-Host ('{0}: {1}' -f $s, $r.Out.Trim())
}

# ---------------------------------------------------------------------------------------------
Step 'Log shipper'
$fb = Get-P2ContainerId 'fluent-bit'
$st = (Invoke-Docker @('inspect', '-f', '{{.State.Status}}', $fb)).Out.Trim()
if ($st -ne 'running') { throw ('fluent-bit is {0}. See docker compose -f {1} logs fluent-bit.' -f $st, $composeName) }
$store = $project + '_log-store'
$deadline = (Get-Date).AddSeconds(60)
$x = $null
while ((Get-Date) -lt $deadline) {
    # Throwaway reader with the store mounted READ-ONLY (the fluent-bit image has no shell).
    $x = Invoke-Docker @('run', '--rm', '--network', 'none', '-v', ($store + ':/store:ro'), '--entrypoint', 'sh', 'postgres:17', '-c', 'test -s /store/audit.jsonl && wc -l /store/audit.jsonl /store/alerts.jsonl 2>/dev/null; true')
    if ($x.Out -match 'audit\.jsonl') { break }
    Start-Sleep -Seconds 2
}
if ($x.Out -notmatch 'audit\.jsonl') { throw ('the log store has no audit.jsonl yet. See docker compose -f ' + $composeName + ' logs fluent-bit.') }
Write-Host ('fluent-bit: running; store: ' + (($x.Out.Trim() -split "`r?`n") -join '; '))

Write-Host ''
Write-Host 'phase4-setup: done. OpenBao is unsealed. Audit records are shipped to the log-store volume (audit.jsonl, alerts.jsonl).'
