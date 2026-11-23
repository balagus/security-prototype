[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # How long to wait for the stack (migrations, Keycloak, replica clone/seed) after "up -d".
    [int]$WaitSeconds = 420,
    # Stack selection. Defaults = the phase 3 stack, unchanged. scripts\phase4-setup.ps1 passes
    # the phase 4 compose file, project and its own OpenBao secret-file prefix.
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype-phase3',
    [string]$BaoSecretPrefix = 'openbao_phase3',
    # Phase 4 only, passed through to phase2-setup.ps1 (see there). Defaults = phase 3 unchanged.
    [switch]$MariaTempUsersOnReplica,
    [string]$MariaRootRotationStatement = ''
)

# Phase 3 setup: takes a fresh "docker compose -f compose.phase3.yaml up -d" to a fully
# configured state. Idempotent: safe to run again at any time (it also unseals OpenBao).
#   1. scripts\phase2-setup.ps1 against the phase 3 stack (database access setup on the
#      PRIMARIES, OpenBao init/unseal/configuration). The phase 3 OpenBao instance keeps its
#      unseal key and root token in secrets\openbao_phase3_unseal_key / _root_token (LAB-ONLY).
#   2. the replica session sweeper accounts on the primaries (they replicate to the replicas)
#   3. waits until both replicas are healthy and have replayed everything up to now
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($ComposeFile) { $compose = $ComposeFile } else { $compose = Join-Path $root 'compose.phase3.yaml' }
$project = $Project
$baoPrefix = $BaoSecretPrefix

& (Join-Path $PSScriptRoot 'phase2-setup.ps1') -TimeoutSeconds $TimeoutSeconds -WaitSeconds $WaitSeconds -ComposeFile $compose -Project $project -BaoSecretPrefix $baoPrefix -MariaTempUsersOnReplica:$MariaTempUsersOnReplica -MariaRootRotationStatement $MariaRootRotationStatement

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
Step 'Session sweeper accounts on the primaries (design 5.4)'
foreach ($n in @('pg_session_sweeper_password', 'maria_session_sweeper_password', 'pg_replicator_password', 'maria_replicator_password')) {
    if (-not (Test-Path (Join-Path $P2SecretsDir $n))) { throw ('secrets\{0} is missing. Run scripts\gen-secrets.ps1 before "up".' -f $n) }
}
$r = Assert-Ok (Invoke-Docker @('exec', '-u', 'postgres', (Get-P2ContainerId 'pg-primary'), 'bash', '/opt/phase3/access-setup.sh')) 'PostgreSQL sweeper account'
Write-Host $r.All
$r = Assert-Ok (Invoke-Docker @('exec', (Get-P2ContainerId 'maria-primary'), 'bash', '/opt/phase3/access-setup.sh')) 'MariaDB sweeper account'
Write-Host $r.All

# ---------------------------------------------------------------------------------------------
Step 'Replicas'
$deadline = (Get-Date).AddSeconds($WaitSeconds)
function Get-State { param([string]$Service) (Invoke-Docker @('inspect', '-f', '{{.State.Status}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{end}}', (Get-P2ContainerId $Service))).Out.Trim() }
foreach ($s in @('pg-replica', 'maria-replica')) {
    $st = Get-State $s
    while (($st -notmatch 'healthy$') -and ((Get-Date) -lt $deadline)) {
        if ($st -match '^exited') { throw ('{0} stopped: {1}. See docker compose -f {2} logs {0}.' -f $s, $st, (Split-Path -Leaf $compose)) }
        Start-Sleep -Seconds 3
        $st = Get-State $s
    }
    if ($st -notmatch 'healthy$') { throw ('{0} is not healthy: {1}' -f $s, $st) }
    Write-Host ('{0}: {1}' -f $s, $st)
}

# Caught up: the sweeper accounts created above must be on the replicas before the sweepers
# can log in.
$pgP = Get-P2ContainerId 'pg-primary'
$pgR = Get-P2ContainerId 'pg-replica'
$lsn = (Assert-Ok (Invoke-Docker @('exec', '-u', 'postgres', $pgP, 'psql', '-X', '-At', '-d', 'app1', '-c', 'SELECT pg_current_wal_lsn()')) 'primary LSN').Out.Trim()
$ok = $false
while ((Get-Date) -lt $deadline) {
    $x = Invoke-Docker @('exec', '-u', 'postgres', $pgR, 'psql', '-X', '-At', '-d', 'app1', '-c', ("SELECT pg_last_wal_replay_lsn() >= '{0}'::pg_lsn AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'session_sweeper')" -f $lsn))
    if ($x.Out.Trim() -eq 't') { $ok = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $ok) { throw ('pg-replica has not replayed up to {0}' -f $lsn) }
Write-Host ('pg-replica: replayed up to primary LSN {0}; session_sweeper present' -f $lsn)

$mrPw = Read-P2Secret 'maria_root_password'
function MariaLocal { param([string]$Id, [string]$Sql) Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', $Id, 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mrPw } }
$mP = Get-P2ContainerId 'maria-primary'
$mR = Get-P2ContainerId 'maria-replica'
$gtid = (Assert-Ok (MariaLocal $mP 'SELECT @@gtid_binlog_pos') 'primary GTID').Out.Trim()
$ok = $false
while ((Get-Date) -lt $deadline) {
    $x = MariaLocal $mR ("SELECT MASTER_GTID_WAIT('{0}', 2) = 0 AND EXISTS (SELECT 1 FROM mysql.user WHERE User = 'session_sweeper')" -f $gtid)
    if ($x.Out.Trim() -eq '1') { $ok = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ok) { throw ('maria-replica has not applied GTID {0}' -f $gtid) }
Write-Host ('maria-replica: applied up to primary GTID {0}; session_sweeper present' -f $gtid)

Write-Host ''
Write-Host 'phase3-setup: done. OpenBao is unsealed. Developers connect to pg-replica / maria-replica on the access network.'
