[CmdletBinding()]
param(
    # OpenBao max_ttl of the temp-user roles (scripts\setup-access.ps1: 4h).
    [int]$MaxTtlMinutes = 240,
    # Grace period on top of max_ttl before a user counts as stale.
    [int]$MarginMinutes = 15,
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype',
    # Where the MariaDB temp users live: on the replica only (docs/DECISIONS.md D6).
    [string]$MariaHost = 'maria-replica'
)

# OPTIONAL: report-only stale temp-user detector (docs/DECISIONS.md D8). Lists OpenBao temp
# users ("v-...") on pg-primary and maria-replica that outlived their maximum lifetime. It never drops anything: a stale user means
# OpenBao could not revoke a lease (for example an irrevocable lease after repeated failures),
# which a person should look at.
#   PostgreSQL: VALID UNTIL passed more than the margin ago, or the creation time embedded in
#               the name is older than max_ttl + margin.
#   MariaDB:    the account is older than max_ttl + margin, by the creation time embedded in
#               the name and by password_last_changed in mysql.global_priv (set at CREATE USER).
# The embedded time is parsed with a regular expression anchored at the end of the name
# (-<10 digits>-<4 random>), not by splitting on "-", because display names contain hyphens.
# Runs as the local superuser over the socket (docker exec), like an ops job.
# Exit code: 0 = nothing stale, 3 = stale users reported, 1 = error.
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.yaml' }
$LabComposeFile = $ComposeFile
$LabProject = $Project
$LabBaoSecretPrefix = ''
. (Join-Path $PSScriptRoot 'lib.ps1')

$limit = ($MaxTtlMinutes + $MarginMinutes) * 60
$margin = $MarginMinutes * 60
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

$pgSql = @"
SELECT rolname,
       coalesce(extract(epoch FROM rolvaliduntil)::bigint::text, ''),
       coalesce(substring(rolname FROM '-([0-9]{10})-[A-Za-z0-9]{4}`$'), '')
FROM pg_roles WHERE rolname LIKE 'v-%' ORDER BY rolname
"@
$maSql = @"
SELECT CONCAT(User, '@', Host),
       COALESCE(JSON_VALUE(Priv, '$.password_last_changed'), ''),
       COALESCE(REGEXP_SUBSTR(REGEXP_SUBSTR(User, '-[0-9]{10}-[A-Za-z0-9]{4}`$'), '[0-9]{10}'), '')
FROM mysql.global_priv WHERE User LIKE 'v-%' ORDER BY User
"@

$pg = Invoke-Docker @('exec', '-u', 'postgres', (Get-LabContainerId 'pg-primary'), 'psql', '-X', '-At', '-F', '|', '-d', 'app1', '-c', $pgSql)
$ma = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', (Get-LabContainerId $MariaHost), 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $maSql) @{ MYSQL_PWD = (Read-LabSecret 'maria_root_password') }
if (($pg.Code -ne 0) -or ($ma.Code -ne 0)) { Write-Host ('stale-user report failed: {0} {1}' -f $pg.All, $ma.All); exit 1 }

function Fmt { param([long]$T) if ($T -le 0) { return '-' }; return [DateTimeOffset]::FromUnixTimeSeconds($T).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') }
$stale = 0
$total = 0
foreach ($l in ($pg.Out -split "`r?`n" | Where-Object { $_ })) {
    $total++
    $p = $l.Split('|')
    $vu = 0; if ($p[1]) { $vu = [long]$p[1] }
    $ts = 0; if ($p[2]) { $ts = [long]$p[2] }
    $why = @()
    if (($vu -gt 0) -and ($vu -lt ($now - $margin))) { $why += ('VALID UNTIL {0} passed' -f (Fmt $vu)) }
    if (($ts -gt 0) -and ($ts -lt ($now - $limit))) { $why += ('created {0} (name), older than max_ttl + margin' -f (Fmt $ts)) }
    if ($why.Count) { $stale++; Write-Host ('{0} STALE engine=postgresql role={1} {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $p[0], ($why -join '; ')) }
}
foreach ($l in ($ma.Out -split "`r?`n" | Where-Object { $_ })) {
    $total++
    $p = $l.Split("`t")
    $pc = 0; if ($p[1]) { $pc = [long]$p[1] }
    $ts = 0; if ($p[2]) { $ts = [long]$p[2] }
    $why = @()
    if (($ts -gt 0) -and ($ts -lt ($now - $limit))) { $why += ('created {0} (name), older than max_ttl + margin' -f (Fmt $ts)) }
    if (($pc -gt 0) -and ($pc -lt ($now - $limit))) { $why += ('password_last_changed {0}, older than max_ttl + margin' -f (Fmt $pc)) }
    if ($why.Count) { $stale++; Write-Host ('{0} STALE engine=mariadb account={1} {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $p[0], ($why -join '; ')) }
}
Write-Host ('stale-user report: {0} v- users (PostgreSQL on pg-primary, MariaDB on {4}), {1} stale (max_ttl {2} min + margin {3} min). Nothing was dropped.' -f $total, $stale, $MaxTtlMinutes, $MarginMinutes, $MariaHost)
if ($stale -gt 0) { exit 3 } else { exit 0 }
