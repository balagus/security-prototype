[CmdletBinding()]
param(
    # Suites to run, in this order, comma-separated. Default: all of them (about 30 minutes).
    # Names: smoke, hardening, jit-access, replica, audit, revocation, telemetry, portal, write-access
    [string[]]$Suite = @('smoke', 'hardening', 'jit-access', 'replica', 'audit', 'revocation', 'telemetry', 'portal', 'write-access'),
    # Keep going after a failed suite.
    [switch]$ContinueOnFailure
)

# Runs the test suites against the RUNNING, configured stack (compose.yaml after
# scripts\setup.ps1), each in its own PowerShell process, and prints a summary.
# Several suites restart containers (OpenBao, the replicas, the sweepers, pg-primary) and leave
# everything running and unsealed again. Run one at a time, never two in parallel.
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$exe = (Get-Process -Id $PID).Path
$files = @{
    'smoke'        = 'smoke.ps1'
    'hardening'    = 'hardening-checks.ps1'
    'jit-access'   = 'jit-access-checks.ps1'
    'replica'      = 'replica-checks.ps1'
    'audit'        = 'audit-checks.ps1'
    'revocation'   = 'revocation-checks.ps1'
    'telemetry'    = 'telemetry-checks.ps1'
    'portal'       = 'portal-checks.ps1'
    'write-access' = 'write-access-checks.ps1'
}

# "powershell -File run-all.ps1 -Suite a,b" passes one string "a,b": split it here.
$Suite = @($Suite | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($s in $Suite) {
    if (-not $files.ContainsKey($s)) { throw ('unknown suite "{0}". Valid: {1}' -f $s, (($files.Keys | Sort-Object) -join ', ')) }
}

$results = @()
foreach ($s in $Suite) {
    $file = Join-Path $PSScriptRoot $files[$s]
    Write-Host ''
    Write-Host ('######## {0} ({1})' -f $s, $files[$s]) -ForegroundColor Cyan
    $t0 = Get-Date
    & $exe -NoProfile -ExecutionPolicy Bypass -File $file
    $code = $LASTEXITCODE
    $results += [pscustomobject]@{ Suite = $s; Result = $(if ($code -eq 0) { 'PASS' } else { 'FAIL (exit ' + $code + ')' }); Seconds = [int]((Get-Date) - $t0).TotalSeconds }
    if (($code -ne 0) -and -not $ContinueOnFailure) { break }
}

Write-Host ''
$results | Format-Table -AutoSize | Out-String | Write-Host
if (@($results | Where-Object { $_.Result -ne 'PASS' }).Count -eq 0 -and $results.Count -eq $Suite.Count) { exit 0 } else { exit 1 }
