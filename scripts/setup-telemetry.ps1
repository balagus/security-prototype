[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # How long to wait for the telemetry services (Loki, Tempo, Grafana) to report ready.
    [int]$TelemetryWaitSeconds = 180
)

# Setup stage 4 of 5 (run by scripts\setup.ps1 after setup-audit.ps1): debug telemetry.
# Nothing to configure; waits until the telemetry pipeline answers: Loki and Tempo "ready"
# (checked from a throwaway curl container on the internal network telemetry-store; neither has
# a published port), alloy running, Grafana healthy on 127.0.0.1:3000.
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $root 'compose.yaml'
$project = 'security-prototype'
$baoPrefix = 'openbao'

$LabComposeFile = $compose
$LabProject = $project
$LabBaoSecretPrefix = $baoPrefix
. (Join-Path $PSScriptRoot 'lib.ps1')

$curlImage = 'curlimages/curl:8.22.0'
$netStore = $project + '_telemetry-store'

Write-Host '== Telemetry pipeline'
$deadline = (Get-Date).AddSeconds($TelemetryWaitSeconds)
$pending = @('loki', 'tempo', 'alloy', 'grafana')
while ($pending.Count -gt 0) {
    $still = @()
    foreach ($s in $pending) {
        $ok = $false
        switch ($s) {
            'loki'  { $r = Invoke-Docker @('run', '--rm', '--network', $netStore, $curlImage, '-sf', '-m', '5', 'http://loki:3100/ready'); $ok = ($r.Code -eq 0) -and ($r.Out -match 'ready') }
            'tempo' { $r = Invoke-Docker @('run', '--rm', '--network', $netStore, $curlImage, '-sf', '-m', '5', 'http://tempo:3200/ready'); $ok = ($r.Code -eq 0) -and ($r.Out -match 'ready') }
            'alloy' { $r = Invoke-Docker @('inspect', '-f', '{{.State.Status}}', (Get-LabContainerId 'alloy')); $ok = ($r.Out.Trim() -eq 'running') }
            'grafana' {
                try { $h = Invoke-RestMethod -Uri 'http://127.0.0.1:3000/api/health' -TimeoutSec 5; $ok = ($h.database -eq 'ok') } catch { $ok = $false }
            }
        }
        if ($ok) { Write-Host ('ready    {0}' -f $s) } else { $still += $s }
    }
    $pending = $still
    if ($pending.Count -eq 0) { break }
    if ((Get-Date) -gt $deadline) {
        throw ('not ready after {0}s: {1}. See docker compose logs {1}' -f $TelemetryWaitSeconds, ($pending -join ' '))
    }
    Start-Sleep -Seconds 5
}

Write-Host 'setup-telemetry: done. Debug telemetry goes to Loki/Tempo.'
Write-Host 'Grafana: http://localhost:3000 (sign in through Keycloak as a member of app1-devs).'
