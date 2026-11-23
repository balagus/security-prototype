[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # How long to wait for the stack (migrations, Keycloak, replica clone/seed) after "up -d".
    [int]$WaitSeconds = 420,
    # How long to wait for the telemetry services (Loki, Tempo, Grafana) to report ready.
    [int]$TelemetryWaitSeconds = 180
)

# Phase 5 setup: takes a fresh "docker compose -f compose.phase5.yaml up -d --build" to a fully
# configured state. Idempotent: safe to run again at any time (it also unseals OpenBao).
#   1. scripts\phase4-setup.ps1 against the phase 5 stack (which runs phase3-setup.ps1 and
#      phase2-setup.ps1 first): everything phases 2 to 4 configure, with the phase 5 OpenBao
#      instance (secrets\openbao_phase5_*, LAB-ONLY).
#   2. waits until the telemetry pipeline answers: Loki and Tempo "ready" (checked from a
#      throwaway curl container on the internal network telemetry-store; neither has a
#      published port), alloy running, Grafana healthy on 127.0.0.1:3000.
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $root 'compose.phase5.yaml'
$project = 'security-prototype-phase5'
$baoPrefix = 'openbao_phase5'

& (Join-Path $PSScriptRoot 'phase4-setup.ps1') -TimeoutSeconds $TimeoutSeconds -WaitSeconds $WaitSeconds -ComposeFile $compose -Project $project -BaoSecretPrefix $baoPrefix

$P2ComposeFile = $compose
$P2Project = $project
$P2BaoSecretPrefix = $baoPrefix
. (Join-Path $PSScriptRoot 'phase2-lib.ps1')

$curlImage = 'curlimages/curl:8.22.0'
$netStore = $project + '_telemetry-store'

Write-Host '== Phase 5: telemetry pipeline'
$deadline = (Get-Date).AddSeconds($TelemetryWaitSeconds)
$pending = @('loki', 'tempo', 'alloy', 'grafana')
while ($pending.Count -gt 0) {
    $still = @()
    foreach ($s in $pending) {
        $ok = $false
        switch ($s) {
            'loki'  { $r = Invoke-Docker @('run', '--rm', '--network', $netStore, $curlImage, '-sf', '-m', '5', 'http://loki:3100/ready'); $ok = ($r.Code -eq 0) -and ($r.Out -match 'ready') }
            'tempo' { $r = Invoke-Docker @('run', '--rm', '--network', $netStore, $curlImage, '-sf', '-m', '5', 'http://tempo:3200/ready'); $ok = ($r.Code -eq 0) -and ($r.Out -match 'ready') }
            'alloy' { $r = Invoke-Docker @('inspect', '-f', '{{.State.Status}}', (Get-P2ContainerId 'alloy')); $ok = ($r.Out.Trim() -eq 'running') }
            'grafana' {
                try { $h = Invoke-RestMethod -Uri 'http://127.0.0.1:3000/api/health' -TimeoutSec 5; $ok = ($h.database -eq 'ok') } catch { $ok = $false }
            }
        }
        if ($ok) { Write-Host ('ready    {0}' -f $s) } else { $still += $s }
    }
    $pending = $still
    if ($pending.Count -eq 0) { break }
    if ((Get-Date) -gt $deadline) {
        throw ('not ready after {0}s: {1}. See docker compose -f compose.phase5.yaml logs {1}' -f $TelemetryWaitSeconds, ($pending -join ' '))
    }
    Start-Sleep -Seconds 5
}

Write-Host 'phase5-setup: done. OpenBao is unsealed, audit records are shipped to log-store, and debug telemetry goes to Loki/Tempo.'
Write-Host 'Grafana: http://localhost:3000 (sign in through Keycloak as a member of app1-devs).'
