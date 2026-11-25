[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # How long to wait for the stack after "up -d" (migrations, Keycloak, replica clone and seed).
    [int]$WaitSeconds = 420
)

# One-shot setup of the whole stack after "docker compose up -d --build". Idempotent: run it
# again at any time, for example after a reboot (it unseals OpenBao) or after Keycloak was
# recreated. Runs the five stages in order; each stage can also be re-run on its own once the
# stages before it have run.
#   1. setup-access.ps1     database access objects, OpenBao init/unseal, secrets engine,
#                           OIDC/JWT auth against Keycloak (just-in-time read access)
#   2. setup-replicas.ps1   sweeper accounts, waits for both replicas to catch up
#   3. setup-audit.ps1      MariaDB temp users on the replica, pgAudit role settings,
#                           revocation backstops, lease reconciler, audit shipping check
#   4. setup-telemetry.ps1  waits for Loki, Tempo, Alloy and Grafana
#   5. setup-portal.ps1     Keycloak configuration of the approval portal, PostgreSQL write path
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$started = Get-Date

& (Join-Path $PSScriptRoot 'setup-access.ps1') -TimeoutSeconds $TimeoutSeconds -WaitSeconds $WaitSeconds
& (Join-Path $PSScriptRoot 'setup-replicas.ps1') -TimeoutSeconds $TimeoutSeconds -WaitSeconds $WaitSeconds
& (Join-Path $PSScriptRoot 'setup-audit.ps1') -TimeoutSeconds $TimeoutSeconds
& (Join-Path $PSScriptRoot 'setup-telemetry.ps1') -TimeoutSeconds $TimeoutSeconds
& (Join-Path $PSScriptRoot 'setup-portal.ps1') -TimeoutSeconds $TimeoutSeconds

Write-Host ''
Write-Host ('setup: done in {0:N0} s.' -f ((Get-Date) - $started).TotalSeconds)
Write-Host '  App:      http://localhost:8080'
Write-Host '  Portal:   http://localhost:8090'
Write-Host '  Grafana:  http://localhost:3000'
Write-Host '  OpenBao:  https://localhost:8200/ui   (lab CA, accept the certificate warning)'
Write-Host '  Keycloak: http://keycloak.localhost:8180'
