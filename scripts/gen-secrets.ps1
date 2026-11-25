[CmdletBinding()]
param(
    # Overwrite existing secret files. After -Force, wipe the volumes (docker compose down -v):
    # the databases keep the passwords they were created with.
    [switch]$Force
)

# Windows PowerShell 5.1 compatible. Generates the Docker secret files for compose.yaml (and the
# placeholders it needs). Existing files are kept unless -Force.
# Files are UTF-8 without BOM and without a trailing newline.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root 'secrets'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

function New-RandomBytes {
    param([int]$Count)
    $b = New-Object byte[] $Count
    $rng.GetBytes($b)
    return ,$b
}

# Alphanumeric only, so the value is safe inside connection strings, SQL literals and shells.
function New-RandomPassword {
    param([int]$Length = 32)
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $sb = New-Object System.Text.StringBuilder
    while ($sb.Length -lt $Length) {
        $bytes = New-RandomBytes 64
        foreach ($x in $bytes) {
            # 248 = 4 * 62: reject the tail to avoid modulo bias.
            if ($x -lt 248 -and $sb.Length -lt $Length) {
                [void]$sb.Append($alphabet[$x % 62])
            }
        }
    }
    return $sb.ToString()
}

function Write-Secret {
    param([string]$Name, [scriptblock]$Value)
    $path = Join-Path $dir $Name
    if ((Test-Path $path) -and -not $Force) {
        Write-Host ('kept     secrets\{0}' -f $Name)
        return
    }
    [System.IO.File]::WriteAllText($path, (& $Value), $utf8NoBom)
    Write-Host ('written  secrets\{0}' -f $Name)
}

function Read-Secret {
    param([string]$Name)
    return [System.IO.File]::ReadAllText((Join-Path $dir $Name), $utf8NoBom)
}

# Database superusers and application accounts (docs/DECISIONS.md D2).
foreach ($n in @(
        'pg_superuser_password',
        'pg_app1_migrator_password',
        'pg_app1_runtime_password',
        'maria_root_password',
        'maria_app1_migrator_password',
        'maria_app1_runtime_password')) {
    Write-Secret $n { New-RandomPassword 32 }
}

# Just-in-time access (D4):
# - *_bao_admin_initial_password: the password bao_admin is created with. OpenBao rotates it
#   (rotate-root) right after it is configured, so afterwards this file no longer works.
# - keycloak_admin_password: Keycloak bootstrap admin (master realm), for the admin console.
# - keycloak_openbao_client_secret: client secret of the confidential Keycloak client "openbao"
#   (OIDC auth method). Imported into the realm and written into OpenBao by setup-access.ps1.
# secrets\openbao_unseal_key and secrets\openbao_root_token are written by setup-access.ps1
# when it initializes OpenBao (LAB-ONLY).
foreach ($n in @(
        'pg_bao_admin_initial_password',
        'maria_bao_admin_initial_password',
        'keycloak_admin_password',
        'keycloak_openbao_client_secret')) {
    Write-Secret $n { New-RandomPassword 32 }
}

# Replicas (D5, D7):
# - *_replicator_password: streaming/GTID replication accounts (created at first primary start).
# - *_session_sweeper_password: the replica session sweepers' own least-privilege accounts
#   (created on the primaries by scripts\setup-replicas.ps1; they replicate to the replicas).
foreach ($n in @(
        'pg_replicator_password',
        'maria_replicator_password',
        'pg_session_sweeper_password',
        'maria_session_sweeper_password')) {
    Write-Secret $n { New-RandomPassword 32 }
}

# Revocation backstops (D8):
# - openbao_reconciler_role_id / _secret_id: AppRole credentials of the lease reconciler.
#   OpenBao issues them; scripts\setup-audit.ps1 writes the real values (LAB-ONLY). Only a
#   placeholder is written here, because Docker creates a DIRECTORY in place of a secret file
#   that is missing at "docker compose up" (measured), and the reconciler starts with the stack.
#   Existing files are kept even with -Force (the real values belong to the OpenBao instance).
foreach ($n in @('openbao_reconciler_role_id', 'openbao_reconciler_secret_id')) {
    $path = Join-Path $dir $n
    if (Test-Path $path) { Write-Host ('kept     secrets\{0}' -f $n); continue }
    [System.IO.File]::WriteAllText($path, 'unprovisioned', $utf8NoBom)
    Write-Host ('written  secrets\{0} (placeholder; setup-audit.ps1 writes the real value)' -f $n)
}

# Debug telemetry (D10):
# - grafana_admin_password: Grafana's local admin, for "grafana cli" inside the container only
#   (login form and basic auth are off; people sign in through Keycloak).
# - keycloak_grafana_client_secret: client secret of the confidential Keycloak client "grafana".
foreach ($n in @(
        'grafana_admin_password',
        'keycloak_grafana_client_secret')) {
    Write-Secret $n { New-RandomPassword 32 }
}

# Approval portal and write path (D11, D12):
# - keycloak_portal_client_secret: client secret of the confidential Keycloak client "portal"
#   (people sign in to the portal with it).
# - keycloak_portal_group_manager_secret: client secret of the service-account client
#   "portal-group-manager" (the portal adds and removes app1-devs memberships with it).
# - keycloak_carol_password: LAB-ONLY test approver "carol" (created by setup-portal.ps1).
# - keycloak_dave_password: LAB-ONLY write approver "dave" (app1-write-approvers).
# setup-portal.ps1 writes all of these values into Keycloak.
foreach ($n in @(
        'keycloak_portal_client_secret',
        'keycloak_portal_group_manager_secret',
        'keycloak_carol_password',
        'keycloak_dave_password')) {
    Write-Secret $n { New-RandomPassword 32 }
}

# Laravel APP_KEY (AES-256-CBC needs 32 random bytes).
Write-Secret 'laravel_app_key' { 'base64:' + [Convert]::ToBase64String((New-RandomBytes 32)) }

# .NET connection strings, derived from the password files above.
# The CA path is the read-only CA volume mounted into the .NET containers.
$csTemplate = 'Host=pg-primary;Port=5432;Database=app1;Username={0};Password={1};SSL Mode=VerifyFull;Root Certificate=/pki-ca/ca.crt'
Write-Secret 'dotnet_app1_connstr' { $csTemplate -f 'app1_runtime', (Read-Secret 'pg_app1_runtime_password') }
Write-Secret 'dotnet_migrator_connstr' { $csTemplate -f 'app1_migrator', (Read-Secret 'pg_app1_migrator_password') }

$rng.Dispose()
