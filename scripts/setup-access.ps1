[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # How long to wait for the stack (migrations, Keycloak) after "up -d".
    [int]$WaitSeconds = 300,
    # Stack selection. Empty = compose.yaml, project security-prototype, secrets\openbao_*.
    [string]$ComposeFile = '',
    [string]$Project = '',
    [string]$BaoSecretPrefix = ''
)

# Setup stage 1 of 5 (run by scripts\setup.ps1): just-in-time developer access.
# Idempotent: safe to run again at any time (it also unseals OpenBao).
#   1. database side (docs/DECISIONS.md D5): masked views, debug_ro, bao_admin, via the local superuser
#      socket in each primary (docker exec), after the migrate services have finished
#   2. OpenBao: init (1 key share, LAB-ONLY), store unseal key + root token in secrets\, unseal
#   3. OpenBao configuration (docs/DECISIONS.md D4): database secrets engine, connections over
#      verified TLS, rotate-root, roles, policy, oidc + jwt auth against Keycloak, identity groups
# Every bao command runs inside the openbao container (docker exec), never on the host.
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
# Set (possibly to '') before dot-sourcing, so values from a calling script never leak in.
$LabComposeFile = $ComposeFile
$LabProject = $Project
$LabBaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $PSScriptRoot 'lib.ps1')

function Step { param([string]$Text) Write-Host ''; Write-Host ('== ' + $Text + ' ==') }

function Assert-Ok {
    param($Result, [string]$What)
    if ($Result.Code -ne 0) { throw ('{0} failed (exit {1}): {2}' -f $What, $Result.Code, $Result.All) }
    return $Result
}

# ---------------------------------------------------------------------------------------------
# Lab constants. They must match compose.yaml and config\keycloak\lab-realm.json.
$KeycloakIssuer = 'http://keycloak.localhost:8180/realms/lab'
$KeycloakJwksInternal = 'http://keycloak:8180/realms/lab/protocol/openid-connect/certs'

# Username templates (docs/DECISIONS.md D4). The display name is "<auth mount>-<user>", e.g. jwt-alice or
# oidc-alice. 2 + 30 + 1 + 12 + 1 + 10 + 1 + 4 = 61 <= 63 (PostgreSQL), so the timestamp is
# never cut. MariaDB allows 80 characters.
$PgUsernameTemplate = '{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 30) (.RoleName | truncate 12) (unix_time) (random 4) | truncate 63 }}'
$MariaUsernameTemplate = '{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 40) (.RoleName | truncate 16) (unix_time) (random 4) | truncate 80 }}'

# Temp-user statements (docs/DECISIONS.md D4). The MariaDB temp-user role app1-maria-ro is
# written by setup-audit.ps1 against maria-replica (D6), never here against the primary.
$PgCreation = 'CREATE ROLE "{{name}}" LOGIN PASSWORD ''{{password}}'' VALID UNTIL ''{{expiration}}'' CONNECTION LIMIT 2; ' +
    'GRANT debug_ro TO "{{name}}"; ' +
    'ALTER ROLE "{{name}}" SET statement_timeout = ''60s''; ' +
    'ALTER ROLE "{{name}}" SET idle_session_timeout = ''15min'';'
$PgRevocation = 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ''{{name}}''; DROP ROLE IF EXISTS "{{name}}";'
# (String concatenation, not -f: -f would turn the {{name}} placeholders into {name}.)
# bao_admin's own password: SET PASSWORD for the CURRENT user is binlogged as a hash, from the
# very first rotate-root. "ALTER USER ... IDENTIFIED BY" would be binlogged in clear text (D6).
$MariaRootRotation = "SET PASSWORD = PASSWORD('{{password}}')"

# The lab-probe-* roles are created and deleted only by tests\jit-access-checks.ps1 (LAB-ONLY) to
# run a statement through OpenBao's own bao_admin session. No policy grants them.
# app1-pg-rw is the write role (setup-portal.ps1, docs/DECISIONS.md D12).
$PgAllowedRoles = 'app1-pg-ro,app1-pg-rw'
# app1-maria (bao_admin on the primary) never creates temp users: only the probe roles.
$MariaAllowedRoles = 'lab-probe-maria-basetable,lab-probe-maria-masked'

# ---------------------------------------------------------------------------------------------
Step 'Secrets'
foreach ($n in @('pg_bao_admin_initial_password', 'maria_bao_admin_initial_password', 'keycloak_openbao_client_secret')) {
    if (-not (Test-Path (Join-Path $LabSecretsDir $n))) { throw ('secrets\{0} is missing. Run scripts\gen-secrets.ps1 before "up".' -f $n) }
}
Write-Host 'required secret files present'

# ---------------------------------------------------------------------------------------------
Step 'Wait for the stack'
$deadline = (Get-Date).AddSeconds($WaitSeconds)
function Get-State { param([string]$Service) (Invoke-Docker @('inspect', '-f', '{{.State.Status}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{end}}', (Get-LabContainerId $Service))).Out.Trim() }
foreach ($w in @(
        @{ S = 'dotnet-migrate'; Want = '^exited 0' },
        @{ S = 'laravel-migrate'; Want = '^exited 0' },
        @{ S = 'pg-primary'; Want = 'healthy$' },
        @{ S = 'maria-primary'; Want = 'healthy$' },
        @{ S = 'openbao'; Want = '^running' },
        @{ S = 'keycloak'; Want = '^running' })) {
    $st = Get-State $w.S
    while (($st -notmatch $w.Want) -and ((Get-Date) -lt $deadline)) {
        if ($st -match '^exited [1-9]') { throw ('{0} failed: {1}. See docker compose logs {0}.' -f $w.S, $st) }
        Start-Sleep -Seconds 3
        $st = Get-State $w.S
    }
    if ($st -notmatch $w.Want) { throw ('{0} is not ready: {1}' -f $w.S, $st) }
    Write-Host ('{0}: {1}' -f $w.S, $st)
}
$discovery = $null
while ((Get-Date) -lt $deadline) {
    try { $discovery = Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:8180/realms/lab/.well-known/openid-configuration' -TimeoutSec 5; break } catch { Start-Sleep -Seconds 3 }
}
if ($null -eq $discovery) { throw 'Keycloak realm lab does not answer on http://127.0.0.1:8180' }
if ($discovery.issuer -ne $KeycloakIssuer) { throw ('Keycloak issuer is {0}, expected {1}' -f $discovery.issuer, $KeycloakIssuer) }
Write-Host ('keycloak: realm lab up, issuer {0}' -f $discovery.issuer)

# ---------------------------------------------------------------------------------------------
Step 'Database access setup (docs/DECISIONS.md D5)'
$r = Assert-Ok (Invoke-Docker @('exec', '-u', 'postgres', (Get-LabContainerId 'pg-primary'), 'bash', '/opt/setup/access-setup.sh')) 'PostgreSQL access setup'
Write-Host $r.All
$r = Assert-Ok (Invoke-Docker @('exec', (Get-LabContainerId 'maria-primary'), 'bash', '/opt/setup/access-setup.sh')) 'MariaDB access setup'
Write-Host $r.All

# ---------------------------------------------------------------------------------------------
Step 'OpenBao init and unseal'
$s = Get-BaoStatus
$wait = (Get-Date).AddSeconds(60)
while (($null -eq $s.Obj) -and ((Get-Date) -lt $wait)) { Start-Sleep -Seconds 2; $s = Get-BaoStatus }
if ($null -eq $s.Obj) { throw ('OpenBao does not answer: ' + $s.All) }
if (-not $s.Obj.initialized) {
    # LAB-ONLY: one key share and the root token stored in plain files under secrets\.
    # Production: several key shares held by different people (or auto-unseal), and the root
    # token revoked after setup.
    $r = Assert-Ok (Invoke-Bao @('operator', 'init', '-key-shares=1', '-key-threshold=1', '-format=json')) 'bao operator init'
    $o = ConvertFrom-JsonOrNull $r.Out
    if (($null -eq $o) -or (-not $o.root_token)) { throw 'bao operator init returned no root token' }
    Write-LabSecret $LabBaoUnsealKeyName ([string]$o.unseal_keys_b64[0])
    Write-LabSecret $LabBaoRootTokenName ([string]$o.root_token)
    Write-Host ('openbao: initialized (1 key share); unseal key and root token written to secrets\{0}, secrets\{1} (LAB-ONLY)' -f $LabBaoUnsealKeyName, $LabBaoRootTokenName)
} else {
    foreach ($n in @($LabBaoUnsealKeyName, $LabBaoRootTokenName)) {
        if (-not (Test-Path (Join-Path $LabSecretsDir $n))) { throw ('OpenBao is initialized but secrets\{0} is missing. Wipe the volumes of project {1} (down -v) to start over.' -f $n, $LabProject) }
    }
    Write-Host 'openbao: already initialized'
}
Invoke-BaoUnseal
$root = Read-LabSecret $LabBaoRootTokenName
function Bao { param([string[]]$A, [string]$Stdin = $null) Invoke-Bao $A $root $Stdin }

$st = ConvertFrom-JsonOrNull (Assert-Ok (Bao @('read', '-format=json', 'sys/config/state/sanitized')) 'read sanitized config').Out
Write-Host ('openbao: storage {0}' -f $st.data.storage.type)

# The audit device comes from bao.hcl (declarative). Creating one over the API is refused.
$aud = ConvertFrom-JsonOrNull (Assert-Ok (Bao @('audit', 'list', '-format=json')) 'audit list').Out
if (-not ($aud.PSObject.Properties.Name -contains 'main/')) { throw 'audit device main/ (from bao.hcl) is missing' }
Write-Host ('openbao: audit device main/ -> {0}' -f $aud.'main/'.options.file_path)

# ---------------------------------------------------------------------------------------------
Step 'OpenBao database secrets engine (docs/DECISIONS.md D4)'
$mounts = ConvertFrom-JsonOrNull (Assert-Ok (Bao @('secrets', 'list', '-format=json')) 'secrets list').Out
if ($mounts.PSObject.Properties.Name -contains 'database/') {
    Write-Host 'database/: already enabled'
} else {
    Assert-Ok (Bao @('secrets', 'enable', 'database')) 'enable database' | Out-Null
    Write-Host 'database/: enabled'
}
# Audit devices HMAC all response values by default, including the generated username. Keep the
# username readable so the audit log maps person -> lease -> DB username; the password stays HMAC'd.
Assert-Ok (Bao @('secrets', 'tune', '-audit-non-hmac-response-keys=username', 'database/')) 'tune database/' | Out-Null
Write-Host 'database/: audit_non_hmac_response_keys=username'

function Set-DbConnection {
    param([string]$Name, [string[]]$Fields, [string]$InitialPasswordSecret)
    $exists = (Bao @('read', '-format=json', ('database/config/' + $Name))).Code -eq 0
    if ($exists) {
        # Update everything except the credential: OpenBao merges into the stored connection
        # details, so the rotated bao_admin password is kept.
        Assert-Ok (Bao (@('write', ('database/config/' + $Name)) + $Fields)) ('update database/config/' + $Name) | Out-Null
        Write-Host ('database/config/{0}: updated (bao_admin password unchanged)' -f $Name)
    } else {
        Assert-Ok (Bao (@('write', ('database/config/' + $Name)) + $Fields + @('username=bao_admin', 'password=-')) (Read-LabSecret $InitialPasswordSecret)) ('write database/config/' + $Name) | Out-Null
        Write-Host ('database/config/{0}: written with the initial bao_admin password (connection verified)' -f $Name)
        # After this only OpenBao knows the bao_admin password.
        Assert-Ok (Bao @('write', '-force', ('database/rotate-root/' + $Name))) ('rotate-root ' + $Name) | Out-Null
        Write-Host ('database/rotate-root/{0}: bao_admin password rotated' -f $Name)
    }
}

Set-DbConnection 'app1-pg' @(
    'plugin_name=postgresql-database-plugin',
    'connection_url=postgresql://{{username}}:{{password}}@pg-primary:5432/app1?sslmode=verify-full&sslrootcert=/pki-ca/ca.crt',
    'password_authentication=scram-sha-256',
    ('allowed_roles=' + $PgAllowedRoles),
    ('username_template=' + $PgUsernameTemplate),
    'verify_connection=true') 'pg_bao_admin_initial_password'

Set-DbConnection 'app1-maria' @(
    'plugin_name=mysql-database-plugin',
    'connection_url={{username}}:{{password}}@tcp(maria-primary:3306)/',
    'tls_ca=@/pki-ca/ca.crt',
    'tls_server_name=maria-primary',
    ('allowed_roles=' + $MariaAllowedRoles),
    ('username_template=' + $MariaUsernameTemplate),
    ('root_rotation_statements=' + $MariaRootRotation),
    'verify_connection=true') 'maria_bao_admin_initial_password'

Assert-Ok (Bao @('write', 'database/roles/app1-pg-ro', 'db_name=app1-pg', 'default_ttl=1h', 'max_ttl=4h',
        ('creation_statements=' + $PgCreation), ('revocation_statements=' + $PgRevocation))) 'role app1-pg-ro' | Out-Null
Write-Host 'database/roles/app1-pg-ro: written (default_ttl 1h, max_ttl 4h)'
Write-Host 'database/roles/app1-maria-ro: written by setup-audit.ps1 (temp users on maria-replica)'

# ---------------------------------------------------------------------------------------------
Step 'Policy, auth methods, identity groups (docs/DECISIONS.md D4)'
Assert-Ok (Bao @('policy', 'write', 'app1-debug', '/openbao/setup/app1-debug.hcl')) 'policy app1-debug' | Out-Null
Write-Host 'policy app1-debug: written'

$auths = ConvertFrom-JsonOrNull (Assert-Ok (Bao @('auth', 'list', '-format=json')) 'auth list').Out
foreach ($m in @('oidc', 'jwt')) {
    if ($auths.PSObject.Properties.Name -contains ($m + '/')) {
        Write-Host ('auth {0}/: already enabled' -f $m)
    } else {
        Assert-Ok (Bao @('auth', 'enable', $m)) ('auth enable ' + $m) | Out-Null
        Write-Host ('auth {0}/: enabled' -f $m)
    }
}

# (a) oidc: interactive login (web UI or CLI). The issuer must be reachable under the same URL
# from the browser and from this container: keycloak.localhost:8180 (see compose.yaml).
Assert-Ok (Bao @('write', 'auth/oidc/config', ('oidc_discovery_url=' + $KeycloakIssuer), 'oidc_client_id=openbao',
        'oidc_client_secret=-', 'default_role=dev') (Read-LabSecret 'keycloak_openbao_client_secret')) 'auth/oidc/config' | Out-Null
Assert-Ok (Bao @('write', 'auth/oidc/role/dev', 'role_type=oidc', 'user_claim=preferred_username', 'groups_claim=groups',
        'oidc_scopes=openid,profile', 'claim_mappings=preferred_username=username',
        'allowed_redirect_uris=https://localhost:8200/ui/vault/auth/oidc/oidc/callback,https://127.0.0.1:8200/ui/vault/auth/oidc/oidc/callback,http://localhost:8250/oidc/callback',
        'token_ttl=1h', 'token_max_ttl=4h')) 'auth/oidc/role/dev' | Out-Null
Write-Host ('auth/oidc: discovery {0}, client openbao, role dev' -f $KeycloakIssuer)

# (b) jwt: automated tests (LAB-ONLY direct-access-grant client bao-jwt-test). Keys from the
# internal JWKS URL, issuer bound to the public issuer name in the tokens.
Assert-Ok (Bao @('write', 'auth/jwt/config', ('jwks_url=' + $KeycloakJwksInternal), ('bound_issuer=' + $KeycloakIssuer), 'default_role=dev')) 'auth/jwt/config' | Out-Null
Assert-Ok (Bao @('write', 'auth/jwt/role/dev', 'role_type=jwt', 'user_claim=preferred_username', 'groups_claim=groups',
        'bound_audiences=bao-jwt-test', 'claim_mappings=preferred_username=username',
        'token_ttl=1h', 'token_max_ttl=4h')) 'auth/jwt/role/dev' | Out-Null
Write-Host ('auth/jwt: jwks {0}, bound_issuer {1}, audience bao-jwt-test, role dev' -f $KeycloakJwksInternal, $KeycloakIssuer)

# Identity. An external group holds exactly ONE group alias (a second alias for another mount
# silently replaces the first), so: one external group per auth mount, each with alias
# "app1-devs" (the Keycloak group name in the groups claim), both members of the internal group
# app1-devs, which carries the policy.
$auths = ConvertFrom-JsonOrNull (Assert-Ok (Bao @('auth', 'list', '-format=json')) 'auth list').Out
$memberIds = @()
foreach ($m in @('oidc', 'jwt')) {
    $acc = $auths.($m + '/').accessor
    $gname = 'app1-devs-' + $m
    $g = ConvertFrom-JsonOrNull (Bao @('read', '-format=json', ('identity/group/name/' + $gname))).Out
    if ($null -eq $g) {
        Assert-Ok (Bao @('write', 'identity/group', ('name=' + $gname), 'type=external')) ('group ' + $gname) | Out-Null
        $g = ConvertFrom-JsonOrNull (Assert-Ok (Bao @('read', '-format=json', ('identity/group/name/' + $gname))) ('read group ' + $gname)).Out
    }
    if ($g.data.type -ne 'external') { throw ('identity group {0} exists but is not external' -f $gname) }
    $memberIds += $g.data.id
    if (($null -ne $g.data.alias) -and ($g.data.alias.name -eq 'app1-devs') -and ($g.data.alias.mount_accessor -eq $acc)) {
        Write-Host ('identity group {0}: alias app1-devs on {1} present' -f $gname, $acc)
    } else {
        Assert-Ok (Bao @('write', 'identity/group-alias', 'name=app1-devs', ('mount_accessor=' + $acc), ('canonical_id=' + $g.data.id))) ('group alias for ' + $gname) | Out-Null
        Write-Host ('identity group {0}: alias app1-devs on {1} created' -f $gname, $acc)
    }
}
Assert-Ok (Bao @('write', 'identity/group/name/app1-devs', 'type=internal', 'policies=app1-debug', ('member_group_ids=' + ($memberIds -join ',')))) 'group app1-devs' | Out-Null
Write-Host 'identity group app1-devs (internal): policy app1-debug, members app1-devs-oidc, app1-devs-jwt'

Write-Host ''
Write-Host 'setup-access: done. OpenBao is unsealed. UI: https://localhost:8200/ui (lab CA certificate).'
