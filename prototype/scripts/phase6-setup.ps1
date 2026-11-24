[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # Skip scripts\phase5-setup.ps1 (when the phase 5 stack is already configured and unsealed).
    [switch]$SkipPhase5,
    # How long to wait for Keycloak and the portal.
    [int]$WaitSeconds = 240,
    [string]$KeycloakUrl = 'http://127.0.0.1:8180',
    [string]$PortalUrl = 'http://127.0.0.1:8090',
    [string]$Project = 'security-prototype-phase5'
)

# Phase 6 setup: takes "docker compose -f compose.phase5.yaml -f compose.phase6.yaml up -d --build"
# to a configured approval portal. Idempotent: safe to run again at any time.
#   1. scripts\phase5-setup.ps1 (phases 2 to 5, unseals OpenBao), unless -SkipPhase5. Then
#      attaches the running Keycloak container to the network portal-idp (not in the compose
#      add-on: that would recreate Keycloak and re-import the realm with new user IDs).
#   2. Keycloak realm "lab", through the admin REST API (the realm seed file is not changed, so
#      phases 2 to 5 import exactly what they did before):
#      - group app1-approvers and the LAB-ONLY approver "carol" (password: secrets\keycloak_carol_password)
#      - client "portal": confidential, code flow with PKCE, groups claim
#      - client "portal-group-manager": service account only, with the kc-admin-api scope (the
#        audience the admin API requires) and one realm-management role, view-users (read-only)
#      - fine-grained admin permissions (v2) for that service account: Groups app1-devs
#        {manage-membership}, Users {manage-group-membership}. Keycloak requires both for a
#        membership change; any other group, user change, password reset or user creation is
#        refused (tests\phase6-checks.ps1)
#      - LAB-ONLY client "portal-test": direct-access grant, audience "portal", for the tests
#      - phase 6b: groups app1-devs-rw and app1-write-approvers, LAB-ONLY write approver "dave"
#        (password: secrets\keycloak_dave_password); the permission also covers app1-devs-rw
#   3. phase 6b, the PostgreSQL write path: config/postgres/phase6-write-access.sh on pg-primary
#      (debug_rw, dev_audit, triggers), a check that pg-primary runs the phase 6 pg_hba, and in
#      OpenBao the role app1-pg-rw, the policy app1-write and the identity group app1-devs-rw
#   4. waits until the portal answers /readyz (its service account sees app1-devs and app1-devs-rw).
# Windows PowerShell 5.1 compatible. Secrets are sent to Keycloak in request bodies only.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not $SkipPhase5) {
    & (Join-Path $PSScriptRoot 'phase5-setup.ps1') -TimeoutSeconds $TimeoutSeconds
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Read-Secret { param([string]$Name) return [System.IO.File]::ReadAllText((Join-Path $root ('secrets\' + $Name)), $utf8).Trim() }
foreach ($n in @('keycloak_admin_password', 'keycloak_portal_client_secret', 'keycloak_portal_group_manager_secret', 'keycloak_carol_password', 'keycloak_dave_password')) {
    if (-not (Test-Path (Join-Path $root ('secrets\' + $n)))) { throw ('secrets\{0} is missing. Run scripts\gen-secrets.ps1 first.' -f $n) }
}

# ---- Keycloak admin API ---------------------------------------------------------------------
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ($true) {
    try { $null = Invoke-RestMethod -Uri ($KeycloakUrl + '/realms/lab/.well-known/openid-configuration') -TimeoutSec 5; break }
    catch {
        if ((Get-Date) -gt $deadline) { throw 'Keycloak realm lab is not reachable on ' + $KeycloakUrl }
        Start-Sleep -Seconds 3
    }
}
Write-Host 'ready    keycloak'

# Keycloak joins portal-idp, the portal's only network to it. Done here rather than in
# compose.phase6.yaml so that Keycloak is never recreated (see the comment there).
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $dd = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin'
    if (Test-Path (Join-Path $dd 'docker.exe')) { $env:Path = $dd + ';' + $env:Path }
}
$kcId = (& docker ps -q --filter ('label=com.docker.compose.project=' + $Project) --filter 'label=com.docker.compose.service=keycloak' | Select-Object -First 1)
if (-not $kcId) { throw 'no running keycloak container in project ' + $Project }
$idpNet = $Project + '_portal-idp'
$kcNets = (& docker inspect -f '{{json .NetworkSettings.Networks}}' $kcId) | ConvertFrom-Json
$onIdp = $kcNets.PSObject.Properties.Name -contains $idpNet
# The portal reaches Keycloak by the name "keycloak", which a manual connect does not register
# unless it is given as an alias.
if (-not $onIdp -or -not (@($kcNets.$idpNet.Aliases) -contains 'keycloak')) {
    if ($onIdp) { & docker network disconnect $idpNet $kcId | Out-Null }
    & docker network connect --ip 10.81.14.10 --alias keycloak $idpNet $kcId
    if ($LASTEXITCODE -ne 0) { throw ('could not attach keycloak to {0}. Is the portal stack up (compose.phase6.yaml)?' -f $idpNet) }
    Write-Host ('attached keycloak to {0} (10.81.14.10)' -f $idpNet)
} else {
    Write-Host ('ok       keycloak is on {0}' -f $idpNet)
}

$script:AdminToken = $null
$script:AdminTokenAt = [DateTime]::MinValue
function Get-AdminHeaders {
    if (-not $script:AdminToken -or ((Get-Date) - $script:AdminTokenAt).TotalSeconds -gt 40) {
        $body = @{ grant_type = 'password'; client_id = 'admin-cli'; username = 'admin'; password = (Read-Secret 'keycloak_admin_password') }
        $script:AdminToken = (Invoke-RestMethod -Method Post -Uri ($KeycloakUrl + '/realms/master/protocol/openid-connect/token') -Body $body -TimeoutSec 15).access_token
        $script:AdminTokenAt = Get-Date
    }
    return @{ Authorization = 'Bearer ' + $script:AdminToken }
}
$A = $KeycloakUrl + '/admin/realms/lab'
function Kc {
    param([string]$Method, [string]$Path, $Body = $null)
    $p = @{ Method = $Method; Uri = ($A + $Path); Headers = (Get-AdminHeaders); TimeoutSec = 20 }
    if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 20 -Compress)) }
    $r = Invoke-RestMethod @p
    # Windows PowerShell 5.1 emits a JSON array as ONE pipeline object: unroll it here.
    if ($r -is [array]) { return ,$r }
    return $r
}
function KcList { param([string]$Path) $r = Kc GET $Path; if ($null -eq $r) { return @() }; return @($r | ForEach-Object { $_ }) }

function Get-Group {
    param([string]$Name)
    return (KcList ('/groups?search={0}&exact=true&briefRepresentation=true' -f $Name)) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
}
function Get-Client {
    param([string]$ClientId)
    return (KcList ('/clients?clientId=' + $ClientId)) | Select-Object -First 1
}

# Creates the client, or updates it to $Rep. Then adds every mapper in $Mappers that is missing.
function Set-Client {
    param([hashtable]$Rep, [object[]]$Mappers = @())
    $c = Get-Client $Rep.clientId
    if (-not $c) {
        Kc POST '/clients' $Rep | Out-Null
        $c = Get-Client $Rep.clientId
        Write-Host ('created  client {0}' -f $Rep.clientId)
    } else {
        $Rep.id = $c.id
        Kc PUT ('/clients/' + $c.id) $Rep | Out-Null
        Write-Host ('updated  client {0}' -f $Rep.clientId)
    }
    $existing = @(KcList ('/clients/{0}/protocol-mappers/models' -f $c.id) | ForEach-Object { $_.name })
    foreach ($m in $Mappers) {
        if ($existing -notcontains $m.name) { Kc POST ('/clients/{0}/protocol-mappers/models' -f $c.id) $m | Out-Null }
    }
    return $c
}

$groupsMapper = @{
    name = 'groups'; protocol = 'openid-connect'; protocolMapper = 'oidc-group-membership-mapper'; consentRequired = $false
    config = @{ 'claim.name' = 'groups'; 'full.path' = 'false'; 'id.token.claim' = 'true'; 'access.token.claim' = 'true'; 'userinfo.token.claim' = 'true'; 'introspection.token.claim' = 'true' }
}

Write-Host '== Phase 6: Keycloak'

# Fine-grained admin permissions v2 (default feature in Keycloak 26.2+), off per realm until enabled.
$realm = Kc GET ''
if (-not $realm.adminPermissionsEnabled) {
    Kc PUT '' @{ realm = 'lab'; adminPermissionsEnabled = $true } | Out-Null
    Write-Host 'enabled  admin permissions (v2) on realm lab'
}

# Approver group.
if (-not (Get-Group 'app1-approvers')) { Kc POST '/groups' @{ name = 'app1-approvers' } | Out-Null; Write-Host 'created  group app1-approvers' }
$gApprovers = Get-Group 'app1-approvers'
$gDevs = Get-Group 'app1-devs'
if (-not $gDevs) { throw 'group app1-devs is missing from realm lab' }

# LAB-ONLY approver "carol".
$carol = (KcList '/users?username=carol&exact=true') | Select-Object -First 1
if (-not $carol) {
    Kc POST '/users' @{ username = 'carol'; enabled = $true; email = 'carol@lab.localhost'; emailVerified = $true; firstName = 'Carol'; lastName = 'Lab' } | Out-Null
    $carol = (KcList '/users?username=carol&exact=true') | Select-Object -First 1
    Write-Host 'created  user carol'
}
Kc PUT ('/users/{0}/reset-password' -f $carol.id) @{ type = 'password'; value = (Read-Secret 'keycloak_carol_password'); temporary = $false } | Out-Null
Kc PUT ('/users/{0}/groups/{1}' -f $carol.id, $gApprovers.id) | Out-Null
Write-Host 'ok       carol in app1-approvers (password: secrets\keycloak_carol_password, LAB-ONLY)'

# Phase 6b: write access. app1-devs-rw is filled only by the portal; app1-write-approvers is a
# separate, smaller group (carol approves read access, not write access).
foreach ($g in @('app1-devs-rw', 'app1-write-approvers')) {
    if (-not (Get-Group $g)) { Kc POST '/groups' @{ name = $g } | Out-Null; Write-Host ('created  group {0}' -f $g) }
}
$gDevsRw = Get-Group 'app1-devs-rw'
$gWriteApprovers = Get-Group 'app1-write-approvers'
# LAB-ONLY write approver "dave".
$dave = (KcList '/users?username=dave&exact=true') | Select-Object -First 1
if (-not $dave) {
    Kc POST '/users' @{ username = 'dave'; enabled = $true; email = 'dave@lab.localhost'; emailVerified = $true; firstName = 'Dave'; lastName = 'Lab' } | Out-Null
    $dave = (KcList '/users?username=dave&exact=true') | Select-Object -First 1
    Write-Host 'created  user dave'
}
Kc PUT ('/users/{0}/reset-password' -f $dave.id) @{ type = 'password'; value = (Read-Secret 'keycloak_dave_password'); temporary = $false } | Out-Null
Kc PUT ('/users/{0}/groups/{1}' -f $dave.id, $gWriteApprovers.id) | Out-Null
Write-Host 'ok       dave in app1-write-approvers (password: secrets\keycloak_dave_password, LAB-ONLY)'

# Interactive client of the portal.
$null = Set-Client @{
    clientId = 'portal'; name = 'Access approval portal (phase 6, interactive login)'; enabled = $true; protocol = 'openid-connect'
    publicClient = $false; clientAuthenticatorType = 'client-secret'; secret = (Read-Secret 'keycloak_portal_client_secret')
    standardFlowEnabled = $true; implicitFlowEnabled = $false; directAccessGrantsEnabled = $false; serviceAccountsEnabled = $false
    fullScopeAllowed = $false; frontchannelLogout = $true
    redirectUris = @('http://localhost:8090/signin-oidc', 'http://127.0.0.1:8090/signin-oidc')
    webOrigins = @()
    attributes = @{ 'pkce.code.challenge.method' = 'S256'; 'post.logout.redirect.uris' = 'http://localhost:8090/##http://127.0.0.1:8090/' }
} @($groupsMapper)

# Service account for group membership changes.
$gm = Set-Client @{
    clientId = 'portal-group-manager'; name = 'Access approval portal: app1-devs membership (service account)'; enabled = $true; protocol = 'openid-connect'
    publicClient = $false; clientAuthenticatorType = 'client-secret'; secret = (Read-Secret 'keycloak_portal_group_manager_secret')
    standardFlowEnabled = $false; implicitFlowEnabled = $false; directAccessGrantsEnabled = $false; serviceAccountsEnabled = $true
    fullScopeAllowed = $false; redirectUris = @(); webOrigins = @()
}
$adminScope = (KcList '/client-scopes') | Where-Object { $_.name -eq 'kc-admin-api' } | Select-Object -First 1
if (-not $adminScope) { throw 'client scope kc-admin-api not found (Keycloak older than 26.4?)' }
Kc PUT ('/clients/{0}/default-client-scopes/{1}' -f $gm.id, $adminScope.id) | Out-Null
# Exactly one realm-management role: view-users (read-only; it includes query-users and
# query-groups). Measured on Keycloak 26.8.2: with resource-scoped fine-grained permissions
# alone (Groups app1-devs view/view-members, even Users view), the list endpoints the portal
# needs (group search, group members) return an empty list. Reads therefore come from
# view-users; every WRITE is still limited to app1-devs by the permissions below. Any other role
# that a previous run or a person added is removed.
$keepRole = 'view-users'
$sa = Kc GET ('/clients/{0}/service-account-user' -f $gm.id)
$rm = Get-Client 'realm-management'
$role = (KcList ('/clients/{0}/roles' -f $rm.id)) | Where-Object { $_.name -eq $keepRole } | Select-Object -First 1
foreach ($kind in @('user', 'scope')) {
    # user: the service account's role mappings. scope: the client's scope mappings (fullScopeAllowed
    # is off, so a role reaches the token only through both).
    $path = if ($kind -eq 'user') { '/users/{0}/role-mappings/clients/{1}' -f $sa.id, $rm.id } else { '/clients/{0}/scope-mappings/clients/{1}' -f $gm.id, $rm.id }
    $have = @(KcList $path)
    $extra = @($have | Where-Object { $_.name -ne $keepRole })
    if ($extra.Count -gt 0) {
        Kc DELETE $path @($extra | ForEach-Object { @{ id = $_.id; name = $_.name } }) | Out-Null
        Write-Host ('removed  realm-management {0} mappings of portal-group-manager: {1}' -f $kind, (($extra | ForEach-Object { $_.name }) -join ', '))
    }
    if (-not ($have | Where-Object { $_.name -eq $keepRole })) {
        Kc POST $path @(@{ id = $role.id; name = $role.name }) | Out-Null
        Write-Host ('granted  realm-management {0} to portal-group-manager ({1} mapping)' -f $keepRole, $kind)
    }
}

# LAB-ONLY: token source for tests\phase6-checks.ps1 (audience "portal").
$null = Set-Client @{
    clientId = 'portal-test'; name = 'LAB-ONLY: direct-access-grant client for the portal tests'; enabled = $true; protocol = 'openid-connect'
    publicClient = $true; standardFlowEnabled = $false; implicitFlowEnabled = $false; directAccessGrantsEnabled = $true; serviceAccountsEnabled = $false
    fullScopeAllowed = $false; redirectUris = @(); webOrigins = @()
} @($groupsMapper, @{
    name = 'audience-portal'; protocol = 'openid-connect'; protocolMapper = 'oidc-audience-mapper'; consentRequired = $false
    config = @{ 'included.custom.audience' = 'portal'; 'access.token.claim' = 'true'; 'id.token.claim' = 'false'; 'introspection.token.claim' = 'true' }
})

# Fine-grained admin permissions for the service account.
$ap = Get-Client 'admin-permissions'
if (-not $ap) { throw 'client admin-permissions not found: admin permissions are not enabled on realm lab' }
$rs = '/clients/{0}/authz/resource-server' -f $ap.id
$polName = 'portal-group-manager service account'
$pol = (KcList ($rs + '/policy?max=200')) | Where-Object { $_.name -eq $polName } | Select-Object -First 1
$polBody = @{ name = $polName; description = 'Phase 6: the approval portal service account'; clients = @($gm.id); logic = 'POSITIVE' }
if (-not $pol) { $pol = Kc POST ($rs + '/policy/client') $polBody; Write-Host 'created  policy portal-group-manager' }
else { $polBody.id = $pol.id; Kc PUT ($rs + '/policy/client/' + $pol.id) $polBody | Out-Null }

function Set-Permission {
    param([string]$Name, [string]$Description, [string]$ResourceType, [string[]]$Resources, [string[]]$Scopes)
    $body = @{ name = $Name; description = $Description; resourceType = $ResourceType; resources = @($Resources); scopes = @($Scopes); policies = @($pol.id); decisionStrategy = 'UNANIMOUS' }
    $p = (KcList ($rs + '/permission?max=200')) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if (-not $p) { Kc POST ($rs + '/permission/scope') $body | Out-Null; Write-Host ('created  permission "{0}"' -f $Name) }
    else { $body.id = $p.id; Kc PUT ($rs + '/permission/scope/' + $p.id) $body | Out-Null; Write-Host ('updated  permission "{0}"' -f $Name) }
}
Set-Permission 'portal: app1-devs membership' 'The approval portal may add users to and remove users from app1-devs and app1-devs-rw.' 'Groups' @($gDevs.id, $gDevsRw.id) @('manage-membership')
Set-Permission 'portal: user group membership' 'Needed together with manage-membership on the group; limited to app1-devs and app1-devs-rw by that permission.' 'Users' @() @('manage-group-membership')

# ---- Phase 6b: write path, database and OpenBao -------------------------------------------------
Write-Host '== Phase 6b: PostgreSQL write access (debug_rw, dev_audit)'
$P2ComposeFile = Join-Path $root 'compose.phase5.yaml'
$P2Project = $Project
$P2BaoSecretPrefix = 'openbao_phase5'
. (Join-Path $PSScriptRoot 'phase2-lib.ps1')
$pgP = (& docker ps -q --filter ('label=com.docker.compose.project=' + $Project) --filter 'label=com.docker.compose.service=pg-primary' | Select-Object -First 1)
if (-not $pgP) { throw 'no running pg-primary container in project ' + $Project }
$r = Invoke-Docker @('exec', '-u', 'postgres', $pgP, 'bash', '/opt/phase6/write-access.sh')
if ($r.Code -ne 0) { throw ('phase6-write-access.sh failed (is pg-primary recreated with compose.phase6.yaml?): ' + $r.All) }
Write-Host $r.All
# The pg_hba file comes from compose.phase6.yaml; make sure the running server uses it.
$r = Invoke-Docker @('exec', '-u', 'postgres', $pgP, 'psql', '-X', '-At', '-d', 'postgres', '-c', "SELECT count(*) FROM pg_hba_file_rules WHERE 'debug_rw' = ANY (user_name) OR '+debug_rw' = ANY (user_name)")
if ($r.Out.Trim() -ne '2') { throw ('pg-primary pg_hba has no debug_rw lines; recreate it: docker compose -f compose.phase5.yaml -f compose.phase6.yaml up -d pg-primary (' + $r.All + ')') }
Write-Host 'ok       pg-primary pg_hba: +debug_rw allowed from rw-access only'

Write-Host '== Phase 6b: OpenBao role app1-pg-rw, policy app1-write, group app1-devs-rw'
$baoRoot = Read-P2Secret $P2BaoRootTokenName
function BaoOk {
    param([string[]]$A, [string]$Stdin = $null)
    $x = Invoke-Bao $A $baoRoot $Stdin
    if ($x.Code -ne 0) { throw ('bao {0} failed: {1}' -f ($A -join ' '), $x.All) }
    return $x
}
# Only allowed_roles changes; OpenBao merges into the stored connection (bao_admin password kept).
# phase2-setup.ps1 (run again by every phase 5 setup) resets it to app1-pg-ro; this puts it back.
BaoOk @('write', 'database/config/app1-pg', 'allowed_roles=app1-pg-ro,app1-pg-rw') | Out-Null
Write-Host 'ok       database/config/app1-pg allowed_roles: app1-pg-ro, app1-pg-rw'

# Temp users ON THE PRIMARY, member of debug_rw. One session at a time, short timeouts (a stuck
# lock on the primary hurts the application). enable_session_audit() sets full pgAudit logging on
# the role itself; if it fails, the whole creation fails and no credentials are issued.
$PgRwCreation = 'CREATE ROLE "{{name}}" LOGIN PASSWORD ''{{password}}'' VALID UNTIL ''{{expiration}}'' CONNECTION LIMIT 1; ' +
    'GRANT debug_rw TO "{{name}}"; ' +
    'ALTER ROLE "{{name}}" SET statement_timeout = ''60s''; ' +
    'ALTER ROLE "{{name}}" SET lock_timeout = ''5s''; ' +
    'ALTER ROLE "{{name}}" SET idle_in_transaction_session_timeout = ''2min''; ' +
    'ALTER ROLE "{{name}}" SET idle_session_timeout = ''15min''; ' +
    'SELECT dev_audit.enable_session_audit(''{{name}}'');'
$PgRwRevocation = 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ''{{name}}''; DROP ROLE IF EXISTS "{{name}}";'
BaoOk @('write', 'database/roles/app1-pg-rw', 'db_name=app1-pg', 'default_ttl=30m', 'max_ttl=30m',
    ('creation_statements=' + $PgRwCreation), ('revocation_statements=' + $PgRwRevocation)) | Out-Null
Write-Host 'ok       database/roles/app1-pg-rw (default_ttl 30m, max_ttl 30m)'

$policy = [System.IO.File]::ReadAllText((Join-Path $root 'config\openbao\app1-write.hcl'), $utf8)
BaoOk @('policy', 'write', 'app1-write', '-') $policy | Out-Null
Write-Host 'ok       policy app1-write'

# Same identity layout as app1-devs (phase2-setup.ps1): one external group per auth mount with
# the alias "app1-devs-rw" (the Keycloak group name in the groups claim), both members of the
# internal group app1-devs-rw, which carries the policy.
$auths = (BaoOk @('auth', 'list', '-format=json')).Out | ConvertFrom-Json
$memberIds = @()
foreach ($m in @('oidc', 'jwt')) {
    $acc = $auths.($m + '/').accessor
    $gname = 'app1-devs-rw-' + $m
    $g = ConvertFrom-JsonOrNull (Invoke-Bao @('read', '-format=json', ('identity/group/name/' + $gname)) $baoRoot).Out
    if ($null -eq $g) {
        BaoOk @('write', 'identity/group', ('name=' + $gname), 'type=external') | Out-Null
        $g = ConvertFrom-JsonOrNull (BaoOk @('read', '-format=json', ('identity/group/name/' + $gname))).Out
    }
    if ($g.data.type -ne 'external') { throw ('identity group {0} exists but is not external' -f $gname) }
    $memberIds += $g.data.id
    if (-not (($null -ne $g.data.alias) -and ($g.data.alias.name -eq 'app1-devs-rw') -and ($g.data.alias.mount_accessor -eq $acc))) {
        BaoOk @('write', 'identity/group-alias', 'name=app1-devs-rw', ('mount_accessor=' + $acc), ('canonical_id=' + $g.data.id)) | Out-Null
    }
}
BaoOk @('write', 'identity/group/name/app1-devs-rw', 'type=internal', 'policies=app1-write', ('member_group_ids=' + ($memberIds -join ','))) | Out-Null
Write-Host 'ok       identity group app1-devs-rw (internal): policy app1-write, members app1-devs-rw-oidc, app1-devs-rw-jwt'

# ---- Portal -----------------------------------------------------------------------------------
Write-Host '== Phase 6: portal'
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$last = ''
while ($true) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri ($PortalUrl + '/readyz') -TimeoutSec 10
        if ($r.StatusCode -eq 200) { break }
    } catch {
        $last = $_.ErrorDetails.Message
        if (-not $last) { $last = $_.Exception.Message }
    }
    if ((Get-Date) -gt $deadline) { throw ('portal not ready after {0}s: {1}. See docker compose -f compose.phase5.yaml -f compose.phase6.yaml logs portal' -f $WaitSeconds, $last) }
    Start-Sleep -Seconds 3
}
Write-Host 'ready    portal'
Write-Host 'phase6-setup: done. Portal: http://localhost:8090 (requesters: any realm user; approver: carol).'
