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
#   3. waits until the portal answers /readyz (its service account sees app1-devs).
# Windows PowerShell 5.1 compatible. Secrets are sent to Keycloak in request bodies only.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not $SkipPhase5) {
    & (Join-Path $PSScriptRoot 'phase5-setup.ps1') -TimeoutSeconds $TimeoutSeconds
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Read-Secret { param([string]$Name) return [System.IO.File]::ReadAllText((Join-Path $root ('secrets\' + $Name)), $utf8).Trim() }
foreach ($n in @('keycloak_admin_password', 'keycloak_portal_client_secret', 'keycloak_portal_group_manager_secret', 'keycloak_carol_password')) {
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
Set-Permission 'portal: app1-devs membership' 'The approval portal may add users to and remove users from app1-devs.' 'Groups' @($gDevs.id) @('manage-membership')
Set-Permission 'portal: user group membership' 'Needed together with manage-membership on the group; limited to app1-devs by that permission.' 'Users' @() @('manage-group-membership')

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
