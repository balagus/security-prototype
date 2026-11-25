[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype',
    [string]$BaoSecretPrefix = 'openbao',
    [string]$PortalUrl = 'http://127.0.0.1:8090',
    [string]$KeycloakUrl = 'http://127.0.0.1:8180',
    # How long to wait for a record to reach log-store.
    [int]$ShipWaitSeconds = 30,
    # The portal's reconcile interval in compose.yaml (Portal__ReconcileSeconds).
    [int]$ReconcileSeconds = 15
)

# Portal checks (docs/DECISIONS.md D11) against the RUNNING stack (compose.yaml after
# scripts\setup.ps1): the access approval portal.
#   1. sign-in surface: OIDC redirect with PKCE, no anonymous API, CSRF header, Bearer audience
#   2. input rules: ticket, reason, duration, app, standing members
#   3. approval: nobody approves their own request, only app1-approvers decide, approval adds the
#      app1-devs membership, OpenBao then issues credentials to the requester, revocation removes it
#   4. deny and withdraw
#   5. expiry removes the membership within one reconcile interval
#   6. drift: a membership added outside the portal is removed and raises an alert
#   7. the service account can change app1-devs membership and nothing else
#   8. isolation of the portal container (networks, user, mounts, ports)
#   9. audit: every step is in log-store with ticket and approver, alerts in alerts.jsonl
#  10. requests survive a portal restart
# Test users: bob (requester), carol (approver), alice (standing app1-devs member, not an
# approver). Passwords come from the LAB-ONLY realm seed and secrets\keycloak_carol_password.
# Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.yaml' }
$LabComposeFile = $ComposeFile
$LabProject = $Project
$LabBaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $root 'scripts\lib.ps1')

$curlImage = 'curlimages/curl:8.22.0'
$volStore = $LabProject + '_log-store'
$realmFile = Join-Path $LabRoot 'config\keycloak\lab-realm.json'
$realm = [System.IO.File]::ReadAllText($realmFile, $LabUtf8NoBom) | ConvertFrom-Json
$runTag = (Get-Date).ToString('HHmmss')

$script:Pass = 0
$script:Fail = 0
$script:BaoTokens = New-Object System.Collections.ArrayList

function Write-Result {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) { $script:Pass++; $tag = 'PASS'; $color = 'Green' } else { $script:Fail++; $tag = 'FAIL'; $color = 'Red' }
    Write-Host ('{0} {1}' -f $tag, $Name) -ForegroundColor $color
    if ($Detail) { foreach ($l in ($Detail.Trim() -split "`r?`n")) { if ($l.Trim()) { Write-Host ('       | ' + $l.TrimEnd()) } } }
}
function Note { param([string]$Text) Write-Host ('       | ' + $Text) }
function Section { param([string]$T) Write-Host ''; Write-Host ('== ' + $T) -ForegroundColor Cyan }
function Short { param([string]$T, [int]$N = 300) if (-not $T) { return '' }; if ($T.Length -le $N) { return $T }; return $T.Substring(0, $N) + '...' }

function Get-TestPassword {
    param([string]$User)
    if ($User -eq 'carol') { return Read-LabSecret 'keycloak_carol_password' }
    return [string](($realm.users | Where-Object { $_.username -eq $User }).credentials[0].value)
}

# Access token of the LAB-ONLY client portal-test (audience "portal").
function Get-PortalToken {
    param([string]$User)
    $body = @{ grant_type = 'password'; client_id = 'portal-test'; username = $User; password = (Get-TestPassword $User); scope = 'openid' }
    return [string](Invoke-RestMethod -Method Post -Uri ($KeycloakUrl + '/realms/lab/protocol/openid-connect/token') -Body $body -TimeoutSec 15).access_token
}

# Returns @{ Code; Body (parsed JSON or $null); Raw; Headers }. Never throws.
function Invoke-Portal {
    param([string]$Method, [string]$Path, [string]$Token = '', $Body = $null, [switch]$NoCsrf, [hashtable]$Headers = @{}, [switch]$NoRedirect)
    if ($NoRedirect) {
        # Windows PowerShell 5.1 returns a 3xx with -MaximumRedirection 0 only when the
        # "redirect limit exceeded" error is not turned into an exception.
        $r = Invoke-WebRequest -UseBasicParsing -Method $Method -Uri ($PortalUrl + $Path) -MaximumRedirection 0 -TimeoutSec 30 -ErrorAction SilentlyContinue
        if ($null -eq $r) { return @{ Code = -1; Body = $null; Raw = 'no response'; Headers = @{} } }
        return @{ Code = [int]$r.StatusCode; Body = $null; Raw = $r.Content; Headers = $r.Headers }
    }
    $h = @{}
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    if ($Token) { $h['Authorization'] = 'Bearer ' + $Token }
    if ($Method -ne 'GET' -and -not $NoCsrf) { $h['X-Portal-Request'] = '1' }
    $p = @{ UseBasicParsing = $true; Method = $Method; Uri = ($PortalUrl + $Path); Headers = $h; TimeoutSec = 30; MaximumRedirection = 0 }
    if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Compress)) }
    elseif ($Method -ne 'GET') { $p.ContentType = 'application/json'; $p.Body = '{}' }
    try {
        $r = Invoke-WebRequest @p
        return @{ Code = [int]$r.StatusCode; Body = (ConvertFrom-JsonOrNull $r.Content); Raw = $r.Content; Headers = $r.Headers }
    } catch {
        $resp = $_.Exception.Response
        if ($resp) {
            $raw = $_.ErrorDetails.Message
            if (-not $raw) {
                try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $raw = $sr.ReadToEnd(); $sr.Dispose() } catch { $raw = '' }
            }
            $hdr = @{}
            foreach ($k in $resp.Headers.AllKeys) { $hdr[$k] = $resp.Headers[$k] }
            return @{ Code = [int]$resp.StatusCode; Body = (ConvertFrom-JsonOrNull $raw); Raw = $raw; Headers = $hdr }
        }
        return @{ Code = -1; Body = $null; Raw = $_.Exception.Message; Headers = @{} }
    }
}
function Show { param($R) return ('HTTP {0}: {1}' -f $R.Code, (Short $R.Raw 240)) }

# ---- Keycloak admin (master realm admin; the test's own view, not the portal's) -----------------
$script:KcTok = $null; $script:KcTokAt = [DateTime]::MinValue
function Get-KcHeaders {
    if (-not $script:KcTok -or ((Get-Date) - $script:KcTokAt).TotalSeconds -gt 40) {
        $b = @{ grant_type = 'password'; client_id = 'admin-cli'; username = 'admin'; password = (Read-LabSecret 'keycloak_admin_password') }
        $script:KcTok = (Invoke-RestMethod -Method Post -Uri ($KeycloakUrl + '/realms/master/protocol/openid-connect/token') -Body $b -TimeoutSec 15).access_token
        $script:KcTokAt = Get-Date
    }
    return @{ Authorization = 'Bearer ' + $script:KcTok }
}
$KA = $KeycloakUrl + '/admin/realms/lab'
function KcGet { param([string]$Path) $r = Invoke-RestMethod -Uri ($KA + $Path) -Headers (Get-KcHeaders) -TimeoutSec 15; return @($r | ForEach-Object { $_ }) }
function Get-KcUserId { param([string]$U) return (KcGet ('/users?username={0}&exact=true' -f $U))[0].id }
function Get-KcGroupId { param([string]$G) return ((KcGet ('/groups?search={0}&exact=true' -f $G)) | Where-Object { $_.name -eq $G })[0].id }
function Get-KcMembers { param([string]$G) return @((KcGet ('/groups/{0}/members?max=500' -f (Get-KcGroupId $G))) | ForEach-Object { $_.username }) }
function Test-Member { param([string]$U, [string]$G = 'app1-devs') return (@(Get-KcMembers $G) -contains $U) }

# ---- OpenBao as a developer (jwt auth method, id token of the LAB-ONLY client bao-jwt-test) ------
function Get-IdToken {
    param([string]$User)
    $body = @{ grant_type = 'password'; client_id = 'bao-jwt-test'; username = $User; password = (Get-TestPassword $User); scope = 'openid' }
    return [string](Invoke-RestMethod -Method Post -Uri ($KeycloakUrl + '/realms/lab/protocol/openid-connect/token') -Body $body -TimeoutSec 15).id_token
}
function Connect-Bao {
    param([string]$User)
    $r = Invoke-Bao @('write', '-format=json', 'auth/jwt/login', 'role=dev', 'jwt=-') '' (Get-IdToken $User)
    $o = ConvertFrom-JsonOrNull $r.Out
    $tok = $null
    if (($r.Code -eq 0) -and ($null -ne $o)) { $tok = [string]$o.auth.client_token; [void]$script:BaoTokens.Add($tok) }
    return @{ R = $r; Token = $tok; Policies = $(if ($o) { @($o.auth.identity_policies) + @($o.auth.policies) } else { @() }) }
}
function Read-Creds {
    param([string]$Token, [string]$Role)
    $r = Invoke-Bao @('read', '-format=json', ('database/creds/' + $Role)) $Token
    $o = ConvertFrom-JsonOrNull $r.Out
    return @{ Ok = (($r.Code -eq 0) -and $null -ne $o -and $o.data.username); User = $(if ($o) { [string]$o.data.username } else { '' }); Lease = $(if ($o) { [string]$o.lease_id } else { '' }); All = $r.All }
}
function Close-Bao { param([string]$Token) if ($Token) { [void](Invoke-Bao @('token', 'revoke', '-self') $Token) } }

# ---- audit store (read through a throwaway container that mounts log-store read-only) -----------
$findScript = @'
end=$(( $(date +%s) + WAIT ))
while :; do
  out="$(cat "/store/$F" 2>/dev/null)"
  for v in N1 N2 N3 N4; do eval "n=\${$v:-}"; [ -n "$n" ] && out="$(printf '%s\n' "$out" | grep -F -- "$n")"; done
  if [ -n "$out" ]; then printf '%s\n' "$out"; exit 0; fi
  [ "$(date +%s)" -ge "$end" ] && exit 1
  sleep 1
done
'@
function Find-InStore {
    param([string[]]$Needles, [string]$File = 'audit.jsonl', [int]$Wait = $ShipWaitSeconds)
    $envs = @{ WAIT = [string]$Wait; F = $File }
    $a = @('run', '--rm', '--network', 'none', '-v', ($volStore + ':/store:ro'), '-e', 'WAIT', '-e', 'F')
    $i = 0
    foreach ($n in $Needles) { $i++; $envs[('N' + $i)] = $n; $a += @('-e', ('N' + $i)) }
    $a += @('--entrypoint', 'bash', 'postgres:17', '-c', $findScript)
    $r = Invoke-Docker $a $envs ($Wait + 60)
    $objs = @()
    foreach ($l in ($r.Out -split "`r?`n")) { if ($l.Trim().StartsWith('{')) { $o = ConvertFrom-JsonOrNull $l; if ($o) { $objs += $o } } }
    return $objs
}

function Get-PortalContainer {
    $r = Invoke-Docker @('ps', '-a', '-q', '--filter', ('label=com.docker.compose.project=' + $LabProject), '--filter', 'label=com.docker.compose.service=portal')
    $id = ($r.Out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $id) { throw 'No portal container. Start the stack with compose.yaml.' }
    return $id.Trim()
}

# =================================================================================================
Section '0. Preconditions'
$health = Invoke-Portal GET '/healthz'
$ready = Invoke-Portal GET '/readyz'
Write-Result (($health.Code -eq 200) -and ($ready.Code -eq 200)) 'portal answers /healthz and /readyz (its service account sees app1-devs)' ((Show $health) + "`n" + (Show $ready))
$bs = Get-BaoStatus
Write-Result (($bs.Code -eq 0) -and ($bs.Obj.sealed -eq $false)) 'OpenBao is unsealed' (Short $bs.All 200)
if ($ready.Code -ne 200 -or $bs.Code -ne 0) { Write-Host 'Run scripts\setup-portal.ps1 first.' -ForegroundColor Red; exit 1 }

$tBob = Get-PortalToken 'bob'; $tCarol = Get-PortalToken 'carol'; $tAlice = Get-PortalToken 'alice'
# Leftovers of an earlier run: bob's open requests end, bob leaves app1-devs.
$old = Invoke-Portal GET '/api/requests?scope=all' $tCarol
foreach ($x in @($old.Body | ForEach-Object { $_ })) {
    if ($x.requester -eq 'bob' -and $x.status -eq 'pending') { [void](Invoke-Portal POST ('/api/requests/' + $x.id + '/cancel') $tBob) }
    if ($x.requester -eq 'bob' -and $x.status -eq 'active') { [void](Invoke-Portal POST ('/api/requests/' + $x.id + '/revoke') $tCarol @{ comment = 'test cleanup' }) }
    if ($x.requester -eq 'carol' -and $x.status -eq 'pending') { [void](Invoke-Portal POST ('/api/requests/' + $x.id + '/cancel') $tCarol) }
}
$devs = Get-KcMembers 'app1-devs'
$approvers = Get-KcMembers 'app1-approvers'
Write-Result ((-not ($devs -contains 'bob')) -and ($devs -contains 'alice') -and ($approvers -contains 'carol') -and -not ($approvers -contains 'bob') -and -not ($approvers -contains 'alice')) 'start state: app1-devs = alice (standing) and not bob; app1-approvers has carol, not bob or alice' ('app1-devs: ' + ($devs -join ', ') + "`napp1-approvers: " + ($approvers -join ', '))

# =================================================================================================
Section '1. Sign-in surface'
$r = Invoke-Portal GET '/api/me'
Write-Result ($r.Code -eq 401) 'no session, no token: /api/me is 401 (no anonymous API)' (Show $r)
$r = Invoke-Portal GET '/signin' -NoRedirect
$loc = [string]$r.Headers['Location']
# .NET 10 pushes the authorization request to Keycloak first (PAR, RFC 9126): the browser URL
# carries only client_id and a request_uri; response_type, redirect_uri and the PKCE challenge
# travel server to server.
$ok = ($r.Code -eq 302) -and ($loc -like 'http://keycloak.localhost:8180/realms/lab/protocol/openid-connect/auth?*') -and ($loc -match 'client_id=portal(&|$)') -and ($loc -match 'request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri')
Write-Result $ok '/signin redirects to Keycloak with a pushed authorization request (client portal, request_uri only)' ('HTTP ' + $r.Code + ' Location: ' + (Short $loc 260))
$pc = (KcGet '/clients?clientId=portal')[0]
Write-Result (($pc.attributes.'pkce.code.challenge.method' -eq 'S256') -and $pc.standardFlowEnabled -and -not $pc.implicitFlowEnabled -and -not $pc.directAccessGrantsEnabled -and -not $pc.publicClient) 'Keycloak client portal: confidential, code flow only, PKCE S256 enforced by Keycloak' ('pkce=' + $pc.attributes.'pkce.code.challenge.method' + ' standard=' + $pc.standardFlowEnabled + ' implicit=' + $pc.implicitFlowEnabled + ' password-grant=' + $pc.directAccessGrantsEnabled + ' public=' + $pc.publicClient)
$r = Invoke-Portal GET '/signin?returnUrl=//evil.example/' -NoRedirect
Write-Result (($r.Code -eq 302) -and ([string]$r.Headers['Location'] -like 'http://keycloak.localhost:8180/*')) '/signin with an off-site returnUrl still goes to Keycloak (the target is reduced to "/")' ('HTTP ' + $r.Code)
$r = Invoke-Portal GET '/'
$csp = [string]$r.Headers['Content-Security-Policy']
Write-Result (($r.Code -eq 200) -and ($r.Raw -match '<app-root>') -and ($csp -match "default-src 'self'") -and ($csp -match "frame-ancestors 'none'")) 'the UI is served with a restrictive Content-Security-Policy' ('HTTP ' + $r.Code + ' CSP: ' + $csp)
$baoTok = Get-IdToken 'bob'
$r = Invoke-Portal GET '/api/me' $baoTok
Write-Result ($r.Code -eq 401) 'a Keycloak token for another client (bao-jwt-test id token, audience not "portal") is refused' (Show $r)
$r = Invoke-Portal GET '/api/me' 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.'
Write-Result ($r.Code -eq 401) 'an unsigned token is refused' (Show $r)
$r = Invoke-Portal POST '/api/requests' $tBob @{ app = 'app1'; ticket = 'OPS-1'; reason = 'csrf check, should not be created'; durationMinutes = 60 } -NoCsrf
Write-Result ($r.Code -eq 400 -and $r.Raw -match 'X-Portal-Request') 'a state change without the X-Portal-Request header is refused (CSRF guard)' (Show $r)
$mb = Invoke-Portal GET '/api/me' $tBob
$mc = Invoke-Portal GET '/api/me' $tCarol
$ma = Invoke-Portal GET '/api/me' $tAlice
Write-Result (($mb.Body.isApprover -eq $false) -and ($mc.Body.isApprover -eq $true) -and ($ma.Body.isApprover -eq $false)) 'approver role comes from the Keycloak group app1-approvers: carol yes, bob and alice no' ('bob: ' + $mb.Raw + "`ncarol isApprover=" + $mc.Body.isApprover + ', alice isApprover=' + $ma.Body.isApprover)
$r = Invoke-Portal GET '/api/requests?scope=all' $tBob
Write-Result ($r.Code -eq 403) 'only approvers can list all requests' (Show $r)

# =================================================================================================
Section '2. Input rules'
$good = @{ app = 'app1'; ticket = 'OPS-' + $runTag; reason = 'Investigate order totals for a customer complaint'; durationMinutes = 60 }
foreach ($c in @(
        @{ N = 'ticket "hello"'; B = @{ app = 'app1'; ticket = 'hello'; reason = $good.reason; durationMinutes = 60 } },
        @{ N = 'ticket with SQL characters'; B = @{ app = 'app1'; ticket = "OPS-1';--"; reason = $good.reason; durationMinutes = 60 } },
        @{ N = 'reason shorter than 10 characters'; B = @{ app = 'app1'; ticket = 'OPS-1'; reason = 'debug'; durationMinutes = 60 } },
        @{ N = 'duration 241 min (over the 4 h maximum)'; B = @{ app = 'app1'; ticket = 'OPS-1'; reason = $good.reason; durationMinutes = 241 } },
        @{ N = 'duration 0'; B = @{ app = 'app1'; ticket = 'OPS-1'; reason = $good.reason; durationMinutes = 0 } },
        @{ N = 'unknown app'; B = @{ app = 'app2'; ticket = 'OPS-1'; reason = $good.reason; durationMinutes = 60 } })) {
    $r = Invoke-Portal POST '/api/requests' $tBob $c.B
    Write-Result ($r.Code -eq 400) ('refused: ' + $c.N) (Show $r)
}
$r = Invoke-Portal POST '/api/requests' $tAlice $good
Write-Result ($r.Code -eq 409 -and $r.Raw -match 'standing access') 'alice (standing member of app1-devs) cannot open a request' (Show $r)

# =================================================================================================
Section '3. Approval, OpenBao, revocation'
$c0 = Connect-Bao 'bob'
$cr0 = Read-Creds $c0.Token 'app1-pg-ro'
Write-Result (($c0.Token) -and (-not $cr0.Ok) -and ($cr0.All -match 'permission denied')) 'baseline: bob can log in to OpenBao but may not read database/creds/app1-pg-ro' ('login exit ' + $c0.R.Code + "; read: " + (Short $cr0.All 200))
Close-Bao $c0.Token

$rA = Invoke-Portal POST '/api/requests' $tBob $good
$idA = [string]$rA.Body.id
Write-Result (($rA.Code -eq 201) -and ($rA.Body.status -eq 'pending') -and ($rA.Body.ticket -eq $good.ticket)) 'bob requests app1 for 60 min with a ticket: pending' (Show $rA)
$r = Invoke-Portal POST '/api/requests' $tBob $good
Write-Result ($r.Code -eq 409) 'a second request while one is pending is refused' (Show $r)
Write-Result (-not (Test-Member 'bob')) 'while pending, bob is not in app1-devs' ''

$r = Invoke-Portal POST ('/api/requests/' + $idA + '/approve') $tBob @{ comment = 'self' }
Write-Result ($r.Code -eq 403) 'bob cannot approve (not an approver; also his own request)' (Show $r)
$r = Invoke-Portal POST ('/api/requests/' + $idA + '/approve') $tAlice @{ comment = 'looks fine' }
Write-Result ($r.Code -eq 403) 'alice cannot approve (not in app1-approvers, even though she has standing access)' (Show $r)
$rC = Invoke-Portal POST '/api/requests' $tCarol @{ app = 'app1'; ticket = 'OPS-' + $runTag; reason = 'Approver tries to grant herself access'; durationMinutes = 60 }
$idC = [string]$rC.Body.id
$r = Invoke-Portal POST ('/api/requests/' + $idC + '/approve') $tCarol @{ comment = 'self' }
Write-Result (($rC.Code -eq 201) -and ($r.Code -eq 403) -and ($r.Raw -match 'own request') -and -not (Test-Member 'carol')) 'carol (approver) cannot approve her own request; she stays out of app1-devs' ((Show $rC) + "`n" + (Show $r))
[void](Invoke-Portal POST ('/api/requests/' + $idC + '/cancel') $tCarol)

$t0 = Get-Date
$r = Invoke-Portal POST ('/api/requests/' + $idA + '/approve') $tCarol @{ comment = 'ok for ' + $good.ticket }
$exp = $null; if ($r.Body.expiresAt) { $exp = [DateTimeOffset]::Parse([string]$r.Body.expiresAt) }
$mins = if ($exp) { ($exp - [DateTimeOffset]::UtcNow).TotalMinutes } else { 0 }
Write-Result (($r.Code -eq 200) -and ($r.Body.status -eq 'active') -and ($r.Body.decidedBy -eq 'carol') -and ($mins -gt 58) -and ($mins -le 60.1)) 'carol approves: active, decided by carol, expires in 60 min' ((Show $r) + ("`nexpires in {0:N1} min" -f $mins))
Write-Result (Test-Member 'bob') 'bob is now in app1-devs (Keycloak admin view)' ('app1-devs: ' + ((Get-KcMembers 'app1-devs') -join ', '))

$c1 = Connect-Bao 'bob'
$cr1 = Read-Creds $c1.Token 'app1-pg-ro'
$cm1 = Read-Creds $c1.Token 'app1-maria-ro'
Write-Result ($cr1.Ok -and $cm1.Ok) 'bob logs in to OpenBao himself and reads app1-pg-ro and app1-maria-ro credentials' ('pg user ' + $cr1.User + ', maria user ' + $cm1.User + "`n" + $(if (-not $cr1.Ok) { Short $cr1.All 200 }))
Note ('approval to credentials: {0:N1} s' -f ((Get-Date) - $t0).TotalSeconds)
$r = Invoke-Portal POST '/api/requests' $tBob $good
Write-Result ($r.Code -eq 409) 'a new request while a grant is active is refused' (Show $r)

$r = Invoke-Portal POST ('/api/requests/' + $idA + '/revoke') $tCarol @{ comment = 'done, ticket closed' }
Write-Result (($r.Code -eq 200) -and ($r.Body.status -eq 'revoked') -and ($r.Body.endedBy -eq 'carol')) 'carol ends the grant early: revoked' (Show $r)
Write-Result (-not (Test-Member 'bob')) 'bob is out of app1-devs right away' ('app1-devs: ' + ((Get-KcMembers 'app1-devs') -join ', '))
# Documented limit (docs/DECISIONS.md D11): OpenBao learns about the group change only when the person
# logs in again. Until then the token bob already holds keeps the app1-debug policy.
$cr3 = Read-Creds $c1.Token 'app1-pg-ro'
Write-Result $cr3.Ok 'known limit: right after the revocation, the OpenBao token bob got BEFORE it still reads credentials' ('old token read: ' + $(if ($cr3.Ok) { 'allowed, user ' + $cr3.User } else { Short $cr3.All 200 }))
$rn = Invoke-Bao @('token', 'renew', '-format=json') $c1.Token
$cr4 = Read-Creds $c1.Token 'app1-pg-ro'
Note ('after "bao token renew" of the old token: exit {0}; read creds: {1}' -f $rn.Code, $(if ($cr4.Ok) { 'still allowed (a jwt token renewal does not re-read the groups)' } else { 'denied: ' + (Short $cr4.All 120) }))
$c2 = Connect-Bao 'bob'
$cr2 = Read-Creds $c2.Token 'app1-pg-ro'
Write-Result ((-not $cr2.Ok) -and ($cr2.All -match 'permission denied')) 'a new OpenBao login of bob no longer reads credentials' (Short $cr2.All 200)
Close-Bao $c2.Token
# The group is a property of bob's OpenBao entity, not of one token: the new login updated it.
$cr5 = Read-Creds $c1.Token 'app1-pg-ro'
Write-Result ((-not $cr5.Ok) -and ($cr5.All -match 'permission denied')) 'after that login the OLD token is cut too (the external group membership belongs to the entity and is re-evaluated per request)' ('old token read: ' + (Short $cr5.All 160))
Close-Bao $c1.Token

# =================================================================================================
Section '4. Deny and withdraw'
$rD = Invoke-Portal POST '/api/requests' $tBob @{ app = 'app1'; ticket = 'OPS-' + $runTag; reason = 'Second look at the same complaint'; durationMinutes = 120 }
$idD = [string]$rD.Body.id
$r = Invoke-Portal POST ('/api/requests/' + $idD + '/deny') $tCarol @{ comment = '' }
Write-Result ($r.Code -eq 400) 'a denial without a comment is refused' (Show $r)
$r = Invoke-Portal POST ('/api/requests/' + $idD + '/deny') $tCarol @{ comment = 'use the telemetry in Grafana first' }
Write-Result (($r.Code -eq 200) -and ($r.Body.status -eq 'denied') -and -not (Test-Member 'bob')) 'carol denies with a comment: denied, no membership' (Show $r)
$r = Invoke-Portal POST ('/api/requests/' + $idD + '/approve') $tCarol @{}
Write-Result ($r.Code -eq 409) 'a denied request cannot be approved afterwards' (Show $r)
$rE = Invoke-Portal POST '/api/requests' $tBob @{ app = 'app1'; ticket = 'OPS-' + $runTag; reason = 'Opened by mistake, will withdraw'; durationMinutes = 60 }
$idE = [string]$rE.Body.id
$r1 = Invoke-Portal POST ('/api/requests/' + $idE + '/cancel') $tCarol
$r2 = Invoke-Portal POST ('/api/requests/' + $idE + '/cancel') $tBob
$r3 = Invoke-Portal POST ('/api/requests/' + $idE + '/approve') $tCarol @{}
Write-Result (($r1.Code -eq 404) -and ($r2.Code -eq 200) -and ($r2.Body.status -eq 'cancelled') -and ($r3.Code -eq 409)) 'only the requester can withdraw; a withdrawn request cannot be approved' ('carol cancel: ' + (Show $r1) + "`nbob cancel: " + (Show $r2) + "`napprove after: " + (Show $r3))

# =================================================================================================
Section '5. Expiry'
$rB = Invoke-Portal POST '/api/requests' $tBob @{ app = 'app1'; ticket = 'OPS-' + $runTag; reason = 'Short grant to watch the expiry'; durationMinutes = 1 }
$idB = [string]$rB.Body.id
$r = Invoke-Portal POST ('/api/requests/' + $idB + '/approve') $tCarol @{ comment = 'expiry test' }
$expB = [DateTimeOffset]::Parse([string]$r.Body.expiresAt)
Write-Result (($r.Code -eq 200) -and (Test-Member 'bob')) '1-minute grant approved; bob in app1-devs' (Show $r)
$gone = $null
$deadline = $expB.AddSeconds($ReconcileSeconds + 20)
while ([DateTimeOffset]::UtcNow -lt $deadline) {
    if (([DateTimeOffset]::UtcNow -ge $expB) -and -not (Test-Member 'bob')) { $gone = [DateTimeOffset]::UtcNow; break }
    if (([DateTimeOffset]::UtcNow -lt $expB) -and -not (Test-Member 'bob')) { $gone = 'early'; break }
    Start-Sleep -Seconds 1
}
$lag = if ($gone -is [DateTimeOffset]) { ($gone - $expB).TotalSeconds } else { -1 }
$rb = Invoke-Portal GET '/api/requests' $tBob
$stB = (@($rb.Body | ForEach-Object { $_ }) | Where-Object { $_.id -eq $idB }).status
Write-Result (($gone -is [DateTimeOffset]) -and ($lag -le ($ReconcileSeconds + 5)) -and ($stB -eq 'expired')) ('at expiry the portal removes bob from app1-devs within one reconcile interval ({0} s): status expired' -f $ReconcileSeconds) ('membership gone {0:N1} s after expires_at; status {1}' -f $lag, $stB)
$c5 = Connect-Bao 'bob'
$cr5 = Read-Creds $c5.Token 'app1-pg-ro'
Write-Result (-not $cr5.Ok) 'after expiry a new OpenBao login of bob no longer reads credentials' (Short $cr5.All 160)
Close-Bao $c5.Token

# =================================================================================================
Section '6. Drift: membership added outside the portal'
$bobId = Get-KcUserId 'bob'
$devId = Get-KcGroupId 'app1-devs'
Invoke-RestMethod -Method Put -Uri ($KA + ('/users/{0}/groups/{1}' -f $bobId, $devId)) -Headers (Get-KcHeaders) | Out-Null
$tAdd = Get-Date
Write-Result (Test-Member 'bob') 'an administrator adds bob to app1-devs directly in Keycloak' ''
$removed = $null
while (((Get-Date) - $tAdd).TotalSeconds -lt ($ReconcileSeconds * 2 + 10)) {
    if (-not (Test-Member 'bob')) { $removed = ((Get-Date) - $tAdd).TotalSeconds; break }
    Start-Sleep -Seconds 1
}
Write-Result ($null -ne $removed) ('the portal removes the unapproved membership (within {0} s)' -f ($ReconcileSeconds * 2 + 10)) $(if ($removed) { 'removed after {0:N1} s' -f $removed } else { 'still a member' })
Write-Result (Test-Member 'alice') 'alice (standing member) is left alone' ''
$al = @(Find-InStore @('"engine":"portal"', '"alert":"portal_membership_drift"', '"requester":"bob"') 'alerts.jsonl')
Write-Result ($al.Count -gt 0) 'alert portal_membership_drift is in alerts.jsonl' $(if ($al.Count) { Short (ConvertTo-Json $al[-1] -Compress) 300 } else { 'not found' })

# =================================================================================================
Section '7. The portal service account can change app1-devs membership and nothing else'
$gmSecret = Read-LabSecret 'keycloak_portal_group_manager_secret'
$saTok = (Invoke-RestMethod -Method Post -Uri ($KeycloakUrl + '/realms/lab/protocol/openid-connect/token') -Body @{ grant_type = 'client_credentials'; client_id = 'portal-group-manager'; client_secret = $gmSecret } -TimeoutSec 15).access_token
function SA {
    param([string]$Method, [string]$Path, $Body = $null)
    $p = @{ UseBasicParsing = $true; Method = $Method; Uri = ($KA + $Path); Headers = @{ Authorization = 'Bearer ' + $saTok }; TimeoutSec = 15 }
    if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = (ConvertTo-Json -InputObject $Body -Compress -Depth 5) }
    try { return [int](Invoke-WebRequest @p).StatusCode } catch { if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }; return -1 }
}
$apprId = Get-KcGroupId 'app1-approvers'
$labId = Get-KcGroupId 'lab-users'
$rmId = (KcGet '/clients?clientId=realm-management')[0].id
$adminRole = (KcGet ('/clients/{0}/roles/realm-admin' -f $rmId))[0]
$codeAdd = SA PUT ('/users/{0}/groups/{1}' -f $bobId, $devId)
$codeDel = SA DELETE ('/users/{0}/groups/{1}' -f $bobId, $devId)
Write-Result (($codeAdd -eq 204) -and ($codeDel -eq 204)) 'allowed: add bob to app1-devs and remove him again' ('add ' + $codeAdd + ', remove ' + $codeDel)
foreach ($c in @(
        @{ N = 'add bob to app1-approvers'; M = 'PUT'; P = ('/users/{0}/groups/{1}' -f $bobId, $apprId) },
        @{ N = 'remove bob from lab-users'; M = 'DELETE'; P = ('/users/{0}/groups/{1}' -f $bobId, $labId) },
        @{ N = 'reset bob''s password'; M = 'PUT'; P = ('/users/{0}/reset-password' -f $bobId); B = @{ type = 'password'; value = 'x' + $runTag; temporary = $false } },
        @{ N = 'change bob''s profile'; M = 'PUT'; P = ('/users/{0}' -f $bobId); B = @{ firstName = 'Changed' } },
        @{ N = 'create a user'; M = 'POST'; P = '/users'; B = @{ username = 'sa-made-' + $runTag; enabled = $true } },
        @{ N = 'delete bob'; M = 'DELETE'; P = ('/users/{0}' -f $bobId) },
        @{ N = 'give bob the realm-admin role'; M = 'POST'; P = ('/users/{0}/role-mappings/clients/{1}' -f $bobId, $rmId); B = @(@{ id = $adminRole.id; name = 'realm-admin' }) },
        @{ N = 'create a group'; M = 'POST'; P = '/groups'; B = @{ name = 'sa-group-' + $runTag } },
        @{ N = 'list clients (read their secrets)'; M = 'GET'; P = '/clients' },
        @{ N = 'change the realm'; M = 'PUT'; P = ''; B = @{ realm = 'lab'; adminPermissionsEnabled = $false } })) {
    $code = SA $c.M $c.P $c.B
    Write-Result ($code -eq 403) ('refused: ' + $c.N) ('HTTP ' + $code)
}
Write-Result ((-not (Test-Member 'bob')) -and (-not (Test-Member 'bob' 'app1-approvers')) -and (@(KcGet ('/users?username=sa-made-' + $runTag)).Count -eq 0)) 'nothing changed in Keycloak (bob in neither group, no new user)' ''

# =================================================================================================
Section '8. Isolation of the portal container'
$pid_ = Get-PortalContainer
$insp = (ConvertFrom-JsonOrNull (Invoke-Docker @('inspect', $pid_)).Out)[0]
$nets = @($insp.NetworkSettings.Networks.PSObject.Properties.Name | Sort-Object)
Write-Result (($nets -join ',') -eq (($LabProject + '_portal-edge,' + $LabProject + '_portal-idp'))) 'networks: portal-edge and portal-idp only' ($nets -join ', ')
$mounts = @($insp.Mounts | Where-Object { $_.Type -eq 'volume' } | ForEach-Object { '{0}:{1}' -f $_.Name, $_.Destination })
$binds = @($insp.Mounts | Where-Object { $_.Type -ne 'volume' } | ForEach-Object { $_.Destination } | Sort-Object)
$okM = ($mounts.Count -eq 2) -and ($mounts -contains ($LabProject + '_portal-data:/data')) -and ($mounts -contains ($LabProject + '_portal-log:/var/log/portal')) -and (($binds -join ',') -eq '/run/secrets/keycloak_portal_client_secret,/run/secrets/keycloak_portal_group_manager_secret')
Write-Result $okM 'mounts: volumes portal-data and portal-log, and its two secrets (no audit store, no OpenBao or database volume)' (($mounts + $binds) -join ', ')
$ports = @($insp.HostConfig.PortBindings.PSObject.Properties | ForEach-Object { $k = $_.Name; $_.Value | ForEach-Object { '{0}:{1}->{2}' -f $_.HostIp, $_.HostPort, $k } })
Write-Result ((($ports -join ',') -eq '127.0.0.1:8090->8080/tcp') -and $insp.HostConfig.ReadonlyRootfs -and ($insp.Config.User -eq '1654:1654') -and (@($insp.HostConfig.CapDrop) -contains 'ALL')) 'published on 127.0.0.1:8090 only; read-only root, uid 1654, all capabilities dropped' ('ports ' + ($ports -join ',') + '; readonly ' + $insp.HostConfig.ReadonlyRootfs + '; user ' + $insp.Config.User + '; capdrop ' + (@($insp.HostConfig.CapDrop) -join ','))
foreach ($t in @(@{ N = 'OpenBao'; U = 'https://openbao:8200/v1/sys/health' }, @{ N = 'pg-replica'; U = 'telnet://pg-replica:5432' }, @{ N = 'maria-replica'; U = 'telnet://maria-replica:3306' }, @{ N = 'pg-primary'; U = 'telnet://pg-primary:5432' }, @{ N = 'log-store reader (fluent-bit has no network)'; U = 'http://fluent-bit:2020/' })) {
    $r = Invoke-Docker @('run', '--rm', '--network', ('container:' + $pid_), $curlImage, '-sk', '-m', '5', '-o', '/dev/null', '-w', '%{http_code}', $t.U)
    Write-Result ($r.Code -ne 0) ('from the portal''s network namespace, {0} is unreachable' -f $t.N) ('curl exit {0}: {1}' -f $r.Code, (Short $r.All 120))
}
$r = Invoke-Docker @('run', '--rm', '--network', ('container:' + $pid_), $curlImage, '-s', '-m', '5', '-o', '/dev/null', '-w', '%{http_code}', '--connect-to', 'keycloak.localhost:8180:keycloak:8180', 'http://keycloak.localhost:8180/realms/lab/.well-known/openid-configuration')
Write-Result (($r.Code -eq 0) -and ($r.Out.Trim() -eq '200')) 'from the portal''s network namespace, Keycloak is reachable (its only peer)' ('curl exit {0}: {1}' -f $r.Code, $r.Out)
$r = Invoke-Docker @('run', '--rm', '--network', 'none', '-v', ($LabProject + '_portal-log:/v:ro'), '--entrypoint', 'sh', 'postgres:17', '-c', 'stat -c "%u:%g %a" /v; stat -c "%u:%g %a" /v/portal-audit.log')
$lines = @($r.Out -split "`r?`n" | Where-Object { $_.Trim() })
Write-Result (($lines.Count -eq 2) -and ($lines[0].Trim() -eq '1654:4000 2750') -and ($lines[1] -match '^1654:4000 6[46]0$')) 'portal-log: owner 1654, group 4000 (log reader), setgid 2750; the audit file is group-readable, not group-writable' ($r.All)

# =================================================================================================
Section '9. Audit trail in log-store'
foreach ($a in @(
        @{ Ev = 'request-created'; Who = 'bob' },
        @{ Ev = 'request-approved'; Who = 'carol' },
        @{ Ev = 'membership-added'; Who = 'portal' },
        @{ Ev = 'revoke-requested'; Who = 'carol' },
        @{ Ev = 'membership-removed'; Who = 'portal' },
        @{ Ev = 'access-revoked'; Who = 'portal' })) {
    $f = @(Find-InStore @('"engine":"portal"', ('"request_id":"' + $idA + '"'), ('"event":"' + $a.Ev + '"')))
    $o = $f | Select-Object -Last 1
    $ok = ($null -ne $o) -and ($o.user -eq $a.Who) -and ($o.ticket -eq $good.ticket) -and ($o.requester -eq 'bob') -and ($o.group -eq 'app1-devs')
    Write-Result $ok ('request A: {0} by {1}, with ticket, requester and group' -f $a.Ev, $a.Who) $(if ($o) { Short (ConvertTo-Json $o -Compress) 300 } else { 'not found' })
}
$f = @(Find-InStore @('"engine":"portal"', ('"request_id":"' + $idB + '"'), '"event":"access-expired"'))
Write-Result ($f.Count -gt 0) 'request B (1 min): access-expired' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
$f = @(Find-InStore @('"engine":"portal"', ('"request_id":"' + $idD + '"'), '"event":"request-denied"', '"user":"carol"'))
Write-Result ($f.Count -gt 0) 'request D: request-denied by carol, with her comment' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
$f = @(Find-InStore @('"alert":"portal_self_approval"', ('"request_id":"' + $idC + '"')) 'alerts.jsonl')
Write-Result ($f.Count -gt 0) 'alert portal_self_approval for carol''s attempt' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
$f = @(Find-InStore @('"alert":"portal_approval_refused"', ('"request_id":"' + $idA + '"'), '"user":"alice"') 'alerts.jsonl')
Write-Result ($f.Count -gt 0) 'alert portal_approval_refused for alice''s attempt' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
$f = @(Find-InStore @('"engine":"portal"', '"event":"drift-removed"', '"requester":"bob"'))
Write-Result ($f.Count -gt 0) 'drift-removed for bob is in audit.jsonl' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
# The join the design relies on: approval (portal) -> person (OpenBao audit) -> database user.
$f = @(Find-InStore @('"source":"openbao"', '"event":"response"', ('"db_username":"' + $cr1.User + '"')))
Write-Result ($f.Count -gt 0) 'the credentials bob read during grant A are in the OpenBao audit records (person -> lease -> database user)' $(if ($f.Count) { 'user=' + $f[-1].user + ' db_username=' + $f[-1].db_username } else { 'not found' })

# =================================================================================================
Section '10. Restart'
[void](Invoke-Docker @('restart', $pid_) @{} 60)
$deadline = (Get-Date).AddSeconds(60)
do { Start-Sleep -Seconds 2; $ready = Invoke-Portal GET '/readyz' } while (($ready.Code -ne 200) -and ((Get-Date) -lt $deadline))
$tBob = Get-PortalToken 'bob'
$r = Invoke-Portal GET '/api/requests' $tBob
$mineAfter = @($r.Body | ForEach-Object { $_ })
$a = $mineAfter | Where-Object { $_.id -eq $idA }
$b = $mineAfter | Where-Object { $_.id -eq $idB }
Write-Result (($ready.Code -eq 200) -and ($a.status -eq 'revoked') -and ($b.status -eq 'expired')) 'after a portal restart the requests and their states are still there (SQLite on portal-data)' ('readyz ' + $ready.Code + '; A ' + $a.status + ', B ' + $b.status)
$h = Invoke-Portal GET ('/api/requests/' + $idA + '/history') $tBob
$acts = @($h.Body | ForEach-Object { $_.action })
Write-Result (($acts -contains 'request-created') -and ($acts -contains 'request-approved') -and ($acts -contains 'access-revoked')) 'request history (shown in the UI) has every step' ($acts -join ' > ')

# ---- cleanup ---------------------------------------------------------------------------------------
foreach ($t in $script:BaoTokens) { Close-Bao $t }

Write-Host ''
$color = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
Write-Host ('portal checks: {0} passed, {1} failed' -f $script:Pass, $script:Fail) -ForegroundColor $color
if ($script:Fail -gt 0) { exit 1 }
