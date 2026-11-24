[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype-phase5',
    [string]$BaoSecretPrefix = 'openbao_phase5',
    [string]$PortalUrl = 'http://127.0.0.1:8090',
    [string]$KeycloakUrl = 'http://127.0.0.1:8180',
    [string]$AppUrl = 'http://localhost:8080',
    # How long to wait for a record to reach log-store.
    [int]$ShipWaitSeconds = 30
)

# Phase 6b checks against the RUNNING phase 5 + phase 6 stack (after scripts\phase6-setup.ps1):
# the developer WRITE path on PostgreSQL (design 4.C "Write and break-glass path") and its audit.
#   1. database objects: debug_rw allow-list, audit triggers, dev_audit closed to everyone else
#   2. enable_session_audit() refuses anything that is not a v- member of debug_rw
#   3. portal: app1-write needs an approver from app1-write-approvers (not app1-approvers, never
#      the requester), at most 60 min; the grant fills app1-devs-rw only
#   4. OpenBao: only app1-devs-rw members read database/creds/app1-pg-rw; 30-minute leases
#   5. network and pg_hba: write users reach the primary from rw-access only, database app1
#      only; never the replica; read users still never reach the primary
#   6. what a write user can and cannot do (DML yes; TRUNCATE, DDL, audit tampering, SET ROLE,
#      turning pgAudit or triggers off: no); one session at a time
#   7. row audit in the database: old and new row per change; rollback leaves nothing; the
#      application's own writes are not captured
#   8. audit store: login, pgAudit statements with row counts, DEV_CHANGE rows, refusals, portal
#      decisions, and the alerts write_access_login / write_access_statement
#   9. revocation ends the open session and drops the role on primary and replica
# Test users: bob (requester), dave (write approver), carol (read approver only), alice
# (standing app1-devs member, no write access). Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.phase5.yaml' }
$P2ComposeFile = $ComposeFile
$P2Project = $Project
$P2BaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $root 'scripts\phase2-lib.ps1')

$volStore = $P2Project + '_log-store'
$volCa = $P2Project + '_pki-ca'
$netRw = $P2Project + '_rw-access'
$netAccess = $P2Project + '_access'
$realm = [System.IO.File]::ReadAllText((Join-Path $P2Root 'config\keycloak\phase5\lab-realm.json'), $P2Utf8NoBom) | ConvertFrom-Json
$runTag = (Get-Date).ToString('HHmmss')
$baoRoot = Read-P2Secret $P2BaoRootTokenName

$script:Pass = 0
$script:Fail = 0
$script:BaoTokens = New-Object System.Collections.ArrayList
$script:Containers = New-Object System.Collections.ArrayList

function Write-Result {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) { $script:Pass++; $tag = 'PASS'; $color = 'Green' } else { $script:Fail++; $tag = 'FAIL'; $color = 'Red' }
    Write-Host ('{0} {1}' -f $tag, $Name) -ForegroundColor $color
    if ($Detail) { foreach ($l in ($Detail.Trim() -split "`r?`n")) { if ($l.Trim()) { Write-Host ('       | ' + $l.TrimEnd()) } } }
}
function Section { param([string]$T) Write-Host ''; Write-Host ('== ' + $T) -ForegroundColor Cyan }
function Short { param([string]$T, [int]$N = 300) if (-not $T) { return '' }; if ($T.Length -le $N) { return $T }; return $T.Substring(0, $N) + '...' }

function Get-TestPassword {
    param([string]$User)
    if ($User -eq 'carol') { return Read-P2Secret 'keycloak_carol_password' }
    if ($User -eq 'dave') { return Read-P2Secret 'keycloak_dave_password' }
    return [string](($realm.users | Where-Object { $_.username -eq $User }).credentials[0].value)
}

# ---- portal ---------------------------------------------------------------------------------------
function Get-PortalToken {
    param([string]$User)
    $body = @{ grant_type = 'password'; client_id = 'portal-test'; username = $User; password = (Get-TestPassword $User); scope = 'openid' }
    return [string](Invoke-RestMethod -Method Post -Uri ($KeycloakUrl + '/realms/lab/protocol/openid-connect/token') -Body $body -TimeoutSec 15).access_token
}
function Invoke-Portal {
    param([string]$Method, [string]$Path, [string]$Token, $Body = $null)
    $h = @{ Authorization = 'Bearer ' + $Token }
    if ($Method -ne 'GET') { $h['X-Portal-Request'] = '1' }
    $p = @{ UseBasicParsing = $true; Method = $Method; Uri = ($PortalUrl + $Path); Headers = $h; TimeoutSec = 30 }
    if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Compress)) }
    elseif ($Method -ne 'GET') { $p.ContentType = 'application/json'; $p.Body = '{}' }
    try {
        $r = Invoke-WebRequest @p
        return @{ Code = [int]$r.StatusCode; Body = (ConvertFrom-JsonOrNull $r.Content); Raw = $r.Content }
    } catch {
        $resp = $_.Exception.Response
        if ($resp) {
            $raw = $_.ErrorDetails.Message
            if (-not $raw) { try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $raw = $sr.ReadToEnd(); $sr.Dispose() } catch { $raw = '' } }
            return @{ Code = [int]$resp.StatusCode; Body = (ConvertFrom-JsonOrNull $raw); Raw = $raw }
        }
        return @{ Code = -1; Body = $null; Raw = $_.Exception.Message }
    }
}
function Show { param($R) return ('HTTP {0}: {1}' -f $R.Code, (Short $R.Raw 240)) }

# ---- Keycloak admin view -----------------------------------------------------------------------------
$script:KcTok = $null; $script:KcTokAt = [DateTime]::MinValue
function Get-KcHeaders {
    if (-not $script:KcTok -or ((Get-Date) - $script:KcTokAt).TotalSeconds -gt 40) {
        $b = @{ grant_type = 'password'; client_id = 'admin-cli'; username = 'admin'; password = (Read-P2Secret 'keycloak_admin_password') }
        $script:KcTok = (Invoke-RestMethod -Method Post -Uri ($KeycloakUrl + '/realms/master/protocol/openid-connect/token') -Body $b -TimeoutSec 15).access_token
        $script:KcTokAt = Get-Date
    }
    return @{ Authorization = 'Bearer ' + $script:KcTok }
}
$KA = $KeycloakUrl + '/admin/realms/lab'
function KcGet { param([string]$Path) $r = Invoke-RestMethod -Uri ($KA + $Path) -Headers (Get-KcHeaders) -TimeoutSec 15; return @($r | ForEach-Object { $_ }) }
function Get-KcGroupId { param([string]$G) return ((KcGet ('/groups?search={0}&exact=true' -f $G)) | Where-Object { $_.name -eq $G })[0].id }
function Get-KcMembers { param([string]$G) return @((KcGet ('/groups/{0}/members?max=500' -f (Get-KcGroupId $G))) | ForEach-Object { $_.username }) }

# ---- OpenBao as a developer (jwt auth, id token of the LAB-ONLY client bao-jwt-test) -----------------
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
    return @{
        Ok = (($r.Code -eq 0) -and $null -ne $o -and $o.data.username)
        User = $(if ($o) { [string]$o.data.username } else { '' }); Password = $(if ($o) { [string]$o.data.password } else { '' })
        Lease = $(if ($o) { [string]$o.lease_id } else { '' }); Ttl = $(if ($o) { [int]$o.lease_duration } else { 0 }); All = $r.All
    }
}

# ---- databases --------------------------------------------------------------------------------------------
$pgP = Get-P2ContainerId 'pg-primary'
$pgR = Get-P2ContainerId 'pg-replica'
# Local superuser on a server (peer auth). Returns trimmed stdout.
function PgLocal {
    param([string]$Id, [string]$Sql, [string]$Db = 'app1')
    $r = Invoke-Docker @('exec', '-u', 'postgres', $Id, 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-d', $Db, '-c', $Sql)
    return @{ Code = $r.Code; Out = $r.Out.Trim(); All = $r.All }
}
# A developer client (throwaway psql container) on a network, verify-full TLS.
function PgAs {
    param([string]$Net, [string]$User, [string]$Password, [string]$Sql, [string]$Server = 'pg-primary', [string]$Db = 'app1')
    $ci = 'host={0} dbname={1} user={2} sslmode=verify-full sslrootcert=/ca/ca.crt connect_timeout=5 application_name=phase6-write-checks' -f $Server, $Db, $User
    return Invoke-Docker @('run', '--rm', '--network', $Net, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD',
        '--entrypoint', 'psql', 'postgres:17', $ci, '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', $Sql) @{ PGPASSWORD = $Password }
}

# ---- audit store --------------------------------------------------------------------------------------------
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

# =================================================================================================
Section '0. Preconditions'
$ready = Invoke-Portal GET '/readyz' ''
$bs = Get-BaoStatus
Write-Result (($ready.Code -eq 200) -and ($bs.Code -eq 0) -and ($bs.Obj.sealed -eq $false)) 'portal ready (sees app1-devs and app1-devs-rw) and OpenBao unsealed' ((Show $ready) + "`nsealed=" + $bs.Obj.sealed)
$hba = PgLocal $pgP "SELECT line_number || ' ' || type || ' ' || array_to_string(database, ',') || ' ' || array_to_string(user_name, ',') || ' ' || coalesce(address, '') || ' ' || coalesce(netmask, '') || ' ' || auth_method FROM pg_hba_file_rules ORDER BY line_number" 'postgres'
Write-Result (($hba.Out -match "(?m)^5 hostssl app1 \+debug_rw 10\.81\.15\.0 255\.255\.255\.0 scram-sha-256$") -and ($hba.Out -match "(?m)^6 host all \+debug_rw all\s+reject$") -and ($hba.Out -match "(?m)^4 host all \+debug_ro all\s+reject$")) 'pg-primary pg_hba: +debug_ro rejected; +debug_rw only hostssl, app1, from rw-access (10.81.15.0/24), else rejected' $hba.Out
if ($ready.Code -ne 200 -or $bs.Code -ne 0) { Write-Host 'Run scripts\phase6-setup.ps1 first.' -ForegroundColor Red; exit 1 }

# =================================================================================================
Section '1. Database objects'
$g = PgLocal $pgP "SELECT string_agg(x, ' ' ORDER BY x) FROM (SELECT table_schema || '.' || table_name || ':' || privilege_type AS x FROM information_schema.role_table_grants WHERE grantee = 'debug_rw') s"
Write-Result ($g.Out -eq 'public.customers:DELETE public.customers:INSERT public.customers:SELECT public.customers:UPDATE public.orders:DELETE public.orders:INSERT public.orders:SELECT public.orders:UPDATE') 'debug_rw: SELECT, INSERT, UPDATE, DELETE on public.customers and public.orders, nothing else' $g.Out
$attr = PgLocal $pgP "SELECT rolcanlogin || ' ' || rolsuper || ' ' || rolcreaterole || ' ' || rolbypassrls FROM pg_roles WHERE rolname = 'debug_rw'"
$mem = PgLocal $pgP "SELECT r.rolname || ' in ' || g.rolname || ' admin=' || m.admin_option || ' inherit=' || m.inherit_option || ' set=' || m.set_option FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles r ON r.oid = m.member WHERE g.rolname = 'debug_rw' AND r.rolname NOT LIKE 'v-%'"
Write-Result (($attr.Out -eq 'false false false false') -and ($mem.Out -eq 'bao_admin in debug_rw admin=true inherit=false set=false')) 'debug_rw is NOLOGIN; bao_admin may grant it but not use it (INHERIT FALSE, SET FALSE)' ($attr.Out + "`n" + $mem.Out)
$tg = PgLocal $pgP "SELECT string_agg(tgrelid::regclass::text || ':' || tgenabled::text, ' ' ORDER BY tgrelid::regclass::text) FROM pg_trigger WHERE tgname = 'zz_dev_audit'"
Write-Result ($tg.Out -eq 'customers:O orders:O') 'audit trigger zz_dev_audit is enabled on both tables' $tg.Out
$acl = PgLocal $pgP "SELECT 'schema ' || coalesce(array_to_string(nspacl, ','), '') FROM pg_namespace WHERE nspname = 'dev_audit' UNION ALL SELECT 'table ' || coalesce(array_to_string(relacl, ','), '') FROM pg_class WHERE oid = 'dev_audit.row_changes'::regclass UNION ALL SELECT p.proname || ' ' || coalesce(array_to_string(p.proacl, ','), '') || ' owner=' || pg_get_userbyid(p.proowner) || ' definer=' || p.prosecdef FROM pg_proc p WHERE p.pronamespace = 'dev_audit'::regnamespace ORDER BY 1"
$aclOk = ($acl.Out -match '(?m)^schema audit_owner=UC/audit_owner,bao_admin=U/audit_owner$') -and ($acl.Out -match '(?m)^table audit_owner=arwdDxtm/audit_owner$') -and
    ($acl.Out -match '(?m)^capture audit_owner=X/audit_owner owner=audit_owner definer=true$') -and ($acl.Out -match '(?m)^enable_session_audit postgres=X/postgres,bao_admin=X/postgres owner=postgres definer=true$')
Write-Result $aclOk 'dev_audit: only audit_owner reads or writes row_changes; bao_admin may only run enable_session_audit; nothing for PUBLIC, debug_ro or debug_rw' $acl.Out

# =================================================================================================
Section '2. enable_session_audit refuses everything but a v- member of debug_rw'
foreach ($t in @(
        @{ N = 'app1_runtime'; Why = 'not a v- name' },
        @{ N = 'v-nobody-here'; Why = 'role does not exist' },
        @{ N = 'v-x''; DROP ROLE app1_runtime; --'; Why = 'injection in the name' })) {
    $sql = "SET ROLE bao_admin; SELECT dev_audit.enable_session_audit('" + $t.N.Replace("'", "''") + "')"
    $r = PgLocal $pgP $sql
    Write-Result (($r.Code -ne 0) -and ($r.All -match 'enable_session_audit: ')) ('refused as bao_admin: {0} ({1})' -f $t.N, $t.Why) (Short $r.All 200)
}
# A read temp role (member of debug_ro, not debug_rw) is refused too.
$tmpRo = 'v-lab-probe-ro-' + $runTag
$r = PgLocal $pgP ("CREATE ROLE ""{0}"" LOGIN; GRANT debug_ro TO ""{0}""; SET ROLE bao_admin; SELECT dev_audit.enable_session_audit('{0}')" -f $tmpRo)
[void](PgLocal $pgP ('DROP ROLE IF EXISTS "{0}"' -f $tmpRo))
Write-Result (($r.Code -ne 0) -and ($r.All -match 'not a member of debug_rw')) 'refused: a v- role that is not in debug_rw (read temp role)' (Short $r.All 200)
$r = PgLocal $pgP "SET ROLE debug_rw; SELECT dev_audit.enable_session_audit('x')"
Write-Result (($r.Code -ne 0) -and ($r.All -match 'permission denied')) 'debug_rw itself cannot call it (no USAGE on dev_audit)' (Short $r.All 200)

# =================================================================================================
Section '3. Portal: write requests'
$tBob = Get-PortalToken 'bob'; $tCarol = Get-PortalToken 'carol'; $tDave = Get-PortalToken 'dave'; $tAlice = Get-PortalToken 'alice'
# Leftovers of an earlier run.
foreach ($tok in @($tCarol, $tDave)) {
    $all = Invoke-Portal GET '/api/requests?scope=all' $tok
    foreach ($x in @($all.Body | ForEach-Object { $_ })) {
        if ($x.requester -in @('bob', 'alice') -and $x.status -eq 'active') { [void](Invoke-Portal POST ('/api/requests/' + $x.id + '/revoke') $tok @{ comment = 'test cleanup' }) }
    }
}
foreach ($pair in @(@{ T = $tBob }, @{ T = $tAlice }, @{ T = $tDave })) {
    $mine = Invoke-Portal GET '/api/requests' $pair.T
    foreach ($x in @($mine.Body | ForEach-Object { $_ })) { if ($x.status -eq 'pending') { [void](Invoke-Portal POST ('/api/requests/' + $x.id + '/cancel') $pair.T) } }
}
$rw0 = @(Get-KcMembers 'app1-devs-rw')
$wa = @(Get-KcMembers 'app1-write-approvers')
Write-Result (($rw0.Count -eq 0) -and ($wa -contains 'dave') -and -not ($wa -contains 'carol')) 'start state: app1-devs-rw is empty; app1-write-approvers has dave, not carol' ('app1-devs-rw: ' + ($rw0 -join ', ') + "`napp1-write-approvers: " + ($wa -join ', '))

$me = Invoke-Portal GET '/api/me' $tDave
$wApp = @($me.Body.apps | Where-Object { $_.id -eq 'app1-write' })[0]
Write-Result (($null -ne $wApp) -and ($wApp.group -eq 'app1-devs-rw') -and ($wApp.approverGroup -eq 'app1-write-approvers') -and ($wApp.maxDurationMinutes -eq 60) -and ($wApp.isApprover -eq $true) -and ($me.Body.isApprover -eq $true)) '/api/me lists app1-write: group app1-devs-rw, approvers app1-write-approvers, max 60 min; dave approves it' (Short $me.Raw 400)

$r = Invoke-Portal POST '/api/requests' $tBob @{ app = 'app1-write'; ticket = 'FIX-' + $runTag; reason = 'Correct a wrong order total (test)'; durationMinutes = 120 }
Write-Result (($r.Code -eq 400) -and ($r.Raw -match 'to 60 minutes')) 'a write request longer than 60 min is refused' (Show $r)
$rA = Invoke-Portal POST '/api/requests' $tBob @{ app = 'app1-write'; ticket = 'FIX-' + $runTag; reason = 'Correct a wrong order total (test)'; durationMinutes = 30 }
$idA = $rA.Body.id
Write-Result (($rA.Code -eq 201) -and ($rA.Body.status -eq 'pending') -and ($rA.Body.group -eq 'app1-devs-rw')) 'bob requests app1-write for 30 min: pending' (Show $rA)
$r = Invoke-Portal POST ('/api/requests/' + $idA + '/approve') $tCarol @{ comment = 'read approver tries' }
Write-Result (($r.Code -eq 403) -and ($r.Raw -match 'app1-write-approvers')) 'carol (app1-approvers only) cannot approve a write request' (Show $r)
$all = Invoke-Portal GET '/api/requests?scope=all' $tCarol
Write-Result (-not (@($all.Body | ForEach-Object { $_.id }) -contains $idA)) 'carol does not even see write requests in her approver list' ('carol sees ' + @($all.Body).Count + ' requests')
$rD = Invoke-Portal POST '/api/requests' $tDave @{ app = 'app1-write'; ticket = 'FIX-' + $runTag; reason = 'Approver asks for write access herself'; durationMinutes = 15 }
$r = Invoke-Portal POST ('/api/requests/' + $rD.Body.id + '/approve') $tDave @{ comment = 'self' }
[void](Invoke-Portal POST ('/api/requests/' + $rD.Body.id + '/cancel') $tDave)
Write-Result (($rD.Code -eq 201) -and ($r.Code -eq 403) -and ($r.Raw -match 'own request')) 'dave cannot approve his own write request' ((Show $rD) + "`n" + (Show $r))
$rAl = Invoke-Portal POST '/api/requests' $tAlice @{ app = 'app1-write'; ticket = 'FIX-' + $runTag; reason = 'Standing read member asks for write'; durationMinutes = 15 }
[void](Invoke-Portal POST ('/api/requests/' + $rAl.Body.id + '/cancel') $tAlice)
Write-Result ($rAl.Code -eq 201) 'alice''s standing read membership gives no standing write access: she must request it like anyone' (Show $rAl)

$r = Invoke-Portal POST ('/api/requests/' + $idA + '/approve') $tDave @{ comment = 'ok, one order' }
$rw1 = @(Get-KcMembers 'app1-devs-rw'); $ro1 = @(Get-KcMembers 'app1-devs')
Write-Result (($r.Code -eq 200) -and ($r.Body.status -eq 'active') -and ($r.Body.decidedBy -eq 'dave') -and ($rw1 -contains 'bob') -and -not ($ro1 -contains 'bob')) 'dave approves: active; bob is in app1-devs-rw and NOT in app1-devs' ((Show $r) + "`napp1-devs-rw: " + ($rw1 -join ', ') + "`napp1-devs: " + ($ro1 -join ', '))

# =================================================================================================
Section '4. OpenBao'
$cB = Connect-Bao 'bob'
$crW = Read-Creds $cB.Token 'app1-pg-rw'
$crR = Read-Creds $cB.Token 'app1-pg-ro'
Write-Result ($crW.Ok -and (-not $crR.Ok) -and ($cB.Policies -contains 'app1-write') -and -not ($cB.Policies -contains 'app1-debug')) 'bob (app1-devs-rw only) reads app1-pg-rw credentials, not app1-pg-ro' ('policies: ' + ($cB.Policies -join ',') + "`nrw user: " + $crW.User + "`nro read: " + (Short $crR.All 120))
Write-Result (($crW.Ttl -gt 0) -and ($crW.Ttl -le 1800) -and ($crW.User -match '^v-jwt-bob-app1-pg-rw-')) 'the lease lasts at most 30 min; the username names person and role' ('ttl ' + $crW.Ttl + ' s, user ' + $crW.User)
$r = Invoke-Bao @('write', '-format=json', 'sys/leases/renew', ('lease_id=' + $crW.Lease), 'increment=7200') $cB.Token
$o = ConvertFrom-JsonOrNull $r.Out
Write-Result (($r.Code -ne 0) -or ($o.lease_duration -le 1800)) 'renewing cannot stretch it past max_ttl 30 min' (Short $r.All 200)
$cA = Connect-Bao 'alice'
$crA = Read-Creds $cA.Token 'app1-pg-rw'
Write-Result ((-not $crA.Ok) -and ($crA.All -match 'permission denied')) 'alice (standing app1-devs) cannot read app1-pg-rw' (Short $crA.All 200)
$crAro = Read-Creds $cA.Token 'app1-pg-ro'

$U = $crW.User; $P = $crW.Password

# =================================================================================================
Section '5. Network and pg_hba'
$r = PgAs $netRw $U $P 'SELECT current_user, inet_server_addr()'
Write-Result (($r.Code -eq 0) -and ($r.Out -match [regex]::Escape($U)) -and ($r.Out -match '10\.81\.15\.10')) 'write user logs in to pg-primary from rw-access (TLS verify-full)' (Short $r.All 200)
$r = PgAs $netRw $U $P 'SELECT 1' 'pg-primary' 'postgres'
Write-Result (($r.Code -ne 0) -and ($r.All -match 'pg_hba.conf rejects|no pg_hba.conf entry')) 'write user: database postgres refused' (Short $r.All 200)
$r = PgAs $netAccess $U $P 'SELECT 1' 'pg-primary'
Write-Result (($r.Code -ne 0) -and ($r.All -match 'could not translate host name|timeout|could not connect')) 'from the read network (access) the primary is not reachable at all' (Short $r.All 200)
$r = PgAs $netAccess $U $P 'SELECT 1' 'pg-replica'
Write-Result (($r.Code -ne 0) -and ($r.All -match 'pg_hba.conf rejects|no pg_hba.conf entry')) 'write user on the replica: refused by pg_hba (not in debug_ro)' (Short $r.All 200)
if ($crAro.Ok) {
    $r = PgAs $netRw $crAro.User $crAro.Password 'SELECT 1'
    Write-Result (($r.Code -ne 0) -and ($r.All -match 'pg_hba.conf rejects')) 'read temp user from rw-access to the primary: refused (+debug_ro reject line)' (Short $r.All 200)
} else { Write-Result $false 'read temp user from rw-access to the primary: refused' ('could not get alice''s read credentials: ' + (Short $crAro.All 200)) }

# =================================================================================================
Section '6. What a write user can and cannot do'
$set = PgAs $netRw $U $P "SELECT current_setting('pgaudit.log') || ' | rows=' || current_setting('pgaudit.log_rows') || ' | param=' || current_setting('pgaudit.log_parameter') || ' | ' || current_setting('statement_timeout') || ' ' || current_setting('lock_timeout') || ' ' || current_setting('idle_in_transaction_session_timeout')"
Write-Result ($set.Out.Trim() -eq 'read, write, ddl, role, function, misc | rows=on | param=on | 1min 5s 2min') 'session settings: full pgAudit with rows and parameters; statement 60 s, lock 5 s, idle in transaction 2 min' $set.Out
$cust = (PgLocal $pgP 'SELECT min(id) FROM public.customers').Out
$ins = PgAs $netRw $U $P ("INSERT INTO public.orders (customer_id, total, created_at) VALUES ({0}, 4242.{1}, now()) RETURNING id" -f $cust, $runTag.Substring(2))
$oid = ($ins.Out -split "`r?`n" | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
$upd = PgAs $netRw $U $P ("UPDATE public.orders SET total = total + 1 WHERE id = {0}" -f $oid)
$del = PgAs $netRw $U $P ("DELETE FROM public.orders WHERE id = {0}" -f $oid)
Write-Result (($ins.Code -eq 0) -and $oid -and ($upd.Out -match 'UPDATE 1') -and ($del.Out -match 'DELETE 1')) 'INSERT, UPDATE and DELETE on public.orders work' ("insert id " + $oid + "`n" + $upd.Out.Trim() + ' / ' + $del.Out.Trim())
foreach ($t in @(
        @{ S = 'TRUNCATE public.orders'; N = 'TRUNCATE' },
        @{ S = 'CREATE TABLE public.x_' + $runTag + ' (i int)'; N = 'CREATE TABLE' },
        @{ S = 'ALTER TABLE public.orders DISABLE TRIGGER zz_dev_audit'; N = 'disable the audit trigger' },
        @{ S = "SET session_replication_role = replica"; N = 'session_replication_role (skips triggers)' },
        @{ S = "SET pgaudit.log = 'none'"; N = 'turn pgAudit off' },
        @{ S = "SET log_min_messages = 'panic'"; N = 'silence the server log (DEV_CHANGE lines)' },
        @{ S = 'SELECT count(*) FROM dev_audit.row_changes'; N = 'read the row audit table' },
        @{ S = 'DELETE FROM dev_audit.row_changes'; N = 'delete row audit records' },
        @{ S = 'SET ROLE app1_runtime'; N = 'SET ROLE to the application account' },
        @{ S = 'SELECT * FROM debug.customers LIMIT 1'; N = 'the masked read views (not part of the write role)' },
        @{ S = "ALTER ROLE CURRENT_USER SET pgaudit.log = 'none'"; N = 'change its own role settings' },
        @{ S = "SELECT dev_audit.enable_session_audit(current_user)"; N = 'call enable_session_audit' })) {
    $r = PgAs $netRw $U $P $t.S
    Write-Result (($r.Code -ne 0) -and ($r.All -match 'permission denied|must be owner|not allowed|cannot|denied')) ('refused: ' + $t.N) (Short $r.All 200)
}
# =================================================================================================
Section '7. Row audit in the database'
$rc = PgLocal $pgP ("SELECT operation || ' ' || table_name || ' old=' || coalesce(old_row->>'total', '-') || ' new=' || coalesce(new_row->>'total', '-') || ' client=' || host(client_addr) FROM dev_audit.row_changes WHERE db_user = '{0}' AND coalesce(new_row->>'id', old_row->>'id') = '{1}' ORDER BY id" -f $U, $oid)
$lines = @($rc.Out -split "`r?`n" | Where-Object { $_ })
Write-Result (($lines.Count -eq 3) -and ($lines[0] -match '^INSERT public\.orders old=- new=4242') -and ($lines[1] -match '^UPDATE public\.orders old=4242\S+ new=4243') -and ($lines[2] -match '^DELETE public\.orders old=4243\S+ new=-') -and ($lines[0] -match 'client=10\.81\.15\.')) 'dev_audit.row_changes: INSERT, UPDATE and DELETE of that order, with old and new values and the client address' $rc.Out
$rb = PgAs $netRw $U $P ("BEGIN; UPDATE public.orders SET total = total WHERE customer_id = {0}; ROLLBACK;" -f $cust)
$rbN = (PgLocal $pgP ("SELECT count(*) FROM dev_audit.row_changes WHERE db_user = '{0}' AND table_name = 'public.orders' AND operation = 'UPDATE' AND coalesce(new_row->>'id', '') <> '{1}'" -f $U, $oid)).Out
Write-Result (($rb.Code -eq 0) -and ($rbN -eq '0')) 'a rolled-back change leaves no row in row_changes (same transaction)' ('rows from the rolled-back UPDATE: ' + $rbN)
$before = (PgLocal $pgP 'SELECT count(*) FROM dev_audit.row_changes').Out
$email = ('p6w-{0}@example.test' -f $runTag)
try { $api = Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($AppUrl + '/dotnet/api/customers') -ContentType 'application/json' -Body ((@{ email = $email; full_name = 'Phase6 Write ' + $runTag } | ConvertTo-Json -Compress)) -TimeoutSec 30; $apiCode = [int]$api.StatusCode } catch { $apiCode = -1 }
$after = (PgLocal $pgP 'SELECT count(*) FROM dev_audit.row_changes').Out
$there = (PgLocal $pgP ("SELECT count(*) FROM public.customers WHERE email = '{0}'" -f $email)).Out
Write-Result (($apiCode -eq 201) -and ($there -eq '1') -and ($before -eq $after)) 'the application''s own write (POST /dotnet/api/customers as app1_runtime) is not captured' ('API ' + $apiCode + '; rows before ' + $before + ', after ' + $after)
$rep = PgLocal $pgR ("SELECT count(*) FROM dev_audit.row_changes WHERE db_user = '{0}'" -f $U)
Write-Result ($rep.Out -eq '3') 'row_changes replicates to pg-replica (a second copy; debug_ro has no access there either)' ('replica rows: ' + $rep.Out)

# =================================================================================================
Section '8. Audit store and alerts'
$f = @(Find-InStore @('"source":"pg-primary"', '"event":"login"', ('"user":"' + $U + '"')) 'alerts.jsonl')
Write-Result (($f.Count -gt 0) -and ($f[-1].alert -eq 'write_access_login') -and ($f[-1].client_host -match '^10\.81\.15\.')) 'alert write_access_login with the client address' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
$f = @(Find-InStore @('"audit_class":"WRITE"', ('"user":"' + $U + '"'), '"audit_command":"UPDATE"', ('WHERE id = {0}"' -f $oid)) 'alerts.jsonl')
Write-Result (($f.Count -gt 0) -and ($f[-1].alert -eq 'write_access_statement') -and ($f[-1].statement -eq ('UPDATE public.orders SET total = total + 1 WHERE id = {0}' -f $oid)) -and ($f[-1].audit_rows -eq '1')) 'alert write_access_statement: pgAudit UPDATE with the exact statement and rows=1' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 400 } else { 'not found' })
$f = @(Find-InStore @('"event":"row_change"', ('"user":"' + $U + '"'), '"audit_command":"UPDATE"'))
$rowOk = ($f.Count -gt 0) -and ($f[0].audit_object -eq 'public.orders') -and ($f[0].row_change -match '"old": \{[^}]*"total": 4242') -and ($f[0].row_change -match '"new": \{[^}]*"total": 4243') -and ($f[0].txid -match '^\d+$')
Write-Result $rowOk 'row_change (DEV_CHANGE) in audit.jsonl: table, operation, old and new row, txid' $(if ($f.Count) { Short (ConvertTo-Json $f[0] -Compress) 500 } else { 'not found' })
$f = @(Find-InStore @('"source":"pg-primary"', '"event":"error"', ('"user":"' + $U + '"'), 'TRUNCATE public.orders'))
Write-Result (($f.Count -gt 0) -and ($f[-1].state_code -eq '42501')) 'the refused TRUNCATE is in audit.jsonl (42501)' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
$f = @(Find-InStore @('"engine":"portal"', '"event":"request-approved"', ('"request_id":"' + $idA + '"'), '"user":"dave"'))
Write-Result (($f.Count -gt 0) -and ($f[-1].group -eq 'app1-devs-rw') -and ($f[-1].ticket -eq ('FIX-' + $runTag))) 'the approval (ticket, approver dave, group app1-devs-rw) is in audit.jsonl' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })
$f = @(Find-InStore @('"source":"openbao"', '"event":"response"', ('"db_username":"' + $U + '"')))
Write-Result (($f.Count -gt 0) -and ($f[-1].user -eq 'bob')) 'OpenBao records map the write user to bob (portal approval -> person -> database user -> rows)' $(if ($f.Count) { 'user=' + $f[-1].user + ' db_username=' + $f[-1].db_username } else { 'not found' })
$f = @(Find-InStore @('"alert":"portal_approval_refused"', ('"request_id":"' + $idA + '"'), '"user":"carol"') 'alerts.jsonl')
Write-Result ($f.Count -gt 0) 'alert portal_approval_refused for carol''s attempt on the write request' $(if ($f.Count) { Short (ConvertTo-Json $f[-1] -Compress) 300 } else { 'not found' })

# =================================================================================================
Section '9. One session at a time, and revocation'
# CONNECTION LIMIT 1. The open session is also the one the revocation below must end.
$sess = 'p6w-hold-' + $runTag
$ci = 'host=pg-primary dbname=app1 user={0} sslmode=verify-full sslrootcert=/ca/ca.crt application_name=p6w-hold' -f $U
$x = Invoke-Docker @('run', '-d', '--name', $sess, '--network', $netRw, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD', '--entrypoint', 'psql', 'postgres:17', $ci, '-X', '-c', 'SELECT pg_sleep(55)') @{ PGPASSWORD = $P }
[void]$script:Containers.Add($sess)
$deadline = (Get-Date).AddSeconds(20)
do { Start-Sleep -Seconds 1; $n = (PgLocal $pgP ("SELECT count(*) FROM pg_stat_activity WHERE usename = '{0}'" -f $U)).Out } while (($n -ne '1') -and ((Get-Date) -lt $deadline))
$r = PgAs $netRw $U $P 'SELECT 1'
Write-Result (($n -eq '1') -and ($r.Code -ne 0) -and ($r.All -match 'too many connections for role')) 'a second session of the same write user is refused while one is open' ('open sessions: ' + $n + "`n" + (Short $r.All 200))
$r = Invoke-Portal POST ('/api/requests/' + $idA + '/revoke') $tDave @{ comment = 'fix done' }
$rw2 = @(Get-KcMembers 'app1-devs-rw')
Write-Result (($r.Code -eq 200) -and ($r.Body.status -eq 'revoked') -and -not ($rw2 -contains 'bob')) 'dave ends the grant: bob leaves app1-devs-rw' ((Show $r) + "`napp1-devs-rw: " + ($rw2 -join ', '))
$r = Invoke-Bao @('lease', 'revoke', '-sync', $crW.Lease) $baoRoot
$deadline = (Get-Date).AddSeconds(20)
do { Start-Sleep -Seconds 1; $st = (Invoke-Docker @('inspect', '-f', '{{.State.Status}}', $sess)).Out.Trim() } while (($st -eq 'running') -and ((Get-Date) -lt $deadline))
$np = (PgLocal $pgP ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $U)).Out
$deadline = (Get-Date).AddSeconds(20)
do { $nr = (PgLocal $pgR ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $U)).Out; if ($nr -ne '0') { Start-Sleep -Seconds 1 } } while (($nr -ne '0') -and ((Get-Date) -lt $deadline))
$logs = (Invoke-Docker @('logs', $sess)).All
Write-Result (($r.Code -eq 0) -and ($st -ne 'running') -and ($np -eq '0') -and ($nr -eq '0')) 'revoking the lease ends the open session and drops the role on primary and replica' ('session container: ' + $st + ' (' + (Short $logs 120) + ")`nrole on primary: " + $np + ', on replica: ' + $nr)
$r = PgAs $netRw $U $P 'SELECT 1'
# The role is gone, so it no longer matches +debug_rw and falls through to the final reject line.
Write-Result (($r.Code -ne 0) -and ($r.All -match 'pg_hba.conf rejects|password authentication failed|does not exist')) 'the revoked credentials no longer log in' (Short $r.All 200)

# ---- cleanup ---------------------------------------------------------------------------------------
foreach ($c in $script:Containers) { [void](Invoke-Docker @('rm', '-f', $c)) }
foreach ($t in $script:BaoTokens) { if ($t) { [void](Invoke-Bao @('token', 'revoke', '-self') $t) } }
[void](PgLocal $pgP ("DELETE FROM public.customers WHERE email = '{0}'" -f $email))

Write-Host ''
$color = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
Write-Host ('phase 6b (write path): {0} passed, {1} failed' -f $script:Pass, $script:Fail) -ForegroundColor $color
if ($script:Fail -gt 0) { exit 1 }
