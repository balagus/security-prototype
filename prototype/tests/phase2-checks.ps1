[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # Seconds to wait for OpenBao to remove a user after the shortened lease runs out.
    [int]$ExpiryWaitSeconds = 120,
    # Stack selection (defaults: the phase 2 stack, unchanged). Phase 3:
    #   -ComposeFile .\compose.phase3.yaml -Project security-prototype-phase3 -BaoSecretPrefix openbao_phase3
    #   -PgDevHost pg-replica -MariaDevHost maria-replica
    [string]$ComposeFile = '',
    [string]$Project = '',
    [string]$BaoSecretPrefix = '',
    # Developer-facing database hosts: where temp users log in from the access network. Phase 2
    # has no replicas, so they are the primaries. Admin-side facts (roles, grants, rotate-root,
    # lease cleanup) and the "only from the access network" checks always use the primaries.
    [string]$PgDevHost = 'pg-primary',
    [string]$MariaDevHost = 'maria-primary',
    # Phase 4: OpenBao creates the MariaDB temp users on maria-replica ONLY (never on the
    # primary, never binlogged; scripts\phase4-setup.ps1). The MariaDB temp-user facts that were
    # read on the primary (grants, "user gone" after revoke/expiry, cleanup count) are then read
    # on the replica, and one check is added: the temp user does not exist on the primary. Every
    # altered assertion prints its reason. PostgreSQL is unchanged. Default off = phases 2/3.
    [switch]$MariaTempUsersOnReplica
)

# Phase 2 checks against the RUNNING, configured phase 2 stack (compose.phase2.yaml after
# scripts\phase2-setup.ps1). Windows PowerShell 5.1 compatible. One PASS/FAIL line per check;
# exit 0 only if all pass.
#
# Same rules as phase1-checks.ps1: every negative check must fail for the RIGHT reason (its
# error text must match the control under test) and prints the real error text; positive
# controls show that the tool and path work, so a refusal cannot come from a broken test.
#
# Identities: alice (Keycloak group app1-devs) and bob (not in it). The test gets an ID token for
# each from Keycloak with the direct-access grant of the LAB-ONLY client bao-jwt-test (test
# passwords read from config\keycloak\lab-realm.json, never printed), then logs in to OpenBao's
# jwt auth method. Admin-side facts use the OpenBao root token (LAB-ONLY, secrets\) and the
# databases' local superuser socket.
# Database clients are throwaway postgres:17 / mariadb:11.8 containers on the access network.
# Passwords and tokens reach containers only as environment variables of the docker CLI process.
#
# This script restarts the openbao container once (persistence check) and unseals it again.

$ErrorActionPreference = 'Stop'
# Set (possibly to '') before dot-sourcing; empty means the phase 2 defaults of the library.
$P2ComposeFile = $ComposeFile
$P2Project = $Project
$P2BaoSecretPrefix = $BaoSecretPrefix
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\phase2-lib.ps1')
# True when developers use replicas (phase 3). On a read-only server a write is refused by the
# server's read-only state BEFORE the privilege check, so the write checks below then accept
# that error too (PostgreSQL hot standby: "cannot execute ... in a read-only transaction";
# MariaDB read_only=ON: "running with the --read-only option"). tests\phase3-checks.ps1 proves
# the privilege layer for writes separately on the primary.
$devIsReplica = ($PgDevHost -ne 'pg-primary') -or ($MariaDevHost -ne 'maria-primary')
$pgRo = ''; $maRo = ''
if ($PgDevHost -ne 'pg-primary') { $pgRo = '|cannot execute [A-Z ]+ in a read-only transaction' }
if ($MariaDevHost -ne 'maria-primary') { $maRo = '|running with the --read-only option so it cannot execute this statement' }

$netAccess = $P2Project + '_access'
$netPg = $P2Project + '_app1-pg'
$netMaria = $P2Project + '_app1-maria'
$netLab = $P2Project + '_lab'
$netBaoAdmin = $P2Project + '_bao-admin'
$volCa = $P2Project + '_pki-ca'
$realmFile = Join-Path $P2Root 'config\keycloak\lab-realm.json'

$script:Pass = 0
$script:Fail = 0
$script:Tokens = New-Object System.Collections.ArrayList

function Write-Result {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) { $script:Pass++; $tag = 'PASS'; $color = 'Green' } else { $script:Fail++; $tag = 'FAIL'; $color = 'Red' }
    Write-Host ('{0} {1}' -f $tag, $Name) -ForegroundColor $color
    if ($Detail) {
        foreach ($l in ($Detail.Trim() -split "`r?`n")) {
            if ($l.Trim()) { Write-Host ('       | ' + $l.TrimEnd()) }
        }
    }
}

function Assert-Refused {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -ne 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, $Result.All)
    if (-not $ok) { $detail = $detail + ("`n(expected a failure matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}

function Assert-Works {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -eq 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, $Result.All)
    if (-not $ok) { $detail = $detail + ("`n(expected success matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}

# --- identities -----------------------------------------------------------------------------
$realm = [System.IO.File]::ReadAllText($realmFile, $P2Utf8NoBom) | ConvertFrom-Json
function Get-TestPassword { param([string]$User) return [string](($realm.users | Where-Object { $_.username -eq $User }).credentials[0].value) }

function Get-IdToken {
    param([string]$User)
    $body = @{ grant_type = 'password'; client_id = 'bao-jwt-test'; username = $User; password = (Get-TestPassword $User); scope = 'openid' }
    $r = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8180/realms/lab/protocol/openid-connect/token' -Body $body -TimeoutSec 15
    return [string]$r.id_token
}

function Get-JwtClaims {
    param([string]$Jwt)
    $p = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    while ($p.Length % 4) { $p += '=' }
    return ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json)
}

# Returns @{ R = raw result; Token; Auth }.
function Connect-Bao {
    param([string]$User)
    $r = Invoke-Bao @('write', '-format=json', 'auth/jwt/login', 'role=dev', 'jwt=-') '' (Get-IdToken $User)
    $o = ConvertFrom-JsonOrNull $r.Out
    $tok = $null; $auth = $null
    if (($r.Code -eq 0) -and ($null -ne $o)) { $tok = [string]$o.auth.client_token; $auth = $o.auth; [void]$script:Tokens.Add($tok) }
    return @{ R = $r; Token = $tok; Auth = $auth }
}

# Returns @{ R; User; Password; Lease; Duration }.
function Get-Creds {
    param([string]$Token, [string]$Role)
    $r = Invoke-Bao @('read', '-format=json', ('database/creds/' + $Role)) $Token
    $o = ConvertFrom-JsonOrNull $r.Out
    if (($r.Code -eq 0) -and ($null -ne $o)) {
        return @{ R = $r; User = [string]$o.data.username; Password = [string]$o.data.password; Lease = [string]$o.lease_id; Duration = [int]$o.lease_duration }
    }
    return @{ R = $r; User = $null; Password = $null; Lease = $null; Duration = 0 }
}

# --- database clients -----------------------------------------------------------------------
function Invoke-PgClient {
    param([string]$Net, [string]$ConnInfo, [string]$Sql, [string]$Password)
    return Invoke-Docker @('run', '--rm', '--network', $Net, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD',
        '--entrypoint', 'psql', 'postgres:17', ($ConnInfo + ' connect_timeout=5'), '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', $Sql) @{ PGPASSWORD = $Password }
}
function Invoke-PgAdmin {
    param([string]$Sql)
    return Invoke-Docker @('exec', '-u', 'postgres', $ids['pg-primary'], 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', 'app1', '-c', $Sql)
}
function Invoke-MariaClient {
    param([string]$Net, [string]$HostName, [string]$User, [string]$Sql, [string]$Password, [string[]]$Tls = @('--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert'))
    $a = @('run', '--rm', '--network', $Net, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD',
        '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', $HostName, '-u', $User) + $Tls + @('--connect-timeout=5', '-N', '-B', 'app1_masked', '-e', $Sql)
    return Invoke-Docker $a @{ MYSQL_PWD = $Password }
}
$mariaRootPw = Read-P2Secret 'maria_root_password'
function Invoke-MariaAdmin {
    param([string]$Sql)
    return Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', $ids['maria-primary'], 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mariaRootPw }
}
function Get-PgRoleCount { param([string]$Name) return (Invoke-PgAdmin ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $Name)).Out.Trim() }
# Where OpenBao creates the MariaDB temp users: the primary (phases 2/3), or the replica with
# -MariaTempUsersOnReplica (phase 4).
$maTempHost = 'maria-primary'
if ($MariaTempUsersOnReplica) { $maTempHost = 'maria-replica' }
function Invoke-MariaTempAdmin {
    param([string]$Sql)
    return Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', $ids[$maTempHost], 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mariaRootPw }
}
function Get-MariaUserCount { param([string]$Name) return (Invoke-MariaTempAdmin ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $Name)).Out.Trim() }
function Note-Altered { param([string]$Text) if ($MariaTempUsersOnReplica) { Write-Host ('       | ALTERED (-MariaTempUsersOnReplica): ' + $Text) -ForegroundColor Yellow } }
# The same, on the developer-facing servers (= the primaries in phase 2).
function Invoke-PgDevAdmin {
    param([string]$Sql)
    return Invoke-Docker @('exec', '-u', 'postgres', $ids[$PgDevHost], 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', 'app1', '-c', $Sql)
}
function Invoke-MariaDevAdmin {
    param([string]$Sql)
    return Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', $ids[$MariaDevHost], 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mariaRootPw }
}
# Replication lag: a user created on the primary must reach the replica before it can log in.
# No-op in phase 2. Bounded wait; prints the observed delay.
function Wait-DevUsers {
    param([string]$PgUser, [string]$MariaUser)
    if (-not $devIsReplica) { return }
    $t0 = Get-Date
    $deadline = $t0.AddSeconds(30)
    do {
        $a = '1'; $b = '1'
        if ($PgUser) { $a = (Invoke-PgDevAdmin ("SELECT count(*) FROM pg_roles WHERE rolname = '{0}'" -f $PgUser)).Out.Trim() }
        if ($MariaUser) { $b = (Invoke-MariaDevAdmin ("SELECT COUNT(*) FROM mysql.user WHERE User = '{0}'" -f $MariaUser)).Out.Trim() }
        if (($a -eq '1') -and ($b -eq '1')) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    Write-Host ('       | users visible on {0} / {1} after {2:N1} s (pg rows {3}, maria rows {4})' -f $PgDevHost, $MariaDevHost, ((Get-Date) - $t0).TotalSeconds, $a, $b)
}

# Developer-facing connection (temp users) and the primary itself (negative checks from other
# networks and the bao_admin checks).
$verify = 'host=' + $PgDevHost + ' dbname=app1 sslmode=verify-full sslrootcert=/ca/ca.crt'
$verifyPrimary = 'host=pg-primary dbname=app1 sslmode=verify-full sslrootcert=/ca/ca.crt'
$root = Read-P2Secret $P2BaoRootTokenName
function BaoRoot { param([string[]]$A, [string]$Stdin = $null) Invoke-Bao $A $root $Stdin }

Write-Host ('Phase 2 checks: compose file {0}; developer-facing hosts {1}, {2}' -f $P2ComposeFile, $PgDevHost, $MariaDevHost)
$ids = @{}
foreach ($s in (@('pg-primary', 'maria-primary', 'openbao', 'keycloak', $PgDevHost, $MariaDevHost, $maTempHost) | Select-Object -Unique)) { $ids[$s] = Get-P2ContainerId $s }
if ($MariaTempUsersOnReplica) { Write-Host ('MariaDB temp users are expected on {0} only (-MariaTempUsersOnReplica); MariaDB temp-user facts are read there.' -f $maTempHost) }
$s = Get-BaoStatus
if (($null -eq $s.Obj) -or $s.Obj.sealed) { throw 'OpenBao is sealed or not answering. Run scripts\phase2-unseal.ps1 (or phase2-setup.ps1).' }

# =============================================================================================
Write-Host ''
Write-Host '== OpenBao server: not dev mode, TLS, audit device, published ports =='

$cmd = (Invoke-Docker @('inspect', '-f', '{{json .Config.Cmd}}', $ids['openbao'])).Out.Trim()
$st = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'sys/config/state/sanitized')).Out
$stDesc = ('container cmd {0}; storage={1}; seal={2}; initialized={3}; sealed={4}' -f $cmd, $st.data.storage.type, $st.data.seals[0].type, $s.Obj.initialized, $s.Obj.sealed)
$ok = ($cmd -notmatch '-dev') -and ($cmd -match 'server') -and ($st.data.storage.type -eq 'raft') -and ($st.data.seals[0].type -eq 'shamir') -and $s.Obj.initialized
Write-Result $ok 'OpenBao runs from bao.hcl, not dev mode: Raft storage, Shamir seal, initialized (dev mode would be inmem and auto-unsealed)' $stDesc

$r = BaoRoot @('audit', 'list', '-detailed')
Assert-Works 'OpenBao: file audit device main/ from the server configuration is enabled' $r 'main/\s+file\s+.*file_path=/openbao/logs/audit\.log'
$r = BaoRoot @('audit', 'enable', '-path=p2probe', 'file', 'file_path=/tmp/p2probe.log')
Assert-Refused 'OpenBao: creating an audit device over the API is refused (root token)' $r 'cannot enable audit device via API'
Write-Result ($st.data.unsafe_allow_api_audit_creation -eq $false) 'OpenBao: unsafe_allow_api_audit_creation is false' ('unsafe_allow_api_audit_creation=' + $st.data.unsafe_allow_api_audit_creation)

$r = Invoke-Docker @('run', '--rm', '--network', $netLab, '-v', ($volCa + ':/ca:ro'), '--entrypoint', 'sh', 'postgres:17', '-c',
    'echo | openssl s_client -connect openbao:8200 -servername openbao -CAfile /ca/ca.crt -verify_hostname openbao -verify_return_error 2>&1 | grep -E "^(subject|issuer)=|Verify return code|Protocol"')
Assert-Works 'OpenBao: TLS listener presents a lab-CA certificate valid for "openbao" (openssl verify from the lab network)' $r 'Verify return code: 0 \(ok\)'

$pb = @()
foreach ($svc in @('openbao', 'keycloak', 'pg-primary', 'maria-primary')) {
    $x = (Invoke-Docker @('inspect', '-f', '{{json .HostConfig.PortBindings}}', $ids[$svc])).Out.Trim()
    $pb += ('{0}: {1}' -f $svc, $x)
}
$pbText = $pb -join "`n"
$ok = ($pbText -match 'openbao: \{"8200/tcp":\[\{"HostIp":"127\.0\.0\.1","HostPort":"8200"\}\]\}') -and
      ($pbText -match 'keycloak: \{"8180/tcp":\[\{"HostIp":"127\.0\.0\.1","HostPort":"8180"\}\]\}') -and
      ($pbText -match 'pg-primary: (\{\}|null)') -and ($pbText -match 'maria-primary: (\{\}|null)')
Write-Result $ok 'Ports: OpenBao and Keycloak published on 127.0.0.1 only; no database port published' $pbText

# =============================================================================================
Write-Host ''
Write-Host '== Authentication (Keycloak -> OpenBao) and authorization =='

$claimsA = Get-JwtClaims (Get-IdToken 'alice')
$claimsB = Get-JwtClaims (Get-IdToken 'bob')
$d = ('alice: iss={0} aud={1} preferred_username={2} groups={3}' -f $claimsA.iss, $claimsA.aud, $claimsA.preferred_username, ($claimsA.groups -join ',')) + "`n" +
     ('bob:   iss={0} aud={1} preferred_username={2} groups={3}' -f $claimsB.iss, $claimsB.aud, $claimsB.preferred_username, ($claimsB.groups -join ','))
$ok = ($claimsA.iss -eq 'http://keycloak.localhost:8180/realms/lab') -and (@($claimsA.groups) -contains 'app1-devs') -and (-not (@($claimsB.groups) -contains 'app1-devs')) -and ($claimsA.preferred_username -eq 'alice')
Write-Result $ok 'Keycloak: ID tokens carry preferred_username and a short "groups" claim; alice in app1-devs, bob not' $d

$alice = Connect-Bao 'alice'
$ok = ($null -ne $alice.Token) -and (@($alice.Auth.identity_policies) -contains 'app1-debug')
Write-Result $ok 'alice logs in to OpenBao (jwt) and gets policy app1-debug through identity group app1-devs' ('exit {0}; display policies={1}; identity_policies={2}; metadata={3}' -f $alice.R.Code, (@($alice.Auth.policies) -join ','), (@($alice.Auth.identity_policies) -join ','), ($alice.Auth.metadata | ConvertTo-Json -Compress))
$bob = Connect-Bao 'bob'
$ok = ($null -ne $bob.Token) -and (-not (@($bob.Auth.policies) -contains 'app1-debug')) -and (-not (@($bob.Auth.identity_policies) -contains 'app1-debug'))
Write-Result $ok 'control: bob can log in to OpenBao (jwt) but gets only the default policy' ('exit {0}; policies={1}; identity_policies={2}' -f $bob.R.Code, (@($bob.Auth.policies) -join ','), (@($bob.Auth.identity_policies) -join ','))

$apg = Get-Creds $alice.Token 'app1-pg-ro'
Write-Result ($null -ne $apg.User) 'alice reads database/creds/app1-pg-ro' ('exit {0}; username={1}; lease={2}; lease_duration={3}s' -f $apg.R.Code, $apg.User, $apg.Lease, $apg.Duration)
$amr = Get-Creds $alice.Token 'app1-maria-ro'
Write-Result ($null -ne $amr.User) 'alice reads database/creds/app1-maria-ro' ('exit {0}; username={1}; lease={2}; lease_duration={3}s' -f $amr.R.Code, $amr.User, $amr.Lease, $amr.Duration)
Write-Result (($apg.Duration -eq 3600) -and ($amr.Duration -eq 3600)) 'both leases have default_ttl 1h' ('pg {0}s, maria {1}s' -f $apg.Duration, $amr.Duration)

$r = (Get-Creds $bob.Token 'app1-pg-ro').R
Assert-Refused 'bob is denied database/creds/app1-pg-ro' $r 'Code: 403[\s\S]*permission denied'
$r = (Get-Creds $bob.Token 'app1-maria-ro').R
Assert-Refused 'bob is denied database/creds/app1-maria-ro' $r 'Code: 403[\s\S]*permission denied'

$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
foreach ($c in @(@{ N = 'PostgreSQL'; U = $apg.User; Re = '^v-jwt-alice-app1-pg-ro-(\d{10})-[A-Za-z0-9]{4}$' }, @{ N = 'MariaDB'; U = $amr.User; Re = '^v-jwt-alice-app1-maria-ro-(\d{10})-[A-Za-z0-9]{4}$' })) {
    $ok = ([string]$c.U) -match $c.Re
    $ts = 0; if ($ok) { $ts = [long]$Matches[1] }
    $ok = $ok -and ([Math]::Abs($now - $ts) -lt 600)
    Write-Result $ok ('{0}: generated username names the requester (alice) and embeds the unix time of issue' -f $c.N) ('{0} -> timestamp {1} = {2:u} (now {3})' -f $c.U, $ts, [DateTimeOffset]::FromUnixTimeSeconds($ts).UtcDateTime, $now)
}

# Interactive path (oidc mount): OpenBao builds the Keycloak authorization URL from the issuer's
# discovery document, which it fetched from inside the container under the browser-facing name.
$r = BaoRoot @('write', '-format=json', 'auth/oidc/oidc/auth_url', 'role=dev', 'redirect_uri=https://localhost:8200/ui/vault/auth/oidc/oidc/callback')
$o = ConvertFrom-JsonOrNull $r.Out
$url = ''; if ($null -ne $o) { $url = [string]$o.data.auth_url }
$ok = ($r.Code -eq 0) -and ($url -match '^http://keycloak\.localhost:8180/realms/lab/protocol/openid-connect/auth\?') -and ($url -match 'client_id=openbao')
Write-Result $ok 'oidc mount: discovery works from the container and yields a browser URL on keycloak.localhost:8180 for client openbao' ($url -replace '(state|nonce|code_challenge)=[^&]+', '$1=...')
$oidcRole = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'auth/oidc/role/dev')).Out
$jwtRole = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'auth/jwt/role/dev')).Out
$d = ('oidc: user_claim={0} groups_claim={1} token_max_ttl={2}' -f $oidcRole.data.user_claim, $oidcRole.data.groups_claim, $oidcRole.data.token_max_ttl) + "`n" +
     ('jwt:  user_claim={0} groups_claim={1} token_max_ttl={2} bound_audiences={3}' -f $jwtRole.data.user_claim, $jwtRole.data.groups_claim, $jwtRole.data.token_max_ttl, (@($jwtRole.data.bound_audiences) -join ','))
$ok = ($oidcRole.data.user_claim -eq 'preferred_username') -and ($oidcRole.data.groups_claim -eq 'groups') -and ($jwtRole.data.user_claim -eq 'preferred_username') -and ($jwtRole.data.groups_claim -eq 'groups') -and ($oidcRole.data.token_max_ttl -eq 14400) -and ($jwtRole.data.token_max_ttl -eq 14400)
Write-Result $ok 'oidc and jwt roles: user_claim=preferred_username, groups_claim=groups, token_max_ttl 4h' $d
$ga = @()
foreach ($m in @('oidc', 'jwt')) {
    $g = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', ('identity/group/name/app1-devs-' + $m))).Out
    $ga += ('app1-devs-{0}: type={1} alias={2} on {3}' -f $m, $g.data.type, $g.data.alias.name, $g.data.alias.mount_path)
}
$gi = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'identity/group/name/app1-devs')).Out
$ga += ('app1-devs: type={0} policies={1} member groups={2}' -f $gi.data.type, (@($gi.data.policies) -join ','), @($gi.data.member_group_ids).Count)
$gaText = $ga -join "`n"
$ok = ($gaText -match 'app1-devs-oidc: type=external alias=app1-devs on auth/oidc/') -and ($gaText -match 'app1-devs-jwt: type=external alias=app1-devs on auth/jwt/') -and ($gaText -match 'app1-devs: type=internal policies=app1-debug member groups=2')
Write-Result $ok 'identity: group alias app1-devs on both mounts; policy on the internal group app1-devs' $gaText
try {
    $intro = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8180/realms/lab/protocol/openid-connect/token/introspect' -Body @{ client_id = 'openbao'; client_secret = (Read-P2Secret 'keycloak_openbao_client_secret'); token = 'x' } -TimeoutSec 10
    Write-Result $true 'Keycloak accepts the openbao client secret from secrets\ (imported via placeholder)' ('introspect: ' + ($intro | ConvertTo-Json -Compress))
} catch {
    Write-Result $false 'Keycloak accepts the openbao client secret from secrets\ (imported via placeholder)' $_.Exception.Message
}

# =============================================================================================
Write-Host ''
Write-Host ('== PostgreSQL with alice''s temporary credentials (client on the access network, host {0}) ==' -f $PgDevHost)
Wait-DevUsers $apg.User $amr.User
$pgU = 'user=' + $apg.User
$pgPw = $apg.Password
function PgA { param([string]$Sql, [string]$Extra = '') Invoke-PgClient $netAccess ($verify + ' ' + $pgU + ' ' + $Extra) $Sql $pgPw }

$r = PgA "SELECT 'user=' || current_user || ' ssl=' || s.ssl || ' ' || s.version FROM pg_stat_ssl s WHERE s.pid = pg_backend_pid()"
Assert-Works 'PG: TLS (verify-full) login with alice''s credentials' $r ('user=' + [regex]::Escape($apg.User) + ' ssl=true TLSv1\.[23]')
$r = PgA "SELECT string_agg(id || ':' || email || ':' || full_name, ' ' ORDER BY id) FROM debug.customers"
$ok = ($r.Code -eq 0) -and ($r.Out -match '\d+:al\*\*\*:A\*\*\*') -and ($r.Out -notmatch '@') -and ($r.Out -notmatch 'Example')
Write-Result $ok 'PG: SELECT on debug.customers works; email and full_name are masked' ('exit {0}: {1}' -f $r.Code, $r.All)
$r = PgA 'SELECT count(*) FROM debug.orders'
Assert-Works 'PG: SELECT on debug.orders works' $r '^\d+'
$r = PgA 'SELECT email FROM public.customers LIMIT 1'
Assert-Refused 'PG: SELECT on base table public.customers is denied' $r 'permission denied for table customers'
$r = PgA 'SELECT total FROM public.orders LIMIT 1'
Assert-Refused 'PG: SELECT on base table public.orders is denied' $r 'permission denied for table orders'
$r = PgA "INSERT INTO public.customers (email, full_name) VALUES ('x@x.test', 'X')"
Assert-Refused 'PG: INSERT into public.customers is denied' $r ('permission denied for table customers' + $pgRo)
$r = PgA 'UPDATE public.orders SET total = 0'
Assert-Refused 'PG: UPDATE public.orders is denied' $r ('permission denied for table orders' + $pgRo)
$r = PgA 'DELETE FROM public.customers'
Assert-Refused 'PG: DELETE FROM public.customers is denied' $r ('permission denied for table customers' + $pgRo)
# debug.orders is a simple (auto-updatable) view, so the refusal comes from the privilege check.
$r = PgA 'INSERT INTO debug.orders (customer_id, total) VALUES (1, 1)'
Assert-Refused 'PG: INSERT through the view debug.orders is denied' $r ('permission denied for view orders' + $pgRo)
$r = PgA 'CREATE TABLE p2_probe (id int)'
Assert-Refused 'PG: CREATE TABLE (schema public) is denied' $r ('permission denied for schema public' + $pgRo)
$r = PgA 'CREATE TABLE debug.p2_probe (id int)'
Assert-Refused 'PG: CREATE TABLE in schema debug is denied' $r ('permission denied for schema debug' + $pgRo)
$r = PgA 'CREATE TEMP TABLE p2_probe (id int)'
Assert-Refused 'PG: CREATE TEMP TABLE is denied' $r ('permission denied to create temporary tables' + $pgRo)
$r = Invoke-PgClient $netAccess ('host=' + $PgDevHost + ' dbname=postgres sslmode=verify-full sslrootcert=/ca/ca.crt ' + $pgU) 'SELECT 1' $pgPw
Assert-Refused 'PG: connecting to database postgres is denied' $r 'pg_hba\.conf rejects connection .*database "postgres"'
$r = Invoke-PgClient $netAccess ('host=' + $PgDevHost + ' dbname=app1 sslmode=disable ' + $pgU) 'SELECT 1' $pgPw
Assert-Refused 'PG: connecting without TLS is denied' $r 'pg_hba\.conf rejects connection .*no encryption'

$r = PgA "SELECT 'statement_timeout=' || current_setting('statement_timeout') || ' idle_session_timeout=' || current_setting('idle_session_timeout')"
Assert-Works 'PG: session defaults statement_timeout=60s, idle_session_timeout=15min' $r 'statement_timeout=1min idle_session_timeout=15min|statement_timeout=60s idle_session_timeout=15min'
$r = Invoke-PgAdmin ("SELECT 'connlimit=' || rolconnlimit || ' valid_until_set=' || (rolvaliduntil IS NOT NULL) || ' login=' || rolcanlogin || ' super=' || rolsuper || ' createrole=' || rolcreaterole || ' config=' || array_to_string(rolconfig, ',') || ' member_of=' || (SELECT string_agg(b.rolname, ',') FROM pg_auth_members m JOIN pg_roles b ON b.oid = m.roleid WHERE m.member = r.oid) FROM pg_roles r WHERE rolname = '{0}'" -f $apg.User)
Assert-Works 'PG: temp role has CONNECTION LIMIT 2, VALID UNTIL, default timeouts, member only of debug_ro' $r 'connlimit=2 valid_until_set=true login=true super=false createrole=false config=statement_timeout=60s,idle_session_timeout=15min member_of=debug_ro$'

# =============================================================================================
Write-Host ''
Write-Host ('== MariaDB with alice''s temporary credentials (client on the access network, host {0}) ==' -f $MariaDevHost)
$mU = $amr.User
$mPw = $amr.Password
function MA { param([string]$Sql) Invoke-MariaClient $netAccess $MariaDevHost $mU $Sql $mPw }

$r = MA "SELECT CONCAT('user=', CURRENT_USER(), ' tls=', (SELECT VARIABLE_VALUE FROM information_schema.SESSION_STATUS WHERE VARIABLE_NAME = 'Ssl_version'))"
Assert-Works 'Maria: TLS login (CA + server cert verification) with alice''s credentials' $r ('user=' + [regex]::Escape($mU) + '@10\.81\.5\.0/255\.255\.255\.0 tls=TLSv1\.[23]')
$r = MA "SELECT GROUP_CONCAT(CONCAT(id, ':', email, ':', full_name) ORDER BY id SEPARATOR ' ') FROM app1_masked.customers"
$ok = ($r.Code -eq 0) -and ($r.Out -match '\d+:al\*\*\*:A\*\*\*') -and ($r.Out -notmatch '@') -and ($r.Out -notmatch 'Example')
Write-Result $ok 'Maria: SELECT on app1_masked.customers works; email and full_name are masked' ('exit {0}: {1}' -f $r.Code, $r.All)
$r = MA 'SELECT COUNT(*) FROM app1_masked.orders'
Assert-Works 'Maria: SELECT on app1_masked.orders works' $r '^\d+'
$r = MA 'SELECT email FROM app1.customers LIMIT 1'
Assert-Refused 'Maria: SELECT on base table app1.customers is denied' $r 'SELECT command denied to user'
$r = MA 'SELECT total FROM app1.orders LIMIT 1'
Assert-Refused 'Maria: SELECT on base table app1.orders is denied' $r 'SELECT command denied to user'
$r = MA "INSERT INTO app1.customers (email, full_name) VALUES ('x@x.test', 'X')"
Assert-Refused 'Maria: INSERT into app1.customers is denied' $r ('INSERT command denied to user' + $maRo)
$r = MA 'UPDATE app1.orders SET total = 0'
Assert-Refused 'Maria: UPDATE app1.orders is denied' $r ('UPDATE command denied to user' + $maRo)
$r = MA 'DELETE FROM app1.customers'
Assert-Refused 'Maria: DELETE FROM app1.customers is denied' $r ('DELETE command denied to user' + $maRo)
$r = MA 'INSERT INTO app1_masked.orders (customer_id, total) VALUES (1, 1)'
Assert-Refused 'Maria: INSERT through the view app1_masked.orders is denied' $r ('INSERT command denied to user' + $maRo)
$r = MA 'CREATE TABLE app1_masked.p2_probe (id int)'
Assert-Refused 'Maria: CREATE TABLE is denied' $r ('CREATE command denied to user' + $maRo)
$r = MA "SELECT * FROM app1_masked.customers INTO OUTFILE '/tmp/p2_probe.csv'"
Assert-Refused 'Maria: SELECT ... INTO OUTFILE is denied' $r ('Access denied; you need \(at least one of\) the FILE privilege' + $maRo)
$ctl = Invoke-MariaAdmin "SELECT CONCAT('root LOAD_FILE(/etc/hostname) is_null=', LOAD_FILE('/etc/hostname') IS NULL)"
Assert-Works 'Maria: control: LOAD_FILE works for root (FILE privilege), so a NULL below is the privilege check' $ctl 'is_null=0'
$r = MA "SELECT CONCAT('LOAD_FILE(/etc/hostname) is_null=', LOAD_FILE('/etc/hostname') IS NULL, ' LOAD_FILE(/etc/passwd) is_null=', LOAD_FILE('/etc/passwd') IS NULL)"
Assert-Works 'Maria: LOAD_FILE returns nothing (NULL) for alice' $r 'LOAD_FILE\(/etc/hostname\) is_null=1 LOAD_FILE\(/etc/passwd\) is_null=1'
$r = Invoke-MariaClient $netAccess $MariaDevHost $mU 'SELECT 1' $mPw @('--skip-ssl')
Assert-Refused 'Maria: connecting without TLS is denied' $r 'insecure transport are prohibited'
Note-Altered ('the temp user''s grants are read on {0}, where OpenBao created it (it does not exist on the primary)' -f $maTempHost)
$r = Invoke-MariaTempAdmin ("SHOW GRANTS FOR '{0}'@'10.81.5.0/255.255.255.0'; SELECT CONCAT('password_lifetime_days=', JSON_VALUE(Priv, '$.password_lifetime')) FROM mysql.global_priv WHERE User = '{0}'" -f $mU)
$shown = $r.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'"
$grantLines = @($r.Out -split "`r?`n" | Where-Object { $_ -match '^GRANT' })
$ok = ($r.Code -eq 0) -and ($grantLines.Count -eq 2) -and ($r.Out -match 'GRANT USAGE ON \*\.\* TO .* REQUIRE SSL WITH MAX_USER_CONNECTIONS 2 MAX_STATEMENT_TIME 60\.0+') -and
      ($r.Out -match 'GRANT SELECT ON `app1_masked`\.\* TO') -and ($r.Out -match 'password_lifetime_days=1')
Write-Result $ok 'Maria: temp user has only SELECT on app1_masked.*, REQUIRE SSL, 2 connections, 60 s statements, password lifetime 1 day' $shown

# =============================================================================================
Write-Host ''
Write-Host '== Temp users only from the access network =='
$r = Invoke-PgClient $netPg ($verifyPrimary + ' ' + $pgU) 'SELECT 1' $pgPw
Assert-Refused 'PG: alice''s credentials from the app1-pg network are rejected by pg_hba (+debug_ro reject)' $r ('pg_hba\.conf rejects connection for host "10\.81\.2\.\d+", user "' + [regex]::Escape($apg.User) + '"')
$r = Invoke-PgClient $netBaoAdmin ($verifyPrimary + ' ' + $pgU) 'SELECT 1' $pgPw
Assert-Refused 'PG: alice''s credentials from the bao-admin network (not OpenBao''s address) are rejected by pg_hba' $r ('pg_hba\.conf rejects connection for host "10\.81\.4\.\d+", user "' + [regex]::Escape($apg.User) + '"')
if ($MariaTempUsersOnReplica) {
    $x = (Invoke-MariaAdmin ("SELECT COUNT(*) FROM mysql.global_priv WHERE User = '{0}'" -f $mU)).Out.Trim()
    Write-Result ($x -eq '0') 'Maria: alice''s temp user does not exist on the primary at all (created on the replica only, sql_log_bin=0)' ('mysql.global_priv rows on maria-primary for {0}: {1}' -f $mU, $x)
    Note-Altered 'the two primary checks below still expect "Access denied"; on the primary it now comes from the missing account, not only from the host mask'
}
$r = Invoke-MariaClient $netMaria 'maria-primary' $mU 'SELECT 1' $mPw
Assert-Refused 'Maria: alice''s credentials from the app1-maria network are rejected (host mask)' $r ("Access denied for user '" + [regex]::Escape($mU) + "'@'10\.81\.3\.\d+'")
$r = Invoke-MariaClient $netBaoAdmin 'maria-primary' $mU 'SELECT 1' $mPw
# No account at all matches a bao-admin address other than OpenBao's, so MariaDB refuses the host.
Assert-Refused 'Maria: alice''s credentials from the bao-admin network are rejected (host mask)' $r ("Access denied for user '" + [regex]::Escape($mU) + "'@'10\.81\.4\.\d+'|Host '10\.81\.4\.\d+' is not allowed to connect")
$r = Invoke-PgClient $netLab ($verifyPrimary + ' ' + $pgU) 'SELECT 1' $pgPw
Assert-Refused 'PG: from the lab network the database is not reachable at all' $r 'could not translate host name "pg-primary"'

# =============================================================================================
Write-Host ''
Write-Host '== bao_admin: rotate-root and privileges =='

# PostgreSQL: compare the stored SCRAM verifier with the initial password (no password printed).
function Test-ScramVerifier {
    param([string]$Verifier, [string]$Password)
    if ($Verifier -notmatch '^SCRAM-SHA-256\$(\d+):([^$]+)\$([^:]+):(.+)$') { return $null }
    $iter = [int]$Matches[1]; $salt = [Convert]::FromBase64String($Matches[2]); $stored = $Matches[3]
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(([System.Text.Encoding]::UTF8.GetBytes($Password)), $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $salted = $kdf.GetBytes(32)
    $h = New-Object System.Security.Cryptography.HMACSHA256(, $salted)
    $clientKey = $h.ComputeHash([System.Text.Encoding]::ASCII.GetBytes('Client Key'))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return ([Convert]::ToBase64String($sha.ComputeHash($clientKey)) -eq $stored)
}
$vBao = (Invoke-PgAdmin "SELECT rolpassword FROM pg_authid WHERE rolname = 'bao_admin'").Out.Trim()
$vRt = (Invoke-PgAdmin "SELECT rolpassword FROM pg_authid WHERE rolname = 'app1_runtime'").Out.Trim()
$ctlMatch = Test-ScramVerifier $vRt (Read-P2Secret 'pg_app1_runtime_password')
$baoMatch = Test-ScramVerifier $vBao (Read-P2Secret 'pg_bao_admin_initial_password')
Write-Result (($ctlMatch -eq $true) -and ($baoMatch -eq $false)) 'PG: rotate-root changed bao_admin: stored SCRAM verifier no longer matches the initial password' ('control app1_runtime verifier matches its secret: {0}; bao_admin verifier matches initial password: {1}' -f $ctlMatch, $baoMatch)
# Live: log in as bao_admin from OpenBao's own network namespace (the only address pg_hba allows).
$r = Invoke-Docker @('run', '--rm', '--network', ('container:' + $ids['openbao']), '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD',
    '--entrypoint', 'psql', 'postgres:17', ($verifyPrimary + ' user=bao_admin connect_timeout=5'), '-X', '-At', '-c', 'SELECT 1') @{ PGPASSWORD = (Read-P2Secret 'pg_bao_admin_initial_password') }
Assert-Refused 'PG: the initial bao_admin password from secrets\ no longer works (from OpenBao''s address, so pg_hba allows the attempt)' $r 'password authentication failed for user "bao_admin"'

function Get-NativeHash { param([string]$Password)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $h = $sha.ComputeHash($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password)))
    return ('*' + (($h | ForEach-Object { $_.ToString('X2') }) -join ''))
}
$hBao = (Invoke-MariaAdmin "SELECT authentication_string FROM mysql.user WHERE User = 'bao_admin'").Out.Trim()
$hRt = (Invoke-MariaAdmin "SELECT authentication_string FROM mysql.user WHERE User = 'app1_runtime'").Out.Trim()
$ctlMatch = ($hRt -eq (Get-NativeHash (Read-P2Secret 'maria_app1_runtime_password')))
$baoMatch = ($hBao -eq (Get-NativeHash (Read-P2Secret 'maria_bao_admin_initial_password')))
Write-Result ($ctlMatch -and (-not $baoMatch) -and ($hBao.Length -eq 41)) 'Maria: rotate-root changed bao_admin: stored hash no longer matches the initial password' ('control app1_runtime hash matches its secret: {0}; bao_admin hash matches initial password: {1}' -f $ctlMatch, $baoMatch)
$r = Invoke-Docker @('run', '--rm', '--network', ('container:' + $ids['openbao']), '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD',
    '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', 'maria-primary', '-u', 'bao_admin', '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert', '--connect-timeout=5', '-N', '-e', 'SELECT 1') @{ MYSQL_PWD = (Read-P2Secret 'maria_bao_admin_initial_password') }
Assert-Refused 'Maria: the initial bao_admin password from secrets\ no longer works (from OpenBao''s address)' $r "Access denied for user 'bao_admin'@'10\.81\.4\.10' \(using password: YES\)"

$r = Invoke-MariaAdmin "SHOW GRANTS FOR 'bao_admin'@'10.81.4.10'"
$shown = $r.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'"
$grantLines = @($r.Out -split "`r?`n" | Where-Object { $_ -match '^GRANT' })
$ok = ($r.Code -eq 0) -and ($grantLines.Count -eq 2) -and ($r.Out -match 'GRANT CREATE USER, CONNECTION ADMIN ON \*\.\* TO `bao_admin`@`10\.81\.4\.10`.*REQUIRE SSL') -and
      ($r.Out -match 'GRANT SELECT ON `app1_masked`\.\* TO `bao_admin`@`10\.81\.4\.10` WITH GRANT OPTION') -and ($r.Out -notmatch '`app1`\.')
Write-Result $ok 'Maria: bao_admin grants: CREATE USER + CONNECTION ADMIN, SELECT on app1_masked only, host 10.81.4.10, REQUIRE SSL, nothing on app1' $shown
# Live, through OpenBao's own bao_admin session: LAB-ONLY probe roles run one SELECT as their
# creation statement (they create no user), then are deleted again.
$probeRevoke = 'revocation_statements=DO 0'
[void](BaoRoot @('write', 'database/roles/lab-probe-maria-masked', 'db_name=app1-maria', 'default_ttl=1m', 'max_ttl=1m', 'creation_statements=SELECT COUNT(*) FROM app1_masked.customers', $probeRevoke))
[void](BaoRoot @('write', 'database/roles/lab-probe-maria-basetable', 'db_name=app1-maria', 'default_ttl=1m', 'max_ttl=1m', 'creation_statements=SELECT COUNT(*) FROM app1.customers', $probeRevoke))
$r = BaoRoot @('read', '-format=json', 'database/creds/lab-probe-maria-masked')
$o = ConvertFrom-JsonOrNull $r.Out
Write-Result ($r.Code -eq 0) 'Maria: control: bao_admin (via OpenBao) can SELECT from app1_masked.customers' ('exit {0}: {1}' -f $r.Code, $(if ($r.Code -eq 0) { 'statement ran; lease ' + $o.lease_id } else { $r.All }))
if ($null -ne $o) { [void](BaoRoot @('lease', 'revoke', $o.lease_id)) }
$r = BaoRoot @('read', 'database/creds/lab-probe-maria-basetable')
Assert-Refused 'Maria: bao_admin (via OpenBao) cannot SELECT from app1.customers' $r "SELECT command denied to user 'bao_admin'@'10\.81\.4\.10' for table .app1.\..customers."
[void](BaoRoot @('delete', 'database/roles/lab-probe-maria-masked'))
[void](BaoRoot @('delete', 'database/roles/lab-probe-maria-basetable'))

# =============================================================================================
Write-Host ''
Write-Host '== OpenBao audit log: person -> lease -> database username =='
$r = Invoke-Docker @('exec', '-e', 'P2U', $ids['openbao'], 'sh', '-c', 'grep -F "$P2U" /openbao/logs/audit.log') @{ P2U = $apg.User }
$entry = $null
foreach ($line in ($r.Out -split "`n")) {
    $e = ConvertFrom-JsonOrNull $line
    if (($null -ne $e) -and ($e.type -eq 'response') -and ($e.request.path -eq 'database/creds/app1-pg-ro') -and ($e.response.data.username -eq $apg.User)) { $entry = $e }
}
if ($null -ne $entry) {
    $d = ('time={0} display_name={1} metadata.username={2} entity_id={3} path={4} lease_id={5} data.username={6} data.password={7}' -f $entry.time, $entry.auth.display_name, $entry.auth.metadata.username, $entry.auth.entity_id, $entry.request.path, $entry.response.secret.lease_id, $entry.response.data.username, $entry.response.data.password)
    $ok = ($entry.auth.display_name -eq 'jwt-alice') -and ($entry.auth.metadata.username -eq 'alice') -and ($entry.response.secret.lease_id -eq $apg.Lease) -and ([string]$entry.response.data.password -match '^hmac-sha256:')
} else { $d = ('no response entry for {0} found: {1}' -f $apg.User, $r.All); $ok = $false }
Write-Result $ok 'Audit: one response entry ties alice (display name, metadata, entity) to the lease and the clear DB username; password is HMAC''d' $d
$ent = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', ('identity/entity/id/' + $entry.auth.entity_id))).Out
Write-Result (($null -ne $ent) -and ($ent.data.aliases[0].name -eq 'alice')) 'Audit: the entity_id in that entry resolves to the identity alias alice' ('entity {0}: name={1} alias={2} on {3}' -f $entry.auth.entity_id, $ent.data.name, $ent.data.aliases[0].name, $ent.data.aliases[0].mount_path)
$cnt = @()
foreach ($c in @($apg, $amr)) {
    $x = Invoke-Docker @('exec', '-e', 'P2P', $ids['openbao'], 'sh', '-c', 'test -s /openbao/logs/audit.log && grep -cF "$P2P" /openbao/logs/audit.log; true') @{ P2P = $c.Password }
    $cnt += $x.Out.Trim()
}
$sz = (Invoke-Docker @('exec', $ids['openbao'], 'sh', '-c', 'wc -l < /openbao/logs/audit.log')).Out.Trim()
Write-Result (($cnt[0] -eq '0') -and ($cnt[1] -eq '0')) 'Audit: the generated passwords do not appear in clear text in the audit log' ('occurrences: pg password {0}, maria password {1} (audit log has {2} lines)' -f $cnt[0], $cnt[1], $sz)
$tune = ConvertFrom-JsonOrNull (BaoRoot @('read', '-format=json', 'sys/mounts/database/tune')).Out
Write-Result ((@($tune.data.audit_non_hmac_response_keys) -join ',') -eq 'username') 'Audit: database/ mount has audit_non_hmac_response_keys=username (default would HMAC the username too)' ('audit_non_hmac_response_keys=' + (@($tune.data.audit_non_hmac_response_keys) -join ','))

# =============================================================================================
Write-Host ''
Write-Host '== Early revocation (bao token revoke -self) =='
$sessTag = 'p2open' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$rev = Connect-Bao 'alice'
$rpg = Get-Creds $rev.Token 'app1-pg-ro'
$rmr = Get-Creds $rev.Token 'app1-maria-ro'
Write-Host ('       | fresh alice token; pg user {0}; maria user {1}' -f $rpg.User, $rmr.User)
Wait-DevUsers $rpg.User $rmr.User
$pgSess = $sessTag + '-pg'
$maSess = $sessTag + '-maria'
$x = Invoke-Docker @('run', '-d', '--name', $pgSess, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD', '--entrypoint', 'psql', 'postgres:17',
    ($verify + ' user=' + $rpg.User), '-X', '-At', '-c', "SELECT 'session open as ' || current_user", '-c', 'SELECT pg_sleep(45)', '-c', "SELECT 'STILL ALIVE after 45 s'") @{ PGPASSWORD = $rpg.Password }
$y = Invoke-Docker @('run', '-d', '--name', $maSess, '--network', $netAccess, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD', '--entrypoint', 'mariadb', 'mariadb:11.8',
    '-h', $MariaDevHost, '-u', $rmr.User, '--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert', '--skip-reconnect', '-N', '-B', 'app1_masked',
    '-e', "SELECT CONCAT('session open as ', CURRENT_USER()); SELECT SLEEP(45); SELECT 'STILL ALIVE after 45 s';") @{ MYSQL_PWD = $rmr.Password }
# Wait until both sessions are visible on the servers.
$deadline = (Get-Date).AddSeconds(30)
$pgOpen = '0'; $maOpen = '0'
while ((Get-Date) -lt $deadline) {
    $pgOpen = (Invoke-PgDevAdmin ("SELECT count(*) FROM pg_stat_activity WHERE usename = '{0}'" -f $rpg.User)).Out.Trim()
    $maOpen = (Invoke-MariaDevAdmin ("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER = '{0}'" -f $rmr.User)).Out.Trim()
    if (($pgOpen -ne '0') -and ($maOpen -ne '0')) { break }
    Start-Sleep -Seconds 1
}
Write-Result (($pgOpen -ne '0') -and ($maOpen -ne '0')) 'control: an open session for each temp user is running before revocation' ('pg_stat_activity sessions: {0}; MariaDB processlist sessions: {1}' -f $pgOpen, $maOpen)
$t0 = Get-Date
$r = Invoke-Bao @('token', 'revoke', '-self') $rev.Token
Write-Result ($r.Code -eq 0) 'alice runs "bao token revoke -self" (default policy)' ('exit {0}: {1}' -f $r.Code, $r.All)
[void](Invoke-Docker @('wait', $pgSess) @{} 60)
$elPg = [int]((Get-Date) - $t0).TotalSeconds
[void](Invoke-Docker @('wait', $maSess) @{} 60)
$elMa = [int]((Get-Date) - $t0).TotalSeconds
$lp = Invoke-Docker @('logs', $pgSess)
$lm = Invoke-Docker @('logs', $maSess)
$ep = (Invoke-Docker @('inspect', '-f', '{{.State.ExitCode}}', $pgSess)).Out.Trim()
$em = (Invoke-Docker @('inspect', '-f', '{{.State.ExitCode}}', $maSess)).Out.Trim()
[void](Invoke-Docker @('rm', '-f', $pgSess, $maSess))
$ok = ($lp.All -match 'session open as') -and ($lp.All -match 'terminating connection due to administrator command') -and ($lp.All -notmatch 'STILL ALIVE') -and ($ep -ne '0') -and ($elPg -lt 40)
Write-Result $ok ('PG: the session that was open at revocation was terminated (client exited {0}s after revoke, exit {1}; its query would have run 45 s)' -f $elPg, $ep) ('what the open session saw: ' + $lp.All)
$ok = ($lm.All -match 'session open as') -and ($lm.All -match 'Connection was killed|Lost connection|server has gone away|Query execution was interrupted') -and ($lm.All -notmatch 'STILL ALIVE') -and ($em -ne '0') -and ($elMa -lt 40)
Write-Result $ok ('Maria: the session that was open at revocation was terminated (client exited {0}s after revoke, exit {1}; its query would have run 45 s)' -f $elMa, $em) ('what the open session saw: ' + $lm.All)
$a = Get-PgRoleCount $rpg.User; $b = Get-MariaUserCount $rmr.User
Note-Altered ('"gone" for MariaDB is read on {0} (where the user lived); the session above was ended by KILL USER in the revocation statement on the replica itself' -f $maTempHost)
Write-Result (($a -eq '0') -and ($b -eq '0')) 'the database users are gone on both engines' ('pg_roles rows for {0}: {1}; mysql.user rows for {2}: {3}' -f $rpg.User, $a, $rmr.User, $b)
$r = Invoke-PgClient $netAccess ($verify + ' user=' + $rpg.User) 'SELECT 1' $rpg.Password
# The dropped role is no longer a member of debug_ro, so it now hits the final pg_hba reject line.
Assert-Refused 'PG: a new login with the revoked credentials fails' $r ('(pg_hba\.conf rejects connection .*|password authentication failed for )user "' + [regex]::Escape($rpg.User) + '"')
$r = Invoke-MariaClient $netAccess $MariaDevHost $rmr.User 'SELECT 1' $rmr.Password
Assert-Refused 'Maria: a new login with the revoked credentials fails' $r ("Access denied for user '" + [regex]::Escape($rmr.User) + "'")
$r = Invoke-Bao @('token', 'lookup') $rev.Token
Assert-Refused 'the revoked OpenBao token no longer works' $r 'permission denied|bad token'

# =============================================================================================
Write-Host ''
Write-Host '== TTL expiry without manual revoke =='
# The wait is shortened by renewing each lease with a small increment (bao lease renew
# -increment=20s, allowed to alice by the default policy). Roles and TTLs are unchanged.
$exp = Connect-Bao 'alice'
$epg = Get-Creds $exp.Token 'app1-pg-ro'
$emr = Get-Creds $exp.Token 'app1-maria-ro'
$d = @()
foreach ($c in @($epg, $emr)) {
    $r = Invoke-Bao @('lease', 'renew', '-format=json', '-increment=20s', $c.Lease) $exp.Token
    $o = ConvertFrom-JsonOrNull $r.Out
    $d += ('{0}: exit {1}, new lease_duration {2}s' -f $c.User, $r.Code, $o.lease_duration)
}
$ok = ($d -join "`n") -notmatch 'exit [^0]' -and (($d -join "`n") -match 'lease_duration (1\d|20)s')
Write-Result $ok 'alice shortens both leases to 20 s with "bao lease renew -increment=20s"' ($d -join "`n")
$a0 = Get-PgRoleCount $epg.User; $b0 = Get-MariaUserCount $emr.User
Note-Altered ('the MariaDB user rows below are counted on {0}' -f $maTempHost)
$t0 = Get-Date
$deadline = $t0.AddSeconds($ExpiryWaitSeconds)
do {
    Start-Sleep -Seconds 5
    $a = Get-PgRoleCount $epg.User; $b = Get-MariaUserCount $emr.User
} while ((($a -ne '0') -or ($b -ne '0')) -and ((Get-Date) -lt $deadline))
$el = [int]((Get-Date) - $t0).TotalSeconds
$lk = BaoRoot @('lease', 'lookup', $epg.Lease)
Write-Result (($a0 -eq '1') -and ($b0 -eq '1') -and ($a -eq '0') -and ($b -eq '0')) ('after expiry OpenBao removed both users by itself (gone {0}s after renewal; token still valid, no revoke)' -f $el) ('rows before: pg {0}, maria {1}; after: pg {2}, maria {3}; lease lookup now: {4}' -f $a0, $b0, $a, $b, (($lk.All -split "`n" | Select-Object -Last 2) -join ' '))
$r = Invoke-Bao @('token', 'lookup', '-format=json') $exp.Token
Write-Result ($r.Code -eq 0) 'control: alice''s token itself is still valid (the users went because their leases expired)' ('token lookup exit {0}' -f $r.Code)

# =============================================================================================
Write-Host ''
Write-Host '== Persistence: restart openbao, unseal, leases survive =='
$per = Connect-Bao 'alice'
$ppg = Get-Creds $per.Token 'app1-pg-ro'
Write-Host ('       | lease before restart: {0} ({1})' -f $ppg.Lease, $ppg.User)
Wait-DevUsers $ppg.User ''
$r = Invoke-Docker @('compose', '-f', $P2ComposeFile, 'restart', 'openbao') @{} 120
$sealed = $null
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) { $s = Get-BaoStatus; if ($null -ne $s.Obj) { $sealed = $s.Obj.sealed; break }; Start-Sleep -Seconds 2 }
Write-Result ($sealed -eq $true) 'after "docker compose restart openbao" OpenBao is sealed (real seal, not dev mode)' ('restart exit {0}; sealed={1}' -f $r.Code, $sealed)
$unsealOut = ''
try { $unsealOut = (& (Join-Path $P2Root 'scripts\phase2-unseal.ps1') -ComposeFile $P2ComposeFile -Project $P2Project -BaoSecretPrefix $P2BaoSecretPrefix *>&1 | Out-String); $uOk = $true } catch { $unsealOut = $_.Exception.Message; $uOk = $false }
Write-Result $uOk 'scripts\phase2-unseal.ps1 unseals it' $unsealOut
$r = BaoRoot @('lease', 'lookup', '-format=json', $ppg.Lease)
$o = ConvertFrom-JsonOrNull $r.Out
Write-Result (($r.Code -eq 0) -and ($o.data.id -eq $ppg.Lease) -and ($o.data.ttl -gt 0)) 'the lease issued before the restart is still known' ('exit {0}: id={1} ttl={2}s' -f $r.Code, $o.data.id, $o.data.ttl)
$a = Get-PgRoleCount $ppg.User
$r = Invoke-PgClient $netAccess ($verify + ' user=' + $ppg.User) 'SELECT count(*) FROM debug.customers' $ppg.Password
Assert-Works ('its database user still exists (rows {0}) and still works' -f $a) $r '^\d+'
$n2 = Get-Creds $per.Token 'app1-pg-ro'
$n3 = Get-Creds $per.Token 'app1-maria-ro'
Write-Result (($null -ne $n2.User) -and ($null -ne $n3.User)) 'new credentials are issued after the restart (same alice token; rotated bao_admin passwords persisted)' ('pg {0}; maria {1}' -f $n2.User, $n3.User)

# =============================================================================================
# Cleanup: revoke every token this run created (and with it all their leases).
foreach ($tk in $script:Tokens) { [void](Invoke-Bao @('token', 'revoke', '-self') $tk) }
$deadline = (Get-Date).AddSeconds(30)
do {
    Start-Sleep -Seconds 2
    $left = (Invoke-PgAdmin "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-jwt-%'").Out.Trim()
    $leftM = (Invoke-MariaTempAdmin "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'v-jwt-%'").Out.Trim()
} while ((($left -ne '0') -or ($leftM -ne '0')) -and ((Get-Date) -lt $deadline))
Write-Host ''
Write-Host ('cleanup: test tokens revoked; remaining v-jwt-* users: pg {0}, maria {1} (on {2})' -f $left, $leftM, $maTempHost)

Write-Host ''
Write-Host ('Summary: {0} passed, {1} failed' -f $script:Pass, $script:Fail)
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
