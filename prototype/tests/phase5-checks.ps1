[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90,
    # How long to wait for a trace or a log line to be queryable after the request.
    [int]$IngestWaitSeconds = 45,
    [string]$ComposeFile = '',
    [string]$Project = 'security-prototype-phase5',
    [string]$BaoSecretPrefix = 'openbao_phase5',
    [string]$BaseUrl = 'http://127.0.0.1:8080',
    [string]$GrafanaUrl = 'http://127.0.0.1:3000'
)

# Phase 5 checks against the RUNNING, configured phase 5 stack (compose.phase5.yaml after
# scripts\phase5-setup.ps1): debug telemetry for reproducing bugs.
#   1. one request gives one trace across API -> SQL, with trace-correlated logs
#   2. browser telemetry (Faro) is accepted through nginx only with the API key
#   3. redaction: a customer created with sentinel values appears in no trace and no log line;
#      SQL is parameterized; e-mail addresses in browser logs are masked
#   4. isolation: telemetry is separate from the audit trail (mounts, networks, ports) and the
#      stores are unreachable from the apps and from the host
#   5. Grafana: Keycloak sign-in only; app1-devs -> Viewer with Explore; others refused
# smoke.ps1 and phase4-checks.ps1 (with the phase 5 parameters) are run separately.
# Queries to Loki and Tempo go through a throwaway curl container on telemetry-store (neither
# has a published port). Test passwords come from the LAB-ONLY realm seed file and reach the
# curl container as environment variables only. Windows PowerShell 5.1 compatible.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.phase5.yaml' }
$P2ComposeFile = $ComposeFile
$P2Project = $Project
$P2BaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $root 'scripts\phase2-lib.ps1')

$curlImage = 'curlimages/curl:8.22.0'
$netStore = $P2Project + '_telemetry-store'
$netLab = $P2Project + '_lab'
$realmFile = Join-Path $P2Root 'config\keycloak\phase5\lab-realm.json'
$realm = [System.IO.File]::ReadAllText($realmFile, $P2Utf8NoBom) | ConvertFrom-Json

$script:Pass = 0
$script:Fail = 0

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
function Note { param([string]$Text) Write-Host ('       | ' + $Text) }
function Get-TestPassword { param([string]$User) return [string](($realm.users | Where-Object { $_.username -eq $User }).credentials[0].value) }
function New-Hex { param([int]$Bytes) $b = New-Object byte[] $Bytes; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b); return (($b | ForEach-Object { $_.ToString('x2') }) -join '') }
function Short { param([string]$T, [int]$N = 300) if (-not $T) { return '' }; if ($T.Length -le $N) { return $T }; return $T.Substring(0, $N) + '...' }

# curl inside telemetry-store (Loki, Tempo).
function Invoke-StoreCurl { param([string[]]$A, [int]$Timeout = 60) Invoke-Docker (@('run', '--rm', '--network', $netStore, $curlImage) + $A) @{} $Timeout }

# Polls Tempo for a trace until its raw JSON matches every pattern in $Need (or the wait ends).
function Get-Trace {
    param([string]$TraceId, [string[]]$Need = @(), [int]$Wait = $IngestWaitSeconds)
    $deadline = (Get-Date).AddSeconds($Wait)
    $body = ''
    do {
        $r = Invoke-StoreCurl @('-s', '-m', '10', '-H', 'Accept: application/json', ('http://tempo:3200/api/traces/' + $TraceId))
        if ($r.Code -eq 0 -and $r.Out.Trim().StartsWith('{')) {
            $body = $r.Out
            $all = $true
            foreach ($p in $Need) { if ($body -notmatch $p) { $all = $false } }
            if ($all) { return $body }
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $body
}

# LogQL range query over the last $Minutes; returns @{ Lines = log lines; Raw = response }.
function Search-Loki {
    param([string]$Query, [int]$Minutes = 60, [int]$Limit = 500)
    $start = [string](([DateTimeOffset]::UtcNow.AddMinutes(-$Minutes).ToUnixTimeMilliseconds()) * 1000000)
    $r = Invoke-StoreCurl @('-s', '-m', '20', '-G', 'http://loki:3100/loki/api/v1/query_range',
        '--data-urlencode', ('query=' + $Query), '--data-urlencode', ('start=' + $start),
        '--data-urlencode', ('limit=' + $Limit), '--data-urlencode', 'direction=backward')
    $lines = @()
    $o = ConvertFrom-JsonOrNull $r.Out
    if ($null -ne $o -and $o.status -eq 'success') {
        foreach ($s in $o.data.result) { foreach ($v in $s.values) { $lines += [string]$v[1] } }
    }
    return @{ Lines = $lines; Raw = $r.All; Ok = ($null -ne $o -and $o.status -eq 'success') }
}
function Wait-Loki {
    param([string]$Query, [int]$Wait = $IngestWaitSeconds)
    $deadline = (Get-Date).AddSeconds($Wait)
    do {
        $x = Search-Loki $Query
        if ($x.Lines.Count -gt 0) { return $x }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $x
}

function Invoke-App {
    param([string]$Method, [string]$Path, [string]$TraceId, [string]$Json = '')
    $h = @{ traceparent = ('00-{0}-{1}-01' -f $TraceId, (New-Hex 8)) }
    try {
        if ($Json) { $resp = Invoke-WebRequest -UseBasicParsing -Method $Method -Uri ($BaseUrl + $Path) -Headers $h -ContentType 'application/json' -Body $Json -TimeoutSec 30 }
        else { $resp = Invoke-WebRequest -UseBasicParsing -Method $Method -Uri ($BaseUrl + $Path) -Headers $h -TimeoutSec 30 }
        return [int]$resp.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return -1
    }
}

function Test-HostPort {
    param([int]$Port)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(1500)) { return $false }
        $c.EndConnect($iar)
        return $c.Connected
    } catch { return $false } finally { $c.Close() }
}

Write-Host ('Phase 5 checks: compose file {0}, project {1}' -f $P2ComposeFile, $P2Project)
$ids = @{}
foreach ($s in @('alloy', 'loki', 'tempo', 'grafana', 'dotnet-api', 'laravel-api', 'web', 'fluent-bit', 'keycloak')) { $ids[$s] = Get-P2ContainerId $s }

# =============================================================================================
Write-Host ''
Write-Host '== 1. One request, one trace: API -> SQL, with correlated logs'
$tD = New-Hex 16
$code = Invoke-App 'GET' '/dotnet/api/customers' $tD
$svcD = '"key":"service.name","value":\{"stringValue":"dotnet-api"\}'
$dbPg = '"key":"db\.system(\.name)?","value":\{"stringValue":"postgresql"\}'
$trD = Get-Trace $tD @($svcD, $dbPg)
Write-Result (($code -eq 200) -and ($trD -match $svcD) -and ($trD -match $dbPg)) 'dotnet: GET /dotnet/api/customers with a traceparent -> Tempo has that trace with a dotnet-api span and a PostgreSQL span' ('HTTP {0}; trace {1}; {2} bytes' -f $code, $tD, $trD.Length)
$lgD = Wait-Loki ('{service_name="dotnet-api"} | trace_id="' + $tD + '"')
Write-Result ($lgD.Lines.Count -gt 0) 'dotnet: Loki has log lines carrying the same trace_id' ('{0} line(s); first: {1}' -f $lgD.Lines.Count, (Short ($lgD.Lines | Select-Object -First 1)))

$tL = New-Hex 16
$code = Invoke-App 'GET' '/laravel/api/orders' $tL
$svcL = '"key":"service.name","value":\{"stringValue":"laravel-api"\}'
$dbMy = '"key":"db\.system(\.name)?","value":\{"stringValue":"(mysql|mariadb)"\}'
$trL = Get-Trace $tL @($svcL, $dbMy)
Write-Result (($code -eq 200) -and ($trL -match $svcL) -and ($trL -match $dbMy)) 'laravel: GET /laravel/api/orders with a traceparent -> Tempo has that trace with a laravel-api span and a MariaDB span' ('HTTP {0}; trace {1}; {2} bytes' -f $code, $tL, $trL.Length)
$lgL = Wait-Loki ('{service_name="laravel-api"} | trace_id="' + $tL + '"')
Write-Result ($lgL.Lines.Count -gt 0) 'laravel: Loki has log lines carrying the same trace_id' ('{0} line(s); first: {1}' -f $lgL.Lines.Count, (Short ($lgL.Lines | Select-Object -First 1)))

# =============================================================================================
Write-Host ''
Write-Host '== 2. Browser telemetry (Faro) through nginx'
$faroKey = 'lab-faro-app1-web'
$rid = New-Hex 6
$faroEmail = ('p5faro-{0}@sentinel.test' -f $rid)
$ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$faroBody = ('{{"meta":{{"app":{{"name":"web","environment":"lab"}}}},"logs":[{{"message":"phase5-check {0} contact {1}","level":"info","context":{{}},"timestamp":"{2}"}}]}}' -f $rid, $faroEmail, $ts)
function Send-Faro {
    param([string]$Key)
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($BaseUrl + '/faro/collect') -Headers @{ 'x-api-key' = $Key } -ContentType 'application/json' -Body $faroBody -TimeoutSec 15
        return [int]$r.StatusCode
    } catch { if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }; return -1 }
}
$bad = Send-Faro 'wrong-key'
Write-Result (($bad -ge 400) -and ($bad -lt 500)) 'Faro: a payload with a wrong API key is refused' ('HTTP {0}' -f $bad)
$good = Send-Faro $faroKey
Write-Result (($good -ge 200) -and ($good -lt 300)) 'Faro: a payload with the app''s API key is accepted (POST /faro/collect, same origin)' ('HTTP {0}' -f $good)
$fl = Wait-Loki ('{service_name="web"} |= "phase5-check ' + $rid + '"')
$flText = ($fl.Lines -join "`n")
Write-Result (($fl.Lines.Count -gt 0) -and ($flText -notmatch [regex]::Escape($faroEmail)) -and ($flText -match '<email>')) 'Faro: the browser log line reached Loki with the e-mail address masked' (Short $flText 400)

# =============================================================================================
Write-Host ''
Write-Host '== 3. Redaction: sentinel customer data appears in no trace and no log line'
$sid = New-Hex 6
$sEmail = ('p5-{0}@sentinel.test' -f $sid)
$sName = ('P5Sentinel{0}' -f $sid)
$json = ('{{"email":"{0}","full_name":"{1}"}}' -f $sEmail, $sName)
$tPD = New-Hex 16
$cD = Invoke-App 'POST' '/dotnet/api/customers' $tPD $json
$tPL = New-Hex 16
$cL = Invoke-App 'POST' '/laravel/api/customers' $tPL $json
Note ('created sentinel customer via dotnet (HTTP {0}, trace {1}) and laravel (HTTP {2}, trace {3})' -f $cD, $tPD, $cL, $tPL)
$insert = '(?i)insert into'
$trPD = Get-Trace $tPD @($svcD, $insert)
$trPL = Get-Trace $tPL @($svcL, $insert)
foreach ($c in @(@{ N = 'dotnet'; T = $trPD; Code = $cD }, @{ N = 'laravel'; T = $trPL; Code = $cL })) {
    $leak = ($c.T -match [regex]::Escape($sid))
    Write-Result ((($c.Code -eq 200) -or ($c.Code -eq 201)) -and ($c.T -match $insert) -and (-not $leak)) ('{0}: the INSERT trace contains neither the sentinel e-mail nor the sentinel name' -f $c.N) ('HTTP {0}; trace {1} bytes; sentinel id found: {2}' -f $c.Code, $c.T.Length, $leak)
    $stm = ([regex]::Matches($c.T, '"key":"db\.(statement|query\.text)","value":\{"stringValue":"((?:[^"\\]|\\.)*)"\}') | ForEach-Object { $_.Groups[2].Value } | Where-Object { $_ -match $insert } | Select-Object -First 1)
    Write-Result (($null -ne $stm) -and ($stm -match '(\$\d|@p\d|\?)')) ('{0}: the SQL text recorded for the INSERT is parameterized (placeholders, no values)' -f $c.N) (Short ([string]$stm) 300)
}
Start-Sleep -Seconds 5
$ls = Search-Loki ('{deployment_environment=~".+"} |= "' + $sid + '"') 90
$ls2 = Search-Loki ('{service_name=~".+"} |= "' + $sid + '"') 90
Write-Result ($ls.Ok -and $ls2.Ok -and ($ls.Lines.Count -eq 0) -and ($ls2.Lines.Count -eq 0)) 'Loki: no log line of any service contains the sentinel e-mail or name' ('matches: {0} / {1}' -f $ls.Lines.Count, $ls2.Lines.Count)

# =============================================================================================
Write-Host ''
Write-Host '== 4. Isolation: telemetry is not the audit trail'
$auditVols = @('pg-primary-log', 'pg-replica-log', 'maria-primary-audit', 'maria-replica-audit', 'pg-sweeper-log', 'maria-sweeper-log', 'bao-audit', 'reconciler-log', 'log-store', 'fluent-bit-state', 'pg-deny') | ForEach-Object { $P2Project + '_' + $_ }
$telemetrySvc = @('alloy', 'loki', 'tempo', 'grafana', 'telemetry-init')
$all = @((Invoke-Docker @('compose', '-f', $P2ComposeFile, 'ps', '-a', '--format', '{{.Service}} {{.ID}}')).Out -split "`r?`n" | Where-Object { $_.Trim() })
$storeMounters = @()
$telemetryAuditMounts = @()
$hard = @()
foreach ($line in $all) {
    $svc, $cid = $line.Trim() -split '\s+', 2
    $i = (Invoke-Docker @('inspect', '-f', '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}|{{.HostConfig.NetworkMode}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.CapDrop}}', $cid)).Out.Trim()
    $vols, $netMode, $user, $ro, $capDrop = $i -split '\|'
    $vl = @($vols -split ' ' | Where-Object { $_ })
    if ($vl -contains ($P2Project + '_log-store')) { $storeMounters += $svc }
    if ($telemetrySvc -contains $svc) {
        foreach ($v in $vl) { if ($auditVols -contains $v) { $telemetryAuditMounts += ('{0}:{1}' -f $svc, $v) } }
        if (@('alloy', 'loki', 'tempo', 'grafana') -contains $svc) { $hard += ('{0}: user={1} read_only={2} cap_drop={3}' -f $svc, $(if ($user) { $user } else { '(image default)' }), $ro, $capDrop) }
    }
    if ($svc -eq 'fluent-bit') { $fbNet = $netMode }
}
$storeMounters = @($storeMounters | Sort-Object -Unique)
Write-Result ($telemetryAuditMounts.Count -eq 0) 'no telemetry container (alloy, loki, tempo, grafana, telemetry-init) mounts an audit or log-store volume' ($(if ($telemetryAuditMounts.Count) { $telemetryAuditMounts -join ', ' } else { 'none' }))
Write-Result ((($storeMounters -join ',') -eq 'fluent-bit,log-init') -and ($fbNet -eq 'none')) 'log-store is still mounted only by fluent-bit (and the one-shot log-init); fluent-bit still has no network' ('mounted by: {0}; fluent-bit network: {1}' -f ($storeMounters -join ', '), $fbNet)
$hardOk = $true
foreach ($h in $hard) { if (($h -notmatch 'read_only=true') -or ($h -notmatch 'cap_drop=\[ALL\]') -or ($h -match 'user=(0|root)(:|\s)')) { $hardOk = $false } }
Write-Result ($hardOk -and $hard.Count -eq 4) 'telemetry services run read-only, with all capabilities dropped, not as root' ($hard -join "`n")

# The stores are unreachable from the apps (they are only on "telemetry", alloy's side).
$fromLaravel = Invoke-Docker @('exec', $ids['laravel-api'], 'php', '-r', 'foreach ([["loki",3100],["tempo",3200],["grafana",3000],["alloy",4318]] as $t) { $s = @fsockopen($t[0], $t[1], $e, $m, 3); echo $t[0], ":", $t[1], "=", ($s ? "open" : "closed"), " "; }')
Write-Result (($fromLaravel.Out -match 'loki:3100=closed') -and ($fromLaravel.Out -match 'tempo:3200=closed') -and ($fromLaravel.Out -match 'grafana:3000=closed') -and ($fromLaravel.Out -match 'alloy:4318=open')) 'from laravel-api: alloy is reachable, Loki, Tempo and Grafana are not' $fromLaravel.All
$fromDotnet = Invoke-Docker @('exec', $ids['dotnet-api'], 'bash', '-c', 'for t in loki:3100 tempo:3200 grafana:3000 alloy:4317; do h=${t%:*}; p=${t#*:}; if timeout 3 bash -c "</dev/tcp/$h/$p" 2>/dev/null; then echo -n "$t=open "; else echo -n "$t=closed "; fi; done')
Write-Result (($fromDotnet.Out -match 'loki:3100=closed') -and ($fromDotnet.Out -match 'tempo:3200=closed') -and ($fromDotnet.Out -match 'grafana:3000=closed') -and ($fromDotnet.Out -match 'alloy:4317=open')) 'from dotnet-api: alloy is reachable, Loki, Tempo and Grafana are not' $fromDotnet.All

# Host: Grafana on loopback is the only new port; the pipeline ports are closed.
$closed = @(4317, 4318, 12345, 12347, 3100, 3200, 9095, 9096)
$open = @()
foreach ($p in $closed) { if (Test-HostPort $p) { $open += $p } }
$gOpen = Test-HostPort 3000
$pub = @()
foreach ($s in @('alloy', 'loki', 'tempo', 'grafana')) {
    $pp = (Invoke-Docker @('port', $ids[$s])).Out.Trim()
    if ($pp) { $pub += ('{0}: {1}' -f $s, ($pp -replace "`r?`n", ', ')) }
}
Write-Result (($open.Count -eq 0) -and $gOpen -and ($pub.Count -eq 1) -and ($pub[0] -match '^grafana: 3000/tcp -> 127\.0\.0\.1:3000$')) 'host: only Grafana is published (127.0.0.1:3000); OTLP, Faro, Alloy UI, Loki and Tempo ports are closed' ('published: {0}; open among {1}: {2}' -f ($pub -join '; '), ($closed -join ','), $(if ($open.Count) { $open -join ',' } else { 'none' }))

# No audit material in Loki (temp users, pgAudit, server_audit, OpenBao audit).
$au = Search-Loki '{service_name=~".+"} |~ "(v-jwt-|v-oidc-|AUDIT: SESSION|server_audit|auth/jwt/login|database/creds/)"' 1440
Write-Result ($au.Ok -and ($au.Lines.Count -eq 0)) 'Loki holds no audit material (no temp usernames, pgAudit, server_audit or OpenBao audit records)' ('matches: {0}' -f $au.Lines.Count)

# =============================================================================================
Write-Host ''
Write-Host '== 5. Grafana: Keycloak sign-in only'
try { $r = Invoke-WebRequest -UseBasicParsing -Uri ($GrafanaUrl + '/api/search') -TimeoutSec 10; $anon = [int]$r.StatusCode } catch { $anon = $(if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }) }
Write-Result ($anon -eq 401) 'anonymous: /api/search is refused' ('HTTP {0}' -f $anon)
$adminPw = Read-P2Secret 'grafana_admin_password'
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('lab-admin:' + $adminPw))
try { $r = Invoke-WebRequest -UseBasicParsing -Uri ($GrafanaUrl + '/api/user') -Headers @{ Authorization = ('Basic ' + $b64) } -TimeoutSec 10; $basic = [int]$r.StatusCode } catch { $basic = $(if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }) }
Write-Result ($basic -eq 401) 'the local admin cannot sign in over HTTP (basic auth off)' ('HTTP {0}' -f $basic)
try { $r = Invoke-WebRequest -UseBasicParsing -Uri ($GrafanaUrl + '/login') -MaximumRedirection 0 -TimeoutSec 10 -ErrorAction SilentlyContinue; $lc = [int]$r.StatusCode; $loc = [string]$r.Headers['Location'] } catch { $lc = $(if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }); $loc = $(if ($_.Exception.Response) { [string]$_.Exception.Response.Headers['Location'] } else { '' }) }
Write-Result ((($lc -eq 302) -or ($lc -eq 307)) -and ($loc -match 'login/generic_oauth')) '/login sends the browser straight to Keycloak (no login form)' ('HTTP {0} -> {1}' -f $lc, $loc)
$envDump = (Invoke-Docker @('inspect', '-f', '{{range .Config.Env}}{{println .}}{{end}}', $ids['grafana'])).Out
$cs = Read-P2Secret 'keycloak_grafana_client_secret'
Write-Result (($envDump -notmatch [regex]::Escape($adminPw)) -and ($envDump -notmatch [regex]::Escape($cs))) 'the Grafana admin password and Keycloak client secret are not in the container environment (Docker secrets, __FILE)' ''

# Authorization-code flow (PKCE) in a throwaway curl container on "lab", where keycloak.localhost
# is a network alias and Grafana is grafana:3000. The redirect to the browser-facing
# http://localhost:3000 callback is rewritten to grafana:3000.
# Cookies are carried by hand (read from Set-Cookie, sent as a Cookie header), not with a curl
# cookie jar: curl drops the Secure cookies Keycloak sets over plain HTTP (browsers keep them on
# *.localhost, a secure context), and it does not send jar cookies back to the single-label
# host "grafana" (both measured).
$oidc = @'
set -eu
G=http://grafana:3000
# curl resolves every *.localhost name to loopback itself (it never asks Docker's DNS), so
# keycloak.localhost is sent to the keycloak service explicitly. Grafana (Go) uses Docker DNS.
curl() { command curl --connect-to keycloak.localhost:8180:keycloak:8180 "$@"; }
# name=value pairs of every Set-Cookie in a header file, as one Cookie header value.
cookies() { grep -i '^set-cookie:' "$1" | sed -e 's/^[^:]*: *//' -e 's/;.*//' | tr -d '\r' | grep -v '=$' | paste -sd ';' - | sed 's/;/; /g'; }
loc=$(curl -s -m 15 -D /tmp/g1 -o /dev/null -w '%{redirect_url}' "$G/login/generic_oauth")
gc=$(cookies /tmp/g1)
echo "STEP1=${loc%%\?*}"
page=$(curl -s -m 15 -D /tmp/k1 "$loc")
kc=$(cookies /tmp/k1)
action=$(printf '%s' "$page" | tr '\n' ' ' | grep -o 'action="[^"]*login-actions/authenticate[^"]*"' | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')
[ -n "$action" ] || { echo "NO_LOGIN_FORM"; exit 3; }
cb=$(curl -s -m 15 -H "Cookie: $kc" -o /dev/null -w '%{redirect_url}' --data-urlencode "username=$U" --data-urlencode "password=$PW" "$action")
echo "STEP2=${cb%%\?*}"
case "$cb" in http://localhost:3000/login/generic_oauth*) ;; *) echo "NO_CALLBACK"; exit 4;; esac
res=$(curl -s -m 30 -H "Cookie: $gc" -D /tmp/g2 -o /dev/null -w '%{http_code} %{redirect_url}' "$G${cb#http://localhost:3000}")
echo "STEP3=$res"
sc=$(cookies /tmp/g2)
echo "USER=$(curl -s -m 10 -H "Cookie: $sc" $G/api/user)"
echo "ORGS=$(curl -s -m 10 -H "Cookie: $sc" $G/api/user/orgs)"
echo "ACTIONS=$(curl -s -m 10 -H "Cookie: $sc" $G/api/access-control/user/actions)"
echo "TEMPO=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -H "Cookie: $sc" $G/api/datasources/proxy/uid/tempo/api/traces/$T)"
echo "LOKI=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -H "Cookie: $sc" $G/api/datasources/proxy/uid/loki/loki/api/v1/labels)"
'@
function Invoke-GrafanaLogin {
    param([string]$User)
    $envs = @{ U = $User; PW = (Get-TestPassword $User); T = $tD }
    $a = @('run', '--rm', '--network', $netLab, '-e', 'U', '-e', 'PW', '-e', 'T', '--entrypoint', 'sh', $curlImage, '-c', $oidc)
    $r = Invoke-Docker $a $envs 120
    $kv = @{}
    foreach ($l in ($r.Out -split "`r?`n")) { if ($l -match '^([A-Z0-9]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] } }
    return @{ R = $r; KV = $kv }
}
$al = Invoke-GrafanaLogin 'alice'
$kv = $al.KV
$aliceOk = ([string]$kv['USER'] -match '"login":"alice"') -and ([string]$kv['ORGS'] -match '"role":"Viewer"')
Write-Result $aliceOk 'alice (app1-devs) signs in through Keycloak and gets the Viewer role' ((@('STEP1', 'STEP2', 'STEP3', 'ORGS') | ForEach-Object { '{0}={1}' -f $_, (Short ([string]$kv[$_]) 160) }) -join "`n")
Write-Result (([string]$kv['ACTIONS'] -match '"datasources:explore"') -and ($kv['TEMPO'] -eq '200') -and ($kv['LOKI'] -eq '200')) 'alice can use Explore and query Tempo (the dotnet trace from check 1) and Loki through Grafana' ('explore: {0}; tempo HTTP {1}; loki HTTP {2}' -f ([string]$kv['ACTIONS'] -match '"datasources:explore"'), $kv['TEMPO'], $kv['LOKI'])
Write-Result (([string]$kv['ACTIONS'] -match '"datasources:query"') -and -not ([string]$kv['ACTIONS'] -match '"(datasources:write|users:create|org\.users:add|dashboards:create)"')) 'alice cannot change data sources, users or dashboards' ''
$bl = Invoke-GrafanaLogin 'bob'
$kv = $bl.KV
$bobIn = ([string]$kv['USER'] -match '"login":"bob"')
Write-Result (([string]$kv['STEP2'] -eq 'http://localhost:3000/login/generic_oauth') -and (-not $bobIn) -and ($kv['TEMPO'] -ne '200') -and ($kv['LOKI'] -ne '200')) 'bob (not in app1-devs) authenticates at Keycloak but Grafana refuses him (role_attribute_strict); no data access' ((@('STEP2', 'STEP3', 'USER', 'TEMPO', 'LOKI') | ForEach-Object { '{0}={1}' -f $_, (Short ([string]$kv[$_]) 160) }) -join "`n")

# =============================================================================================
Write-Host ''
Write-Host ('Summary: {0} passed, {1} failed' -f $script:Pass, $script:Fail)
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
