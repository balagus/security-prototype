[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://localhost:8080',
    [int]$TimeoutSeconds = 180
)

# Smoke test of the application through nginx (both APIs, read and write), plus a check that no
# database port is reachable from the host.
# Windows PowerShell 5.1 compatible. No &&, ternary or ??.
$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')

$script:Pass = 0
$script:Fail = 0

function Write-Result {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) {
        $script:Pass++
        $tag = 'PASS'
        $color = 'Green'
    } else {
        $script:Fail++
        $tag = 'FAIL'
        $color = 'Red'
    }
    $line = '{0} {1}' -f $tag, $Name
    if ($Detail) { $line = $line + ' - ' + $Detail }
    Write-Host $line -ForegroundColor $color
}

# Returns @{ Status = int; Body = string }. Never throws on non-2xx; Status 0 means no response.
function Invoke-Http {
    param([string]$Method, [string]$Path, [string]$JsonBody)
    $uri = $BaseUrl + $Path
    $result = @{ Status = 0; Body = '' }
    try {
        if ($JsonBody) {
            $r = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method $Method -Body $JsonBody -ContentType 'application/json' -TimeoutSec 30
        } else {
            $r = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method $Method -TimeoutSec 30
        }
        $result.Status = [int]$r.StatusCode
        $result.Body = [string]$r.Content
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -ne $resp) {
            $result.Status = [int]$resp.StatusCode
            try {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $result.Body = $reader.ReadToEnd()
                $reader.Close()
            } catch { }
        }
    } catch {
        $result.Body = $_.Exception.Message
    }
    return $result
}

function ConvertTo-ObjectOrNull {
    param([string]$Text)
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

function Test-HealthBody {
    param([string]$Body)
    $o = ConvertTo-ObjectOrNull $Body
    if ($null -eq $o) { return $false }
    return (($o.status -eq 'ok') -and ($o.db -eq 'ok'))
}

function Test-TcpOpen {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 1500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        try { $client.EndConnect($iar) } catch { return $false }
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

Write-Host ('Smoke test: BaseUrl={0} TimeoutSeconds={1}' -f $BaseUrl, $TimeoutSeconds)

# 1. Wait for both health endpoints (first start runs migrations).
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$dotnetUp = $false
$laravelUp = $false
while ((Get-Date) -lt $deadline) {
    if (-not $dotnetUp) {
        $r = Invoke-Http 'GET' '/dotnet/health'
        if (($r.Status -eq 200) -and (Test-HealthBody $r.Body)) { $dotnetUp = $true }
    }
    if (-not $laravelUp) {
        $r = Invoke-Http 'GET' '/laravel/health'
        if (($r.Status -eq 200) -and (Test-HealthBody $r.Body)) { $laravelUp = $true }
    }
    if ($dotnetUp -and $laravelUp) { break }
    Start-Sleep -Seconds 3
}
Write-Result $dotnetUp 'GET /dotnet/health -> 200 {"status":"ok","db":"ok"}' ''
Write-Result $laravelUp 'GET /laravel/health -> 200 {"status":"ok","db":"ok"}' ''

# 2. Angular app.
$r = Invoke-Http 'GET' '/'
$isHtml = ($r.Status -eq 200) -and ($r.Body -match '(?i)<html')
Write-Result $isHtml 'GET / -> 200 HTML' ('status ' + $r.Status)

# 3. Lists and POST round trip, per backend.
$minCustomers = 3
$minOrders = 4
$stamp = (Get-Date).ToString('yyyyMMddHHmmssfff')

foreach ($b in @('dotnet', 'laravel')) {
    $r = Invoke-Http 'GET' ('/' + $b + '/api/customers')
    $rows = @()
    $o = ConvertTo-ObjectOrNull $r.Body
    if ($null -ne $o) { $rows = @($o) }
    $ok = ($r.Status -eq 200) -and ($rows.Count -ge $minCustomers)
    if ($ok) {
        $first = $rows[0]
        foreach ($f in @('id', 'email', 'full_name', 'created_at')) {
            if (-not ($first.PSObject.Properties.Name -contains $f)) { $ok = $false }
        }
    }
    Write-Result $ok ('GET /' + $b + '/api/customers -> array >= 3 rows with id,email,full_name,created_at') ('status ' + $r.Status + ', rows ' + $rows.Count)

    $r = Invoke-Http 'GET' ('/' + $b + '/api/orders')
    $rows = @()
    $o = ConvertTo-ObjectOrNull $r.Body
    if ($null -ne $o) { $rows = @($o) }
    $ok = ($r.Status -eq 200) -and ($rows.Count -ge $minOrders)
    Write-Result $ok ('GET /' + $b + '/api/orders -> array >= 4 rows') ('status ' + $r.Status + ', rows ' + $rows.Count)

    $email = ('smoke-{0}-{1}@example.test' -f $b, $stamp)
    $name = ('Smoke {0} {1}' -f $b, $stamp)
    $payload = (@{ email = $email; full_name = $name } | ConvertTo-Json -Compress)
    $r = Invoke-Http 'POST' ('/' + $b + '/api/customers') $payload
    $created = ConvertTo-ObjectOrNull $r.Body
    $ok = ($r.Status -eq 201) -and ($null -ne $created) -and ($created.email -eq $email)
    Write-Result $ok ('POST /' + $b + '/api/customers -> 201 and created object') ('status ' + $r.Status)

    $r = Invoke-Http 'GET' ('/' + $b + '/api/customers')
    $found = $false
    $o = ConvertTo-ObjectOrNull $r.Body
    if ($null -ne $o) {
        foreach ($c in @($o)) {
            if ($c.email -eq $email) { $found = $true }
        }
    }
    Write-Result $found ('new customer appears in GET /' + $b + '/api/customers') ('status ' + $r.Status)
}

# 4. Database port exposure.
foreach ($p in @(@{ Name = 'PostgreSQL'; Port = 5432 }, @{ Name = 'MariaDB'; Port = 3306 })) {
    $open = Test-TcpOpen 'localhost' $p.Port
    $label = ('{0} port {1} on localhost' -f $p.Name, $p.Port)
    if ($open) {
        Write-Result $false $label 'open (database ports must never be published)'
    } else {
        Write-Result $true $label 'closed'
    }
}

Write-Host ''
Write-Host ('Summary: {0} passed, {1} failed' -f $script:Pass, $script:Fail)
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
