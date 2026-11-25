[CmdletBinding()]
param(
    # Compose file of the stack under test. Default: compose.yaml.
    [string]$ComposeFile = '',
    # Compose project name of that stack (the "name:" in the file). It prefixes network,
    # volume and image names. Default: security-prototype.
    [string]$Project = 'security-prototype',
    [int]$TimeoutSeconds = 60
)

# Application and database hardening checks (docs/DECISIONS.md D2, D3) against the RUNNING
# stack: network isolation, database privileges, TLS, superuser lockdown, secrets, migrations.
# Windows PowerShell 5.1 compatible. One PASS/FAIL line per check; exit 0 only if all pass.
#
# Every negative check must fail for the RIGHT reason: its error text must match the pattern
# of the control being tested (for example "pg_hba.conf rejects connection"), otherwise the
# check FAILS. A typo, a wrong password or a missing tool therefore cannot produce a PASS.
# The actual error text is printed on the line below each check.
#
# Tools used per container:
#   laravel-api : php (fsockopen)
#   dotnet-api  : bash /dev/tcp with coreutils timeout
#   web         : busybox wget (busybox nc -z prints no error text, so wget is used instead)
#   PostgreSQL  : psql in a throwaway postgres:17 container on the app1-pg network
#   MariaDB     : mariadb client in a throwaway mariadb:11.8 container on the app1-maria network
# Passwords reach throwaway containers only as environment variables of the docker CLI
# process (docker run -e NAME), never on a command line.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
if (-not $ComposeFile) { $ComposeFile = Join-Path $root 'compose.yaml' }
$secretsDir = Join-Path $root 'secrets'
$project = $Project
$netPg = $project + '_app1-pg'
$netMaria = $project + '_app1-maria'
$volCa = $project + '_pki-ca'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Docker is not always on PATH on this host.
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $dd = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin'
    if (Test-Path (Join-Path $dd 'docker.exe')) { $env:Path = $dd + ';' + $env:Path }
}
$dockerExe = (Get-Command docker).Source

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

# Windows command-line quoting for one argument (MSVCRT rules).
function ConvertTo-CmdArg {
    param([string]$Arg)
    if ($Arg -ne '' -and $Arg -notmatch '[\s"]') { return $Arg }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bs = 0
    foreach ($ch in $Arg.ToCharArray()) {
        if ($ch -eq '\') { $bs++; continue }
        if ($ch -eq '"') { [void]$sb.Append('\' * (2 * $bs + 1)); [void]$sb.Append('"'); $bs = 0; continue }
        if ($bs -gt 0) { [void]$sb.Append('\' * $bs); $bs = 0 }
        [void]$sb.Append($ch)
    }
    if ($bs -gt 0) { [void]$sb.Append('\' * (2 * $bs)) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# Runs docker with the given arguments and extra environment variables for the docker CLI
# process. Never throws. Returns @{ Code; Out; Err; All }.
# Scripts are passed as arguments (sh -c), not on stdin: Windows PowerShell 5.1 prepends a
# UTF-8 BOM to redirected stdin, which breaks the first command of a script.
function Invoke-Docker {
    param([string[]]$DockerArgs, [hashtable]$Env = @{})
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $dockerExe
    $psi.Arguments = (($DockerArgs | ForEach-Object { ConvertTo-CmdArg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $utf8NoBom
    $psi.StandardErrorEncoding = $utf8NoBom
    $psi.CreateNoWindow = $true
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try {
        [void]$p.Start()
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            try { $p.Kill() } catch { }
            return @{ Code = -1; Out = ''; Err = ('timed out after {0}s' -f $TimeoutSeconds); All = ('timed out after {0}s' -f $TimeoutSeconds) }
        }
        $p.WaitForExit()
        $out = $outTask.Result
        $err = $errTask.Result
        return @{ Code = $p.ExitCode; Out = $out; Err = $err; All = (($out + "`n" + $err).Trim()) }
    } catch {
        return @{ Code = -2; Out = ''; Err = $_.Exception.Message; All = $_.Exception.Message }
    } finally {
        $p.Dispose()
    }
}

function Read-SecretFile {
    param([string]$Name)
    return [System.IO.File]::ReadAllText((Join-Path $secretsDir $Name), $utf8NoBom)
}

function Get-ContainerId {
    param([string]$Service)
    $r = Invoke-Docker @('compose', '-f', $ComposeFile, 'ps', '-a', '-q', $Service)
    $id = ($r.Out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $id) { throw ('No container for service {0}. Is the stack running?' -f $Service) }
    return $id.Trim()
}

function Get-ContainerIp {
    param([string]$Id, [string]$Network)
    $r = Invoke-Docker @('inspect', '-f', ('{{(index .NetworkSettings.Networks "' + $Network + '").IPAddress}}'), $Id)
    return $r.Out.Trim()
}

# A negative check: the command must fail AND its output must match the expected control's error.
function Assert-Refused {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -ne 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, $Result.All)
    if (-not $ok) { $detail = $detail + ("`n(expected a failure matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}

# A positive check: the command must succeed and its output must match.
function Assert-Works {
    param([string]$Name, $Result, [string]$Pattern)
    $ok = ($Result.Code -eq 0) -and ($Result.All -match $Pattern)
    $detail = ('exit {0}: {1}' -f $Result.Code, $Result.All)
    if (-not $ok) { $detail = $detail + ("`n(expected success matching /{0}/)" -f $Pattern) }
    Write-Result $ok $Name $detail
}

Write-Host ('Hardening checks: compose file {0}, project {1}' -f $ComposeFile, $project)

$ids = @{}
foreach ($s in @('pg-primary', 'maria-primary', 'dotnet-api', 'laravel-api', 'web', 'dotnet-migrate', 'laravel-migrate')) {
    $ids[$s] = Get-ContainerId $s
}
$pgIp = Get-ContainerIp $ids['pg-primary'] $netPg
$mariaIp = Get-ContainerIp $ids['maria-primary'] $netMaria
Write-Host ('pg-primary {0} on {1}; maria-primary {2} on {3}' -f $pgIp, $netPg, $mariaIp, $netMaria)

# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '== Network isolation =='

$phpProbe = @'
[$h, $p] = [$argv[1], (int)$argv[2]];
$s = @fsockopen($h, $p, $errno, $errstr, 4);
if ($s) { fclose($s); echo "connected to $h:$p\n"; exit(0); }
$e = error_get_last();
fwrite(STDERR, "php fsockopen $h:$p failed: [$errno] $errstr" . ($e ? " (" . $e["message"] . ")" : "") . "\n");
exit(1);
'@
function Test-FromLaravel { param([string]$H, [int]$P) Invoke-Docker @('exec', $ids['laravel-api'], 'php', '-r', $phpProbe, '--', $H, [string]$P) }

$bashProbe = 'timeout 5 bash -c ''exec 3<>"/dev/tcp/$0/$1"'' "$1" "$2" && echo "bash /dev/tcp connected to $1:$2"'
function Test-FromDotnet { param([string]$H, [int]$P) Invoke-Docker @('exec', $ids['dotnet-api'], 'bash', '-c', $bashProbe, 'probe', $H, [string]$P) }

$wgetProbe = 'wget -q -T 4 -O /dev/null "http://$1:$2$3" && echo "busybox wget got an HTTP response from $1:$2$3"'
function Test-FromWeb { param([string]$H, [int]$P, [string]$Path = '/') Invoke-Docker @('exec', $ids['web'], 'sh', '-c', $wgetProbe, 'probe', $H, [string]$P, $Path) }

$noName = 'getaddrinfo|Name or service not known|Temporary failure in name resolution|bad address'
$noRoute = 'Network is unreachable|timed out|No route to host'

# Positive controls: the same tool reaches what it should, so a refusal below is not a broken tool.
Assert-Works 'control: laravel-api (php) reaches maria-primary:3306' (Test-FromLaravel 'maria-primary' 3306) 'connected'
Assert-Works 'control: dotnet-api (bash /dev/tcp) reaches pg-primary:5432' (Test-FromDotnet 'pg-primary' 5432) 'connected'
Assert-Works 'control: web (busybox wget) reaches dotnet-api:8080' (Test-FromWeb 'dotnet-api' 8080 '/health') 'HTTP response'

Assert-Refused 'laravel-api cannot reach pg-primary:5432 (by name)' (Test-FromLaravel 'pg-primary' 5432) $noName
Assert-Refused ('laravel-api cannot reach pg-primary:5432 (by IP {0})' -f $pgIp) (Test-FromLaravel $pgIp 5432) $noRoute
Assert-Refused 'dotnet-api cannot reach maria-primary:3306 (by name)' (Test-FromDotnet 'maria-primary' 3306) $noName
Assert-Refused ('dotnet-api cannot reach maria-primary:3306 (by IP {0})' -f $mariaIp) (Test-FromDotnet $mariaIp 3306) $noRoute
Assert-Refused 'web cannot reach pg-primary:5432 (by name)' (Test-FromWeb 'pg-primary' 5432) $noName
Assert-Refused ('web cannot reach pg-primary:5432 (by IP {0})' -f $pgIp) (Test-FromWeb $pgIp 5432) $noRoute
Assert-Refused 'web cannot reach maria-primary:3306 (by name)' (Test-FromWeb 'maria-primary' 3306) $noName
Assert-Refused ('web cannot reach maria-primary:3306 (by IP {0})' -f $mariaIp) (Test-FromWeb $mariaIp 3306) $noRoute

# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '== PostgreSQL (client: throwaway postgres:17 container on the app1-pg network) =='

$pgRuntimePw = Read-SecretFile 'pg_app1_runtime_password'
$pgSuperPw = Read-SecretFile 'pg_superuser_password'

function Invoke-PgClient {
    param([string]$ConnInfo, [string]$Sql, [string]$Password)
    return Invoke-Docker @('run', '--rm', '--network', $netPg, '-v', ($volCa + ':/ca:ro'), '-e', 'PGPASSWORD',
        '--entrypoint', 'psql', 'postgres:17', $ConnInfo, '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', $Sql) @{ PGPASSWORD = $Password }
}
# psql over the local socket inside pg-primary as OS user postgres (peer auth): admin-side facts.
function Invoke-PgAdmin {
    param([string]$Sql)
    return Invoke-Docker @('exec', '-u', 'postgres', $ids['pg-primary'], 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', 'app1', '-c', $Sql)
}

$verify = 'sslmode=verify-full sslrootcert=/ca/ca.crt'
$r = Invoke-PgClient ('host=pg-primary dbname=app1 user=app1_runtime ' + $verify) `
    "SELECT 'user=' || current_user || ' ssl=' || s.ssl || ' ' || s.version || ' customers=' || (SELECT count(*) FROM customers) FROM pg_stat_ssl s WHERE s.pid = pg_backend_pid()" $pgRuntimePw
Assert-Works 'PG: app1_runtime TLS with verify-full succeeds and can SELECT' $r 'user=app1_runtime ssl=true TLSv1\.[23] customers=\d+'

$r = Invoke-PgClient ('host=pg-primary dbname=app1 user=app1_runtime ' + $verify) 'CREATE TABLE p1_probe (id int)' $pgRuntimePw
Assert-Refused 'PG: app1_runtime cannot CREATE TABLE' $r 'permission denied for schema public'

$r = Invoke-PgClient ('host=pg-primary dbname=postgres user=app1_runtime ' + $verify) 'SELECT 1' $pgRuntimePw
$ok = ($r.Code -ne 0) -and ($r.All -match 'pg_hba\.conf rejects connection .*user "app1_runtime", database "postgres"')
$priv = Invoke-PgAdmin "SELECT 'has_database_privilege(app1_runtime, postgres, CONNECT)=' || has_database_privilege('app1_runtime', 'postgres', 'CONNECT')"
$ok = $ok -and ($priv.Code -eq 0) -and ($priv.Out -match '=f')
Write-Result $ok 'PG: app1_runtime cannot connect to database postgres (pg_hba reject; CONNECT also revoked)' ('exit {0}: {1}' -f $r.Code, $r.All)
Write-Host ('       | privilege layer: ' + $priv.All)

$r = Invoke-PgClient 'host=pg-primary dbname=app1 user=app1_runtime sslmode=disable' 'SELECT 1' $pgRuntimePw
Assert-Refused 'PG: app1_runtime without TLS (sslmode=disable) is refused' $r 'pg_hba\.conf rejects connection .*user "app1_runtime", database "app1", no encryption'

$r = Invoke-PgClient ('host=' + $pgIp + ' dbname=app1 user=app1_runtime ' + $verify) 'SELECT 1' $pgRuntimePw
Assert-Refused 'PG: verify-full rejects a host name not in the certificate (connect by IP)' $r 'does not match host name'

$r = Invoke-PgClient ('host=pg-primary dbname=app1 user=postgres ' + $verify) 'SELECT 1' $pgSuperPw
Assert-Refused 'PG: postgres over TCP+TLS from the app1-pg network is refused (correct password)' $r 'pg_hba\.conf rejects connection .*user "postgres"'

$r = Invoke-Docker @('exec', '-e', 'PGPASSWORD', $ids['pg-primary'], 'psql', 'host=127.0.0.1 dbname=app1 user=postgres sslmode=require', '-X', '-At', '-c', 'SELECT 1') @{ PGPASSWORD = $pgSuperPw }
Assert-Refused 'PG: postgres over TCP 127.0.0.1 inside pg-primary is refused (correct password)' $r 'pg_hba\.conf rejects connection .*user "postgres"'

$r = Invoke-PgAdmin ("SELECT 'runtime_super=' || r.rolsuper || ' runtime_createrole=' || r.rolcreaterole || ' db_owner=' || pg_get_userbyid(d.datdba) " +
    "|| ' tables_owned_by_runtime=' || (SELECT count(*) FROM pg_tables WHERE tableowner = 'app1_runtime') " +
    "|| ' runtime_can_select_customers=' || has_table_privilege('app1_runtime', 'public.customers', 'SELECT') " +
    "|| ' public_temp_on_app1=' || has_database_privilege('public', 'app1', 'TEMPORARY') " +
    "|| ' runtime_create_on_public=' || has_schema_privilege('app1_runtime', 'public', 'CREATE') " +
    "FROM pg_roles r, pg_database d WHERE r.rolname = 'app1_runtime' AND d.datname = 'app1'")
Assert-Works 'PG: app1_runtime is not superuser/owner, has DML via default privileges, no CREATE on public' $r 'runtime_super=false runtime_createrole=false db_owner=app1_migrator tables_owned_by_runtime=0 runtime_can_select_customers=true public_temp_on_app1=false runtime_create_on_public=false'

# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '== MariaDB (client: throwaway mariadb:11.8 container on the app1-maria network) =='

$mariaRuntimePw = Read-SecretFile 'maria_app1_runtime_password'
$mariaRootPw = Read-SecretFile 'maria_root_password'

function Invoke-MariaClient {
    param([string]$HostName, [string]$User, [string]$TlsMode, [string]$Sql, [string]$Password)
    # TlsMode: verify = TLS + CA + server cert verification; off = TLS disabled on the client.
    if ($TlsMode -eq 'off') { $tls = @('--skip-ssl') } else { $tls = @('--ssl-ca=/ca/ca.crt', '--ssl-verify-server-cert') }
    $a = @('run', '--rm', '--network', $netMaria, '-v', ($volCa + ':/ca:ro'), '-e', 'MYSQL_PWD',
        '--entrypoint', 'mariadb', 'mariadb:11.8', '-h', $HostName, '-u', $User) + $tls + @('--connect-timeout=5', '-N', '-B', 'app1', '-e', $Sql)
    return Invoke-Docker $a @{ MYSQL_PWD = $Password }
}
# mariadb over the local socket inside maria-primary as OS user mysql, so unix_socket auth
# does not apply and root@localhost must use the password from the secret.
function Invoke-MariaAdmin {
    param([string]$Sql)
    return Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', $ids['maria-primary'], 'mariadb', '--protocol=socket', '-uroot', '-N', '-B', '-e', $Sql) @{ MYSQL_PWD = $mariaRootPw }
}

$r = Invoke-MariaClient 'maria-primary' 'app1_runtime' 'verify' "SELECT CONCAT('user=', CURRENT_USER(), ' tls=', (SELECT VARIABLE_VALUE FROM information_schema.SESSION_STATUS WHERE VARIABLE_NAME = 'Ssl_version'), ' customers=', (SELECT COUNT(*) FROM customers))" $mariaRuntimePw
Assert-Works 'Maria: app1_runtime TLS with CA + server cert verification succeeds and can SELECT' $r 'user=app1_runtime@10\.81\.3\.0/255\.255\.255\.0 tls=TLSv1\.[23] customers=\d+'

$r = Invoke-MariaClient 'maria-primary' 'app1_runtime' 'verify' 'CREATE TABLE p1_probe (id int)' $mariaRuntimePw
Assert-Refused 'Maria: app1_runtime cannot CREATE TABLE' $r "CREATE command denied to user 'app1_runtime'"

$r = Invoke-MariaClient 'maria-primary' 'app1_runtime' 'off' 'SELECT 1' $mariaRuntimePw
Assert-Refused 'Maria: app1_runtime with TLS disabled on the client (--skip-ssl) is refused' $r 'insecure transport are prohibited while --require_secure_transport=ON'

$r = Invoke-MariaClient $mariaIp 'app1_runtime' 'verify' 'SELECT 1' $mariaRuntimePw
Assert-Refused 'Maria: server cert verification rejects a host name not in the certificate (connect by IP)' $r 'Hostname verification failed|does not match'

# The app's own client path: PDO inside laravel-api with only MYSQL_ATTR_SSL_CA set, exactly as
# config/database.php does it. By name it must work over TLS; by IP the name check must fail.
$pdoProbe = @'
$o = [PDO::ATTR_TIMEOUT => 4, Pdo\Mysql::ATTR_SSL_CA => getenv("MYSQL_ATTR_SSL_CA")];
try {
    $p = new PDO("mysql:host=" . $argv[1] . ";port=3306;dbname=app1", getenv("DB_USERNAME"), trim(file_get_contents(getenv("DB_PASSWORD_FILE"))), $o);
    echo "connected, ", implode("=", $p->query("SHOW SESSION STATUS LIKE 'Ssl_version'")->fetch(PDO::FETCH_NUM)), "\n";
    exit(0);
} catch (Throwable $e) {
    $w = error_get_last();
    fwrite(STDERR, "PDO: " . $e->getMessage() . ($w ? " (" . $w["message"] . ")" : "") . "\n");
    exit(1);
}
'@
$r = Invoke-Docker @('exec', $ids['laravel-api'], 'php', '-r', $pdoProbe, '--', 'maria-primary')
Assert-Works 'Maria: laravel-api PDO with MYSQL_ATTR_SSL_CA connects over TLS by service name' $r 'connected, Ssl_version=TLSv1\.[23]'
$r = Invoke-Docker @('exec', $ids['laravel-api'], 'php', '-r', $pdoProbe, '--', $mariaIp)
Assert-Refused 'Maria: laravel-api PDO with MYSQL_ATTR_SSL_CA rejects a host name not in the certificate' $r 'Cannot connect to MySQL using SSL|did not match|verify failed'

# Root: first prove the password from the secret is correct (socket login works), then show
# TCP is refused with that same password.
$ctl = Invoke-MariaAdmin "SELECT CONCAT('socket login as ', CURRENT_USER(), '; root accounts: ', (SELECT GROUP_CONCAT(CONCAT(User, '@', Host)) FROM mysql.user WHERE User = 'root'), '; accounts with host %: ', (SELECT COUNT(*) FROM mysql.user WHERE Host = '%'))"
Assert-Works 'Maria: control: root@localhost via socket works with the secret password; root exists only @localhost; no % accounts' $ctl 'socket login as root@localhost; root accounts: root@localhost; accounts with host %: 0'

$r = Invoke-MariaClient 'maria-primary' 'root' 'verify' 'SELECT 1' $mariaRootPw
Assert-Refused 'Maria: root over TCP+TLS from the app1-maria network is refused (correct password)' $r "Access denied for user 'root'@'10\.81\.3\.\d+'|is not allowed to connect"

$r = Invoke-Docker @('exec', '-u', 'mysql', '-e', 'MYSQL_PWD', $ids['maria-primary'], 'mariadb', '-h', '127.0.0.1', '--protocol=tcp', '-uroot', '--ssl', '--disable-ssl-verify-server-cert', '-N', '-e', 'SELECT 1') @{ MYSQL_PWD = $mariaRootPw }
Assert-Refused 'Maria: root over TCP 127.0.0.1 inside maria-primary is refused (correct password)' $r "Access denied for user 'root'@'127\.0\.0\.1'|is not allowed to connect"

$r = Invoke-MariaAdmin "SHOW GRANTS FOR 'app1_runtime'@'10.81.3.0/255.255.255.0'; SELECT CONCAT('ssl_type=', ssl_type) FROM mysql.user WHERE User = 'app1_runtime'"
$ok = ($r.Code -eq 0) -and ($r.Out -match 'GRANT SELECT, INSERT, UPDATE, DELETE ON `app1`\.\* TO `app1_runtime`@`10\.81\.3\.0/255\.255\.255\.0`') -and ($r.Out -match 'ssl_type=ANY') -and ($r.Out -notmatch 'CREATE|DROP|ALTER|ALL PRIVILEGES')
# Do not print the stored password hash.
$shown = $r.All -replace "PASSWORD '[^']*'", "PASSWORD '<redacted>'"
Write-Result $ok 'Maria: app1_runtime grants are DML on app1.* only, subnet host mask, REQUIRE SSL' ('exit {0}: {1}' -f $r.Code, $shown)

# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '== Secrets =='

$secretFiles = @(Get-ChildItem -File $secretsDir | Sort-Object Name)
$secretValues = @{}
foreach ($f in $secretFiles) {
    $v = [System.IO.File]::ReadAllText($f.FullName, $utf8NoBom)
    if ($v.Length -ge 8) { $secretValues[$f.Name] = $v }
}
# Bare passwords also catch a connection string or URL that embeds them.
Write-Host ('       | comparing against {0} secret files: {1}' -f $secretValues.Count, (($secretValues.Keys | Sort-Object) -join ', '))

function Find-SecretsIn {
    param([string]$Text)
    $hits = @()
    foreach ($k in $secretValues.Keys) { if ($Text.Contains($secretValues[$k])) { $hits += $k } }
    return $hits
}

foreach ($svc in @('dotnet-api', 'laravel-api')) {
    $r = Invoke-Docker @('inspect', '-f', '{{json .Config.Env}}', $ids[$svc])
    $envList = @()
    try { foreach ($e in (ConvertFrom-Json $r.Out)) { $envList += [string]$e } } catch { }
    # Search the raw JSON too, in case parsing missed anything.
    $hits = @(Find-SecretsIn (($envList -join "`n") + "`n" + $r.Out))
    $ok = ($r.Code -eq 0) -and ($envList.Count -gt 0) -and ($hits.Count -eq 0)
    $names = ($envList | ForEach-Object { ($_ -split '=', 2)[0] }) -join ' '
    $detail = ('env var names: {0}' -f $names)
    if ($hits.Count -gt 0) { $detail = $detail + "`nsecret values found for: " + ($hits -join ', ') }
    Write-Result $ok ('{0}: docker inspect env contains no secret value' -f $svc) $detail
}

$r = Invoke-Docker @('image', 'inspect', '-f', '{{json .Config.Env}}', ($project + '-dotnet-api'), ($project + '-laravel-api'), ($project + '-web'))
$compose = [System.IO.File]::ReadAllText($ComposeFile)
$hits = @(Find-SecretsIn ($r.Out + "`n" + $compose))
Write-Result (($r.Code -eq 0) -and ($hits.Count -eq 0)) ('app image env and {0} contain no secret value' -f (Split-Path -Leaf $ComposeFile)) ('hits: ' + ($(if ($hits.Count) { $hits -join ', ' } else { 'none' })))

foreach ($svc in @('dotnet-api', 'laravel-api')) {
    $r = Invoke-Docker @('inspect', '-f', '{{range .Mounts}}{{.Destination}} <- {{if .Name}}volume {{.Name}}{{else}}{{.Source}}{{end}}{{println}}{{end}}', $ids[$svc])
    $ls = Invoke-Docker @('exec', $ids[$svc], 'ls', '-1', '/run/secrets', '/pki-ca')
    $mounts = $r.Out.Trim()
    $ok = ($r.Code -eq 0) -and ($ls.Code -eq 0) -and ($mounts -notmatch '(?i)migrator') -and ($ls.Out -notmatch '(?i)migrator') `
        -and ($mounts -notmatch 'pki-ca-key|pki-pg|pki-maria') -and ($ls.Out -notmatch '\.key')
    Write-Result $ok ('{0}: no migrator secret and no private key mounted' -f $svc) ($mounts + "`nls /run/secrets /pki-ca:`n" + $ls.All)
}

foreach ($svc in @('dotnet-api', 'laravel-api')) {
    $r = Invoke-Docker @('inspect', '-f', '{{json .Config.Env}}', $ids[$svc])
    $ok = ($r.Code -eq 0) -and ($r.Out -notmatch 'RUN_MIGRATIONS_ON_STARTUP')
    Write-Result $ok ('{0}: RUN_MIGRATIONS_ON_STARTUP is not set' -f $svc) ''
}

# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '== Migrations =='

foreach ($svc in @('dotnet-migrate', 'laravel-migrate')) {
    $r = Invoke-Docker @('inspect', '-f', '{{.State.Status}} {{.State.ExitCode}}', $ids[$svc])
    $ok = ($r.Code -eq 0) -and ($r.Out.Trim() -eq 'exited 0')
    Write-Result $ok ('{0} exited with code 0' -f $svc) ('state: ' + $r.All)
}

Write-Host ''
Write-Host ('Summary: {0} passed, {1} failed' -f $script:Pass, $script:Fail)
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
