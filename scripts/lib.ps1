# Shared helpers for the setup scripts and the test suites.
# Dot-source it:  . (Join-Path $PSScriptRoot 'lib.ps1')
# Windows PowerShell 5.1 compatible.
#
# Secrets never go on a command line. They reach containers only as environment variables of
# the docker CLI process ("docker exec -e NAME" / "docker run -e NAME" without a value), and
# inside the container they are piped to the tool with the shell builtin printf.

$LabRoot = Split-Path -Parent $PSScriptRoot
# Stack selection. A caller may set these BEFORE dot-sourcing; empty or unset means the
# defaults below (compose.yaml, project security-prototype, secrets\openbao_*).
#   $LabComposeFile      compose file of the stack (its "name:" is the project)
#   $LabProject          compose project name (prefix of network and volume names)
#   $LabBaoSecretPrefix  file name prefix in secrets\ of the OpenBao unseal key and root token
#                       (<prefix>_unseal_key, <prefix>_root_token); each OpenBao instance has its own
if (-not $LabComposeFile) { $LabComposeFile = Join-Path $LabRoot 'compose.yaml' } else { $LabComposeFile = (Resolve-Path -LiteralPath $LabComposeFile).Path }
if (-not $LabProject) { $LabProject = 'security-prototype' }
if (-not $LabBaoSecretPrefix) { $LabBaoSecretPrefix = 'openbao' }
$LabBaoUnsealKeyName = $LabBaoSecretPrefix + '_unseal_key'
$LabBaoRootTokenName = $LabBaoSecretPrefix + '_root_token'
$LabSecretsDir = Join-Path $LabRoot 'secrets'
$LabUtf8NoBom = New-Object System.Text.UTF8Encoding($false)
if (-not (Get-Variable -Name TimeoutSeconds -Scope Script -ErrorAction SilentlyContinue)) { $script:TimeoutSeconds = 90 }

# Docker is not always on PATH on this host.
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $dd = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin'
    if (Test-Path (Join-Path $dd 'docker.exe')) { $env:Path = $dd + ';' + $env:Path }
}
$LabDockerExe = (Get-Command docker).Source

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
function Invoke-Docker {
    param([string[]]$DockerArgs, [hashtable]$Env = @{}, [int]$Timeout = 0)
    if ($Timeout -le 0) { $Timeout = $script:TimeoutSeconds }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $LabDockerExe
    $psi.Arguments = (($DockerArgs | ForEach-Object { ConvertTo-CmdArg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $LabUtf8NoBom
    $psi.StandardErrorEncoding = $LabUtf8NoBom
    $psi.CreateNoWindow = $true
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try {
        [void]$p.Start()
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($Timeout * 1000)) {
            try { $p.Kill() } catch { }
            $m = ('timed out after {0}s' -f $Timeout)
            return @{ Code = -1; Out = ''; Err = $m; All = $m }
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

function Read-LabSecret {
    param([string]$Name)
    return [System.IO.File]::ReadAllText((Join-Path $LabSecretsDir $Name), $LabUtf8NoBom).Trim()
}

function Write-LabSecret {
    param([string]$Name, [string]$Value)
    if (-not (Test-Path $LabSecretsDir)) { New-Item -ItemType Directory -Path $LabSecretsDir | Out-Null }
    [System.IO.File]::WriteAllText((Join-Path $LabSecretsDir $Name), $Value, $LabUtf8NoBom)
}

function Get-LabContainerId {
    param([string]$Service)
    $r = Invoke-Docker @('compose', '-f', $LabComposeFile, 'ps', '-a', '-q', $Service)
    $id = ($r.Out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $id) { throw ('No container for service {0}. Is the stack running (docker compose -f {1} up -d)?' -f $Service, (Split-Path -Leaf $LabComposeFile)) }
    return $id.Trim()
}

# Runs the bao CLI inside the openbao container (BAO_ADDR and BAO_CACERT are set there).
# -Token: the token for this call (BAO_TOKEN). -StdinSecret: a value piped to bao on stdin, for
# use with a "key=-" argument. Neither appears on any command line.
function Invoke-Bao {
    param([string[]]$BaoArgs, [string]$Token = '', [string]$StdinSecret = $null, [int]$Timeout = 0)
    $id = Get-LabContainerId 'openbao'
    $envs = @{}
    $a = @('exec')
    if ($Token) { $a += @('-e', 'BAO_TOKEN'); $envs['BAO_TOKEN'] = $Token }
    if ($null -ne $StdinSecret) {
        $a += @('-e', 'BAO_STDIN', $id, 'sh', '-c', 'printf %s "$BAO_STDIN" | bao "$@"', 'sh')
        $envs['BAO_STDIN'] = $StdinSecret
    } else {
        $a += @($id, 'bao')
    }
    return Invoke-Docker ($a + $BaoArgs) $envs $Timeout
}

function ConvertFrom-JsonOrNull {
    param([string]$Text)
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

# bao status: exit 0 = unsealed, 2 = sealed, 1 = error.
function Get-BaoStatus {
    $r = Invoke-Bao @('status', '-format=json')
    $o = ConvertFrom-JsonOrNull $r.Out
    return @{ Code = $r.Code; Obj = $o; All = $r.All }
}

# Unseals OpenBao with secrets\openbao_unseal_key if it is sealed and waits until it is active.
function Invoke-BaoUnseal {
    param([int]$WaitSeconds = 90)
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $s = Get-BaoStatus
    while (($null -eq $s.Obj) -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 2; $s = Get-BaoStatus }
    if ($null -eq $s.Obj) { throw ('OpenBao does not answer: ' + $s.All) }
    if (-not $s.Obj.initialized) { throw 'OpenBao is not initialized. Run scripts\setup-access.ps1.' }
    if ($s.Obj.sealed) {
        $keyFile = Join-Path $LabSecretsDir $LabBaoUnsealKeyName
        if (-not (Test-Path $keyFile)) { throw ('OpenBao is sealed and secrets\{0} is missing.' -f $LabBaoUnsealKeyName) }
        $r = Invoke-Bao @('write', '-format=json', 'sys/unseal', 'key=-') '' (Read-LabSecret $LabBaoUnsealKeyName)
        $o = ConvertFrom-JsonOrNull $r.Out
        if (($r.Code -ne 0) -or ($null -eq $o) -or $o.sealed) { throw ('Unseal failed: ' + $r.Err) }
        Write-Host 'openbao: unsealed'
    } else {
        Write-Host 'openbao: already unsealed'
    }
    # Wait until this single Raft node is the active node and answers authenticated requests.
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-Bao @('read', '-format=json', 'sys/leader')
        $o = ConvertFrom-JsonOrNull $r.Out
        if (($r.Code -eq 0) -and ($null -ne $o) -and $o.data.is_self) { Write-Host 'openbao: active'; return }
        Start-Sleep -Seconds 2
    }
    throw 'OpenBao did not become active in time.'
}
