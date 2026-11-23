# Shared helpers for the phase 2 scripts (phase2-setup.ps1, phase2-unseal.ps1, tests\phase2-checks.ps1).
# Dot-source it:  . (Join-Path $PSScriptRoot 'phase2-lib.ps1')
# Windows PowerShell 5.1 compatible.
#
# Secrets never go on a command line. They reach containers only as environment variables of
# the docker CLI process ("docker exec -e NAME" / "docker run -e NAME" without a value), and
# inside the container they are piped to the tool with the shell builtin printf.

$P2Root = Split-Path -Parent $PSScriptRoot
# Stack selection. A caller may set these BEFORE dot-sourcing (phase 3 reuses this library);
# empty or unset means the phase 2 defaults below, so phase 2 behaviour is unchanged.
#   $P2ComposeFile      compose file of the stack (its "name:" is the project)
#   $P2Project          compose project name (prefix of network and volume names)
#   $P2BaoSecretPrefix  file name prefix in secrets\ of the OpenBao unseal key and root token
#                       (<prefix>_unseal_key, <prefix>_root_token); each OpenBao instance has its own
if (-not $P2ComposeFile) { $P2ComposeFile = Join-Path $P2Root 'compose.phase2.yaml' } else { $P2ComposeFile = (Resolve-Path -LiteralPath $P2ComposeFile).Path }
if (-not $P2Project) { $P2Project = 'security-prototype-phase2' }
if (-not $P2BaoSecretPrefix) { $P2BaoSecretPrefix = 'openbao' }
$P2BaoUnsealKeyName = $P2BaoSecretPrefix + '_unseal_key'
$P2BaoRootTokenName = $P2BaoSecretPrefix + '_root_token'
$P2SecretsDir = Join-Path $P2Root 'secrets'
$P2Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
if (-not (Get-Variable -Name TimeoutSeconds -Scope Script -ErrorAction SilentlyContinue)) { $script:TimeoutSeconds = 90 }

# Docker is not always on PATH on this host.
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $dd = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin'
    if (Test-Path (Join-Path $dd 'docker.exe')) { $env:Path = $dd + ';' + $env:Path }
}
$P2DockerExe = (Get-Command docker).Source

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
    $psi.FileName = $P2DockerExe
    $psi.Arguments = (($DockerArgs | ForEach-Object { ConvertTo-CmdArg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $P2Utf8NoBom
    $psi.StandardErrorEncoding = $P2Utf8NoBom
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

function Read-P2Secret {
    param([string]$Name)
    return [System.IO.File]::ReadAllText((Join-Path $P2SecretsDir $Name), $P2Utf8NoBom).Trim()
}

function Write-P2Secret {
    param([string]$Name, [string]$Value)
    if (-not (Test-Path $P2SecretsDir)) { New-Item -ItemType Directory -Path $P2SecretsDir | Out-Null }
    [System.IO.File]::WriteAllText((Join-Path $P2SecretsDir $Name), $Value, $P2Utf8NoBom)
}

function Get-P2ContainerId {
    param([string]$Service)
    $r = Invoke-Docker @('compose', '-f', $P2ComposeFile, 'ps', '-a', '-q', $Service)
    $id = ($r.Out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $id) { throw ('No container for service {0}. Is the stack running (docker compose -f {1} up -d)?' -f $Service, (Split-Path -Leaf $P2ComposeFile)) }
    return $id.Trim()
}

# Runs the bao CLI inside the openbao container (BAO_ADDR and BAO_CACERT are set there).
# -Token: the token for this call (BAO_TOKEN). -StdinSecret: a value piped to bao on stdin, for
# use with a "key=-" argument. Neither appears on any command line.
function Invoke-Bao {
    param([string[]]$BaoArgs, [string]$Token = '', [string]$StdinSecret = $null, [int]$Timeout = 0)
    $id = Get-P2ContainerId 'openbao'
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
    if (-not $s.Obj.initialized) { throw 'OpenBao is not initialized. Run scripts\phase2-setup.ps1.' }
    if ($s.Obj.sealed) {
        $keyFile = Join-Path $P2SecretsDir $P2BaoUnsealKeyName
        if (-not (Test-Path $keyFile)) { throw ('OpenBao is sealed and secrets\{0} is missing.' -f $P2BaoUnsealKeyName) }
        $r = Invoke-Bao @('write', '-format=json', 'sys/unseal', 'key=-') '' (Read-P2Secret $P2BaoUnsealKeyName)
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
