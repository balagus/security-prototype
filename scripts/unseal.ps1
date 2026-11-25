[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 60,
    # Stack selection. Empty = compose.yaml, project security-prototype, secrets\openbao_*.
    [string]$ComposeFile = '',
    [string]$Project = '',
    [string]$BaoSecretPrefix = ''
)

# Unseals OpenBao after a container restart (docker compose restart openbao,
# Docker Desktop restart, host reboot). OpenBao always starts sealed; Raft storage keeps all data,
# leases and the rotated database passwords.
# LAB-ONLY: the single unseal key is read from secrets\openbao_unseal_key. It goes to the bao
# CLI inside the container on stdin, never on a command line.
$ErrorActionPreference = 'Stop'
# Set (possibly to '') before dot-sourcing, so values from a calling script never leak in.
$LabComposeFile = $ComposeFile
$LabProject = $Project
$LabBaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $PSScriptRoot 'lib.ps1')
Invoke-BaoUnseal
