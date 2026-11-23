[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 60,
    # Stack selection (defaults: the phase 2 stack). Phase 3:
    #   -ComposeFile .\compose.phase3.yaml -Project security-prototype-phase3 -BaoSecretPrefix openbao_phase3
    [string]$ComposeFile = '',
    [string]$Project = '',
    [string]$BaoSecretPrefix = ''
)

# Unseals OpenBao after a container restart (docker compose -f compose.phase2.yaml restart openbao,
# Docker Desktop restart, host reboot). OpenBao always starts sealed; Raft storage keeps all data,
# leases and the rotated database passwords.
# LAB-ONLY: the single unseal key is read from secrets\openbao_unseal_key (phase 3:
# secrets\openbao_phase3_unseal_key). It goes to the bao CLI inside the container on stdin, never
# on a command line.
$ErrorActionPreference = 'Stop'
# Set (possibly to '') before dot-sourcing, so values from a calling script never leak in.
$P2ComposeFile = $ComposeFile
$P2Project = $Project
$P2BaoSecretPrefix = $BaoSecretPrefix
. (Join-Path $PSScriptRoot 'phase2-lib.ps1')
Invoke-BaoUnseal
