# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
# Lay out the capture directory and wire up the staging share.
#
# Run once during template baking, AFTER FLARE-VM installation and
# seed-user-profile.ps1 so the decoy user exists to host the workspace.
# Produces:
#
#   <UserProfile>\AppData\Local\Microsoft\PowerManagement\
#                               — workspace for samples during detonation
#                                 (named to match stock Windows telemetry dirs;
#                                 replaces the old C:\sandgnat\).
#   <UserProfile>\AppData\Local\Microsoft\PowerManagement\captures\
#                               — ProcMon/tshark working output.
#   C:\Windows\System32\SystemAudit.exe
#                               — Procmon.exe copied under an innocuous name;
#                                 the original under C:\Tools\Procmon\ is
#                                 deleted so a Process32Next sweep can't find
#                                 "procmon.exe".
#   \\<orchestrator>\analysis   — staging share accessed by UNC only. No drive
#                                 letter is mapped — an un-plumbed Z: is a
#                                 sandbox signal of its own.
#
# Also registers the guest agent Scheduled Task as
# "Windows-PowerManagementAudit" (matches the Windows naming convention) so
# a `schtasks /query` enumeration doesn't surface SandGNAT by name.
#
# We use Task Scheduler instead of a real Windows Service so we can ship the
# agent as a PyInstaller-frozen executable without touching SCM.
#
# Phase C of the anti-analysis mitigation plan
# (docs/explanation/anti-analysis-evasion.md §C).

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $true)]
    [string]$OrchestratorHost,

    [Parameter(Mandatory = $true)]
    [string]$AgentExePath,

    [Parameter(Mandatory = $true)]
    [string]$UserName,

    [string]$ShareName = "analysis",

    [string]$ProcmonSource = "C:\Tools\Procmon\Procmon.exe",

    [string]$TaskName = "Windows-PowerManagementAudit",

    [switch]$KeepOriginalProcmon
)

$ErrorActionPreference = "Stop"

$profileRoot = "C:\Users\$UserName"
if (-not (Test-Path $profileRoot)) {
    throw "user profile $profileRoot not found — run seed-user-profile.ps1 first"
}

$workRoot = Join-Path $profileRoot "AppData\Local\Microsoft\PowerManagement"
$captureRoot = Join-Path $workRoot "captures"

Write-Host "Creating hidden working directories under $workRoot..."
New-Item -ItemType Directory -Force -Path $workRoot    | Out-Null
New-Item -ItemType Directory -Force -Path $captureRoot | Out-Null

# Hidden + System attrs match what legitimate Windows telemetry writes.
(Get-Item $workRoot).Attributes = 'Directory,Hidden,System'

Write-Host "Staging share is \\${OrchestratorHost}\${ShareName} (UNC only — no drive mapping)."
if (Get-PSDrive -Name Z -ErrorAction SilentlyContinue) {
    Write-Host "Removing legacy Z: mapping from earlier template bakes."
    Remove-PSDrive -Name Z -Force -ErrorAction SilentlyContinue
}

# Relocate Procmon under an innocuous System32 name. The agent is
# configured via SANDGNAT_PROCMON env var to invoke the renamed copy;
# the original is deleted so process enumeration can't see
# "procmon.exe" anywhere on disk.
$procmonTarget = "C:\Windows\System32\SystemAudit.exe"
if (-not (Test-Path $ProcmonSource)) {
    Write-Warning "Procmon source $ProcmonSource not found; skipping rename. Agent will fail until SANDGNAT_PROCMON is set."
} else {
    Write-Host "Relocating Procmon: $ProcmonSource -> $procmonTarget"
    Copy-Item -Path $ProcmonSource -Destination $procmonTarget -Force
    if (-not $KeepOriginalProcmon) {
        $procmonDir = Split-Path $ProcmonSource -Parent
        Write-Host "Removing original Procmon install under $procmonDir"
        Remove-Item -Path "$procmonDir\*procmon*" -Force -Recurse -ErrorAction SilentlyContinue
    }
}

# Push the resolved paths into machine-scope env vars so the guest agent
# picks them up at startup regardless of which user session starts it.
Write-Host "Setting machine env vars for the guest agent..."
[System.Environment]::SetEnvironmentVariable("SANDGNAT_STAGING_ROOT", "\\${OrchestratorHost}\${ShareName}", "Machine")
[System.Environment]::SetEnvironmentVariable("SANDGNAT_WORK_ROOT", $workRoot, "Machine")
[System.Environment]::SetEnvironmentVariable("SANDGNAT_PROCMON", $procmonTarget, "Machine")

Write-Host "Registering guest agent startup task as '$TaskName'..."
# Old task name from pre-Phase-C bakes; remove it if present.
Unregister-ScheduledTask -TaskName "SandGNATGuestAgent" -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute $AgentExePath -Argument "serve"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650)
$task = New-ScheduledTask -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Windows Power Management audit service"
Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

Write-Host "Configuring firewall to allow only inbound from orchestrator..."
# Defense-in-depth: the VLAN firewall already blocks everything but explicit
# orchestrator traffic. This mirrors the policy at the guest edge.
New-NetFirewallRule -DisplayName "SandGNAT - deny all outbound" `
    -Direction Outbound -Action Block -Profile Any `
    -RemoteAddress 0.0.0.0/0 -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "SandGNAT - allow orchestrator SMB" `
    -Direction Inbound -Action Allow -Profile Any `
    -RemoteAddress $OrchestratorHost -Protocol TCP -LocalPort 445 `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "Capture environment ready. Reboot to start the agent."
