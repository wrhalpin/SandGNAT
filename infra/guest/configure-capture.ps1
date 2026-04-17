# Lay out the capture directory and mount the staging share.
#
# Run once during template baking, AFTER FLARE-VM installation. Produces:
#
#   C:\sandgnat\                — workspace for samples during detonation
#   C:\captures\                — ProcMon/tshark working output
#   \\<orchestrator>\analysis   — staging share (mounted as Z: if credentials
#                                 are provided via -Credential)
#
# Also registers the guest agent Scheduled Task that starts the watcher at
# boot. We use Task Scheduler instead of a real Windows Service so we can
# ship the agent as a PyInstaller-frozen executable without touching SCM —
# less operational friction, same result for our use case.

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $true)]
    [string]$OrchestratorHost,

    [Parameter(Mandatory = $true)]
    [string]$AgentExePath,

    [string]$ShareName = "analysis",

    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = "Stop"

Write-Host "Creating local working directories..."
New-Item -ItemType Directory -Force -Path "C:\sandgnat"   | Out-Null
New-Item -ItemType Directory -Force -Path "C:\captures"   | Out-Null

$sharePath = "\\${OrchestratorHost}\${ShareName}"
Write-Host "Mapping staging share $sharePath as Z:..."
if (Get-PSDrive -Name Z -ErrorAction SilentlyContinue) {
    Remove-PSDrive -Name Z -Force
}
if ($Credential) {
    New-PSDrive -Name Z -PSProvider FileSystem -Root $sharePath `
        -Persist -Credential $Credential | Out-Null
}
else {
    New-PSDrive -Name Z -PSProvider FileSystem -Root $sharePath `
        -Persist | Out-Null
}

Write-Host "Registering guest agent startup task..."
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
    -Description "SandGNAT guest collector agent"
Register-ScheduledTask -TaskName "SandGNATGuestAgent" -InputObject $task -Force | Out-Null

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
