# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
# Disable Windows Defender real-time protection and SmartScreen so the
# analysis VM observes true malware behaviour. Run as Administrator.
#
# This intentionally weakens host protections. Apply only on VMs attached to
# the isolated analysis VLAN (vmbr.analysis, default-deny egress). Never run
# on a machine that can reach the internet or production networks.
#
# Apply once during template baking, then bake the "clean" snapshot.

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "Disabling Windows Defender real-time protection..."
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent 2          # NeverSend
Set-MpPreference -MAPSReporting 0                  # Disabled

Write-Host "Disabling SmartScreen..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
    -Name "SmartScreenEnabled" -Value "Off" -Force

Write-Host "Disabling UAC prompts for administrators..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 0 -Force

Write-Host "Defender + SmartScreen + UAC disabled. Reboot required for UAC change."
