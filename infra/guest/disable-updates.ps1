# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
# Disable Windows Update so the clean snapshot stays deterministic.
# Automatic updates change hundreds of registry keys and drop files on every
# boot — RegShot baselines would be useless.
#
# Apply during template baking, before taking the clean snapshot.

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "Stopping and disabling Windows Update services..."
$services = @("wuauserv", "UsoSvc", "WaaSMedicSvc", "DoSvc")
foreach ($svc in $services) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service  -Name $svc -StartupType Disabled
}

Write-Host "Blocking Windows Update endpoints via policy..."
$policyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item -Path $policyKey -Force | Out-Null
Set-ItemProperty -Path $policyKey -Name "NoAutoUpdate" -Value 1
Set-ItemProperty -Path $policyKey -Name "AUOptions"   -Value 1   # Never check

$storeKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
New-Item -Path $storeKey -Force | Out-Null
Set-ItemProperty -Path $storeKey -Name "AutoDownload" -Value 2   # Disabled

Write-Host "Windows Update disabled."
