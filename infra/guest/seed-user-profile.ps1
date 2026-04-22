# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
#
# seed-user-profile.ps1 — Phase B of the anti-analysis mitigation plan.
#
# Give the template the fingerprint of a lived-in Windows workstation so
# commodity malware's "is this a sandbox?" heuristics (few users, empty
# Documents, no browser history, no recent files, workgroup=WORKGROUP
# with 1 account, under 10 installed apps) flip from yes to no.
#
# Runs once during template baking, AFTER configure-capture.ps1 and
# BEFORE the clean snapshot. Idempotent — re-running just refreshes the
# seeded content.
#
# Does not touch the `Analyst` account that configure-capture.ps1 set
# the scheduled task under; this is a decoy "primary" user the VM will
# auto-login as. Malware enumerates all profiles, so having both is
# strictly more convincing than having one.
#
# Scope is filesystem + registry realism + installed apps. Does NOT
# simulate active user input during detonation — that's Phase D
# (guest_agent/activity/).

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$UserName,

    [string]$UserPassword = "Welcome1!$(Get-Random -Minimum 1000 -Maximum 9999)",

    [string]$SeedDataRoot = (Join-Path $PSScriptRoot "seed-data"),

    [string]$AppsToInstall = "LibreOffice.LibreOffice,Google.Chrome,7zip.7zip,VideoLAN.VLC,Notepad++.Notepad++,Mozilla.Firefox,Zoom.Zoom",

    [string]$DomainController,

    [string]$DomainName,

    [System.Management.Automation.PSCredential]$DomainJoinCredential,

    [switch]$SkipAppInstall
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$msg) { Write-Host "[seed-profile] $msg" -ForegroundColor Cyan }
function Write-Warn([string]$msg) { Write-Host "[seed-profile] $msg" -ForegroundColor Yellow }

# 1. Pick a plausible user name if one wasn't supplied. The name needs
#    to look like a real person (first.last) — malware rejects "user",
#    "admin", "sandbox", "test", "vmuser", "maltest", etc.
if (-not $UserName) {
    $firstNames = @(
        "emily","james","olivia","michael","sophia","daniel","ava","matthew",
        "isabella","andrew","mia","joshua","charlotte","ethan","amelia","ryan"
    )
    $lastNames = @(
        "carter","morgan","walker","bennett","hayes","reed","fisher","brooks",
        "coleman","rivera","bryant","warren","porter","hunter","sanders"
    )
    $first = Get-Random -InputObject $firstNames
    $last  = Get-Random -InputObject $lastNames
    $UserName = "$first.$last"
    Write-Step "generated user: $UserName"
}

$profileRoot = "C:\Users\$UserName"

# 2. Create the user account if it doesn't exist. Mark password as never
#    expiring — a locked-out profile looks suspicious to LastPasswordSet
#    checks.
$existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Step "creating local user $UserName"
    $securePw = ConvertTo-SecureString $UserPassword -AsPlainText -Force
    New-LocalUser -Name $UserName -Password $securePw `
        -FullName ($UserName -replace '\.', ' ' -replace '\b(.)', { $_.Value.ToUpper() }) `
        -Description "Primary user" `
        -PasswordNeverExpires `
        -AccountNeverExpires | Out-Null
    Add-LocalGroupMember -Group "Users" -Member $UserName -ErrorAction SilentlyContinue
} else {
    Write-Step "user $UserName already exists — re-seeding content"
}

# 3. Force first-logon profile materialisation. Without this the
#    C:\Users\$UserName tree doesn't exist, which is itself a sandbox
#    tell.
if (-not (Test-Path $profileRoot)) {
    Write-Step "materialising profile via runas"
    $cred = New-Object System.Management.Automation.PSCredential(
        $UserName, (ConvertTo-SecureString $UserPassword -AsPlainText -Force))
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit" `
        -Credential $cred -LoadUserProfile -WindowStyle Hidden -Wait `
        -WorkingDirectory "C:\"
}

if (-not (Test-Path $profileRoot)) {
    throw "profile for $UserName still missing; check Group Policy for 'Deny logon locally'"
}

# 4. Populate Documents / Downloads / Pictures from seed-data if
#    present, else from a built-in minimal payload. Avoid shipping
#    third-party copyrighted content in the repo — operators drop real
#    docs into seed-data/ themselves.
function Copy-Seed([string]$subdir, [string]$destFolder) {
    $src = Join-Path $SeedDataRoot $subdir
    if (Test-Path $src) {
        Write-Step "copying $subdir -> $destFolder"
        Copy-Item -Path (Join-Path $src '*') -Destination $destFolder -Recurse -Force
    } else {
        Write-Warn "no seed-data\$subdir present; writing minimal placeholder"
        $ts = (Get-Date).AddDays(-(Get-Random -Minimum 3 -Maximum 180))
        switch ($subdir) {
            'Documents' {
                $fp = Join-Path $destFolder "meeting-notes.txt"
                Set-Content -Path $fp -Value "quarterly review 2025-Q4`nAI budget: pending`nfollow up with finance" -Force
                (Get-Item $fp).LastWriteTime = $ts
                $fp2 = Join-Path $destFolder "taxes-2024.txt"
                Set-Content -Path $fp2 -Value "TODO: gather W2, 1099-INT" -Force
                (Get-Item $fp2).LastWriteTime = $ts.AddDays(-14)
            }
            'Downloads' {
                $fp = Join-Path $destFolder "setup_9.4.2.exe"
                [System.IO.File]::WriteAllBytes($fp, (New-Object byte[] 1048576))
                (Get-Item $fp).LastWriteTime = $ts.AddDays(-22)
            }
            'Pictures' {
                $fp = Join-Path $destFolder "IMG_$(Get-Random -Minimum 1000 -Maximum 9999).jpg"
                [System.IO.File]::WriteAllBytes($fp, (New-Object byte[] 524288))
                (Get-Item $fp).LastWriteTime = $ts.AddDays(-45)
            }
        }
    }
}

foreach ($dir in 'Documents','Downloads','Pictures') {
    $dest = Join-Path $profileRoot $dir
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Seed -subdir $dir -destFolder $dest
}

# 5. Seed Recent Documents so the jump list + shell:recent look lived-
#    in. Each entry is a .lnk that points at a file we just created;
#    explorer materialises them into RecentDocs on first enumeration.
$recentDir = Join-Path $profileRoot "AppData\Roaming\Microsoft\Windows\Recent"
New-Item -ItemType Directory -Force -Path $recentDir | Out-Null

$shell = New-Object -ComObject WScript.Shell
Get-ChildItem -Path (Join-Path $profileRoot "Documents") -File |
    Select-Object -First 10 | ForEach-Object {
    $lnkPath = Join-Path $recentDir ($_.BaseName + ".lnk")
    $lnk = $shell.CreateShortcut($lnkPath)
    $lnk.TargetPath = $_.FullName
    $lnk.Save()
    $randomDaysAgo = Get-Random -Minimum 1 -Maximum 30
    (Get-Item $lnkPath).LastWriteTime = (Get-Date).AddDays(-$randomDaysAgo)
}
Write-Step "seeded $((Get-ChildItem $recentDir).Count) recent-document shortcuts"

# 6. Installed-apps fingerprint. Malware counts entries under
#    HKLM\...\Uninstall; anything under ~8 is a red flag. winget is
#    available on Windows 10 21H2+ and ships with every 11 SKU.
if (-not $SkipAppInstall) {
    $wingetPath = (Get-Command winget -ErrorAction SilentlyContinue).Path
    if (-not $wingetPath) {
        Write-Warn "winget not found; skipping app install (install App Installer from the Store or pass -SkipAppInstall)"
    } else {
        $apps = $AppsToInstall -split '\s*,\s*' | Where-Object { $_ }
        foreach ($app in $apps) {
            Write-Step "winget install $app"
            & $wingetPath install --id $app --accept-package-agreements --accept-source-agreements --silent --exact 2>&1 |
                ForEach-Object { Write-Host "  $_" }
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "winget returned $LASTEXITCODE for $app — continuing"
            }
        }
    }
} else {
    Write-Step "skipping app install (--SkipAppInstall)"
}

# 7. Workgroup / domain posture. WORKGROUP is the Windows default and
#    therefore unremarkable; SANDBOX / MALWARE / TESTENV are themselves
#    signals. Joining a sacrificial AD forest costs ~5 minutes and
#    silences another tranche of checks.
if ($DomainController -and $DomainName -and $DomainJoinCredential) {
    Write-Step "domain-joining $env:COMPUTERNAME to $DomainName via $DomainController"
    Add-Computer -DomainName $DomainName -Credential $DomainJoinCredential -Force -ErrorAction Stop
    Write-Step "domain join queued; reboot required before it takes effect"
} else {
    $currentWg = (Get-WmiObject Win32_ComputerSystem).Workgroup
    if (-not $currentWg -or $currentWg -match '^(SANDBOX|MALWARE|VMWARE|TEST)') {
        Write-Step "workgroup is '$currentWg' — renaming to WORKGROUP"
        Add-Computer -WorkgroupName "WORKGROUP" -Force
    } else {
        Write-Step "workgroup '$currentWg' is fine; leaving as-is"
    }
}

# 8. Autologon for the seeded user. Malware timing checks watch for
#    "no-one's sitting at the console" — automatic logon with an
#    interactive session closes that window.
Write-Step "enabling autologon for $UserName"
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $winlogon -Name "DefaultUserName" -Value $UserName
Set-ItemProperty -Path $winlogon -Name "DefaultPassword" -Value $UserPassword
Set-ItemProperty -Path $winlogon -Name "AutoAdminLogon"  -Value "1"
Set-ItemProperty -Path $winlogon -Name "DefaultDomainName" -Value $env:COMPUTERNAME

# 9. Record what we did so the README can link the clean-snapshot step
#    to the generated credentials.
$stamp = Join-Path $profileRoot "profile.seed.json"
$record = @{
    user       = $UserName
    seeded_at  = (Get-Date -Format "o")
    seed_root  = $SeedDataRoot
    apps       = ($AppsToInstall -split '\s*,\s*' | Where-Object { $_ })
} | ConvertTo-Json -Depth 3
Set-Content -Path $stamp -Value $record -Force

Write-Step "profile seeded. Credentials:"
Write-Host "  user: $UserName"
Write-Host "  pass: $UserPassword"
Write-Step "next step: reboot once to verify autologon, then take the clean snapshot."
