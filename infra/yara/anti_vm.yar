/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Bill Halpin
 *
 * SandGNAT anti-VM / anti-analysis rules.
 *
 * Loaded by the Linux static-analysis guest's deep-scan stage
 * (linux_guest_agent/tools/yara_deep.py). Matches here feed the
 * Phase G evasion detector via `static_analysis.deep_yara_matches`
 * — any rule in this file must be tagged `anti_vm`, `anti_analysis`,
 * or `anti_debug` so the detector picks it up.
 *
 * Deliberately conservative: these rules prefer false negatives over
 * false positives because a hit flips `evasion_observed=TRUE` on the
 * analysis row.
 */

rule SandGNAT_AntiVM_VMwareArtifacts : anti_vm
{
    meta:
        author      = "SandGNAT"
        description = "References VMware Tools driver or install paths"

    strings:
        $a1 = "VMware, Inc." ascii wide
        $a2 = "vmmouse.sys" ascii wide nocase
        $a3 = "vmhgfs.sys" ascii wide nocase
        $a4 = "VMware Tools" ascii wide nocase
        $a5 = "VMwareService.exe" ascii wide nocase
        $a6 = "HGFS" ascii wide

    condition:
        2 of ($a*)
}

rule SandGNAT_AntiVM_VBoxArtifacts : anti_vm
{
    meta:
        author      = "SandGNAT"
        description = "References VirtualBox Guest Additions drivers or paths"

    strings:
        $a1 = "VBoxMouse.sys" ascii wide nocase
        $a2 = "VBoxGuest.sys" ascii wide nocase
        $a3 = "VBoxSF.sys"    ascii wide nocase
        $a4 = "VBoxService.exe" ascii wide nocase
        $a5 = "VBoxTray.exe"    ascii wide nocase
        $a6 = "Oracle\\VirtualBox Guest Additions" ascii wide nocase
        $a7 = "VBoxMiniRdrDN" ascii wide

    condition:
        2 of ($a*)
}

rule SandGNAT_AntiVM_BiosRegistryProbes : anti_vm
{
    meta:
        author      = "SandGNAT"
        description = "Probes BIOS/ACPI registry keys commonly used for VM detection"

    strings:
        $k1 = "HARDWARE\\ACPI\\DSDT" ascii wide nocase
        $k2 = "HARDWARE\\ACPI\\FADT" ascii wide nocase
        $k3 = "SystemBiosVersion" ascii wide nocase
        $k4 = "VideoBiosVersion" ascii wide nocase
        $k5 = "SystemProductName" ascii wide nocase
        $k6 = "SystemManufacturer" ascii wide nocase

    condition:
        2 of ($k*)
}

rule SandGNAT_AntiVM_MacOUIChecks : anti_vm
{
    meta:
        author      = "SandGNAT"
        description = "Hard-coded MAC-OUI prefixes used by commodity VM detectors"

    strings:
        // QEMU.
        $qemu1 = "52:54:00" ascii wide
        $qemu2 = "525400"   ascii wide
        // VMware.
        $vmw1  = "00:05:69" ascii wide
        $vmw2  = "00:0C:29" ascii wide nocase
        $vmw3  = "00:1C:14" ascii wide nocase
        $vmw4  = "00:50:56" ascii wide
        // VirtualBox.
        $vbox1 = "08:00:27" ascii wide

    condition:
        any of them
}

rule SandGNAT_AntiDebug_WellKnownAPIs : anti_debug
{
    meta:
        author      = "SandGNAT"
        description = "Imports/strings commonly paired with anti-debug checks"

    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "NtQueryInformationProcess" ascii
        $a4 = "OutputDebugStringA" ascii
        $a5 = "DebugActiveProcess" ascii
        $a6 = "NtGlobalFlag" ascii wide

    condition:
        3 of ($a*)
}

rule SandGNAT_AntiAnalysis_ProcessEnumeration : anti_analysis
{
    meta:
        author      = "SandGNAT"
        description = "Hard-codes analysis-tool process names for enumeration"

    strings:
        $p1  = "procmon.exe" ascii wide nocase
        $p2  = "procmon64.exe" ascii wide nocase
        $p3  = "wireshark.exe" ascii wide nocase
        $p4  = "tcpdump.exe" ascii wide nocase
        $p5  = "fiddler.exe" ascii wide nocase
        $p6  = "ollydbg.exe" ascii wide nocase
        $p7  = "idaq.exe" ascii wide nocase
        $p8  = "idaq64.exe" ascii wide nocase
        $p9  = "ida64.exe" ascii wide nocase
        $p10 = "x64dbg.exe" ascii wide nocase
        $p11 = "x32dbg.exe" ascii wide nocase
        $p12 = "autoruns.exe" ascii wide nocase
        $p13 = "regshot.exe" ascii wide nocase

    condition:
        3 of ($p*)
}

rule SandGNAT_AntiAnalysis_SleepStalling : anti_analysis
{
    meta:
        author      = "SandGNAT"
        description = "Imports multiple long-sleep primitives; typical of stalling loaders"

    strings:
        $s1 = "Sleep"           ascii
        $s2 = "SleepEx"         ascii
        $s3 = "NtDelayExecution" ascii
        $s4 = "WaitForSingleObject" ascii
        $s5 = "GetTickCount64"  ascii
        $s6 = "QueryPerformanceCounter" ascii

    condition:
        3 of ($s*)
}
