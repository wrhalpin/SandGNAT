# SPDX-License-Identifier: Apache-2.0 (doc)

---
layout: default
title: Anti-analysis evasion
description: How modern malware detects sandboxes + VMs, and SandGNAT's plan to defeat those checks so more samples run to completion.
---

# Anti-analysis evasion

**Status:** research + plan. Implementation is tracked in the mitigation
sections below; nothing in this doc is shipped yet.

A sample that correctly identifies SandGNAT as a sandbox will sleep, exit
silently, or run a decoy payload. Our goal is the opposite: look enough
like a real workstation at every level a sample can probe that the real
payload runs inside our instrumented VMs. This doc catalogs the checks
we're defending against and maps each to a concrete SandGNAT mitigation.

---

## Part 1 — The detection landscape

Malware's anti-sandbox arsenal falls into seven families. Ranked roughly
by how often we see them in the wild and how hard they are to evade.

### 1. Hypervisor presence

Cheap, universal, and one `CPUID` instruction away.

| Check | Signal |
|-------|--------|
| `CPUID.1:ECX[31]` (hypervisor bit) | Set under *any* hypervisor — VMware, KVM, Hyper-V, Xen |
| `CPUID.40000000h` vendor string | `KVMKVMKVM\0\0\0`, `VMwareVMware`, `Microsoft Hv`, `XenVMMXenVMM`, `TCGTCGTCGTCG` |
| MSR probe (`IA32_THERM_STATUS` etc.) | Values differ or `#GP` under KVM |
| `RDTSC` around `CPUID`/`VMEXIT` | Huge cycle-count jumps indicate a trap |
| `VMXON` / `VMREAD` | Bare metal runs them, nested virt may fail |

### 2. SMBIOS / hardware fingerprints

Visible to userland via WMI (`Win32_ComputerSystem`, `Win32_BIOS`),
registry, or device-property APIs.

| Surface | Tell |
|---------|------|
| System manufacturer | `QEMU`, `innotek GmbH`, `VMware, Inc.`, `Microsoft Corporation` (Hyper-V), `Xen`, `Bochs` |
| System product name | `Standard PC (i440FX + PIIX, 1996)`, `VirtualBox`, `VMware Virtual Platform` |
| BIOS vendor / version | `SeaBIOS`, `VBOX`, `Phoenix Technologies LTD` with VMware dates |
| Baseboard product | `440BX Desktop Reference Platform` |
| Drive model | `QEMU HARDDISK`, `VMware Virtual disk`, `VBOX HARDDISK` |
| MAC OUI | `00:05:69`/`00:0C:29`/`00:50:56` (VMware), `08:00:27`/`0A:00:27` (VirtualBox), `52:54:00` (QEMU/KVM) |
| ACPI tables | Custom OEM fields `BXPC`, `VBOXVE`, `BOCHS ` |
| PCI device IDs | `1AF4:*` (virtio), `80EE:*` (VirtualBox), `15AD:*` (VMware) |

### 3. OS-level artifacts (most common in commodity malware)

Files, registry keys, processes, services, drivers.

| Class | Examples |
|-------|----------|
| Drivers | `VBoxMouse.sys`, `VBoxGuest.sys`, `VBoxSF.sys`, `vmhgfs.sys`, `vmmouse.sys`, `vm3dmp.sys`, `vmrawdsk.sys`, `vmicheartbeat.sys` |
| Processes | `vmtoolsd.exe`, `VBoxTray.exe`, `VBoxService.exe`, `vmwareuser.exe`, `vmacthlp.exe`, `qemu-ga.exe`, `prl_tools.exe` |
| Services | `VMTools`, `VBoxService`, `vmicheartbeat`, `vmicvss`, `vmicshutdown` |
| File paths | `C:\Program Files\VMware\`, `C:\Program Files\Oracle\VirtualBox Guest Additions\`, `C:\Windows\System32\drivers\vbox*.sys` |
| Registry | `HKLM\HARDWARE\ACPI\DSDT\VBOX__`, `HKLM\SYSTEM\CCS\Services\VBoxGuest`, `HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion` (contains `VBOX`/`VMware`), `HKLM\SYSTEM\CCS\Enum\PCI\VEN_15AD` |
| Device paths | `\\.\VBoxGuest`, `\\.\VBoxMiniRdrDN`, `\\.\VMCI`, `\\.\HGFS` |
| Window classes | `VBoxTrayToolWndClass` |

### 4. Environment realism

Would a real user be here?

| Check | Typical sandbox tell |
|-------|----------------------|
| Username / hostname | `sandbox`, `malware`, `analyst`, `cuckoo`, `test`, `user`, `WIN-*` generated name, unchanged default `Administrator` |
| Domain join | Sandboxes usually WORKGROUP; enterprises are AD-joined |
| Installed programs | ProcMon, Wireshark, x64dbg, IDA, Process Hacker, Fiddler, PEiD, FakeNet-NG, IDA Pro |
| Disk size | <60 GB |
| Total RAM | <4 GB |
| CPU cores | 1 or 2 (most real machines have ≥ 4 logical cores) |
| Screen resolution | 1024×768, 800×600 |
| Recent-documents list | Empty |
| Browser history | None |
| Printers | None configured |
| Connected USB peripherals | None (beyond mouse/keyboard emulated by hypervisor) |
| Desktop icons / Start menu | Pristine |
| User profile age (from NTUSER.DAT) | Minutes old |

### 5. User-interaction checks

A real workstation is not idle.

- Mouse position unchanged over N seconds → sandbox.
- `GetLastInputInfo` returns idle time longer than plausible.
- No foreground-window switches in last N minutes.
- Specific wait for mouse click (`GetCursorPos` loop, or a dialog that
  requires a button click before payload runs).
- Scroll-wheel never fires.
- No keyboard events.

### 6. Timing & sleep defeat

- **Long sleeps** (30 min to 24 h) rely on the sandbox's analysis
  timeout being shorter — which is exactly how most sandboxes behave.
- **Stalling loops**: tight loops with large constant iterations
  expecting wall-clock acceleration by the sandbox.
- **`QueryPerformanceCounter` / `RDTSC` delta** comparisons with
  `GetSystemTimeAsFileTime` — if they diverge, time acceleration is
  active.
- **Multi-stage time checks**: sample records `t0` at startup, waits
  for a button click to record `t1`, only detonates if `t1 - t0` is
  long enough that a human could have produced it.

### 7. Network-fingerprint and capture-tool detection

- Looking for **INetSim patterns**: identical HTTP 200 for any domain,
  default banner strings, specific `Server:` headers.
- DNS checks against **known-reachable real domains**
  (`windowsupdate.microsoft.com`, `google.com`) — sandbox with isolated
  DNS fails these.
- **Captive-portal detection** via Microsoft NCSI (`msftncsi.com`
  returns the string `Microsoft NCSI`).
- **Public-IP ASN lookup** — sample calls `icanhazip.com` or similar,
  compares against residential/enterprise ASN lists.
- **Latency probes** — `ping` to `8.8.8.8` expects single-digit ms jitter.
- **Process enumeration** for `procmon.exe`, `wireshark.exe`,
  `tcpview.exe`, `ollydbg.exe`, `windbg.exe`, `x32dbg.exe`,
  `fiddler.exe`, `python.exe` (yes, really — catches unpackers).
- **Window-title enumeration** for `"Process Monitor"`,
  `"Wireshark"`, `"Sysinternals"`.
- **Kernel-driver enumeration** via `ZwQuerySystemInformation` for
  `procmon23.sys`, `NPF.sys` (npcap).

---

Part 2 (the SandGNAT-specific mitigation plan) is in the next commit.
