# SPDX-License-Identifier: Apache-2.0 (doc)

---
layout: default
title: Anti-analysis evasion
description: How modern malware detects sandboxes + VMs, and SandGNAT's plan to defeat those checks so more samples run to completion.
---

# Anti-analysis evasion

**Status:** Phases A–G shipped. Each mitigation section below ends with
an "Implementation" note linking the code and commit. The detection
landscape survey (Part 1) is unchanged reference material; the
mitigation plan (Part 2) has become the mitigation record.

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

---

## Part 2 — SandGNAT mitigation plan

Each mitigation lives in a concrete module already in the repo, or a
clearly-named new directory. Phases are ordered for cost-to-value; A/B/C
are quick wins that defeat the majority of commodity malware checks, D/E
are the heavier lifts for evasive families.

### A. Proxmox-level hardening (1 week)

**Shipped** (`b37d8a7`). Code: `infra/proxmox/harden-template.sh`,
`infra/proxmox/README.md`.

Target: defeat CPUID vendor string, SMBIOS strings, disk/NIC model
fingerprints, MAC OUI checks.

**New directory: `infra/proxmox/`**

`infra/proxmox/harden-template.sh` — run once per template vmid. Wraps
`qm set` invocations:

```bash
# Hide the KVM hypervisor bit + vendor string.
qm set "$VMID" --args '-cpu host,kvm=off,-hypervisor,hv_vendor_id=GenuineIntel'

# SMBIOS strings that match a real Dell OptiPlex.
qm set "$VMID" --smbios1 "manufacturer=Dell Inc.,\
product=OptiPlex 7090,\
version=1.0.0,\
serial=$(uuidgen | tr -d - | head -c 7 | tr a-f A-F),\
uuid=$(uuidgen),\
sku=SKU123"

# MAC from a Dell OUI (A4:BB:6D, 00:14:22).
qm set "$VMID" --net0 "virtio=00:14:22:$(openssl rand -hex 3 | sed 's/../&:/g;s/:$//'),bridge=vmbr.analysis"

# Swap virtio NIC for e1000e (less obviously paravirtualised).
# Swap virtio-scsi for ahci with a realistic drive model + serial.
qm set "$VMID" --scsi0 "local-lvm:vm-$VMID-disk-0,ssd=1,cache=none,\
discard=on,iothread=1,serial=WD-WCASY7$(openssl rand -hex 4 | tr a-f A-F)"
```

`infra/proxmox/README.md` documents the required Proxmox version (8.0+
for the `-hypervisor` cpu feature) and lists every flag we override and
why.

Validation: run `pafish` inside the template before and after. Expect
the "CPUID hypervisor", "SMBIOS", "MAC vendor", "HDD model" checks to
flip from detected → clean.

### B. Guest-OS realism (1 week)

**Shipped** (`0c83008`). Code: `infra/guest/seed-user-profile.ps1`,
`infra/guest/seed-data/README.md`, updated `infra/guest/README.md`
with sizing baseline and Phase-B template-bake step.

Target: defeat environment-realism checks (§4 above).

**New: `infra/guest/seed-user-profile.ps1`** — runs during template bake,
after `configure-capture.ps1`:

- Creates a realistic user account (random first.last, random 6-digit
  age, parametrised via `-UserName`).
- Populates `Documents/`, `Downloads/`, `Pictures/` with stock content
  (shipped in `infra/guest/seed-data/`).
- Seeds browser history by running a Chromium/Edge profile generator
  against a curated 200-site list.
- Adds entries to Recent Documents (`shell:recent`) for the last 30
  days.
- Domain-joins to a sacrificial AD forest if `-DomainController` is
  provided, else leaves the machine in a realistic local WORKGROUP
  named `WORKGROUP` (not `SANDBOX`).
- Installs 5–10 real apps: LibreOffice, Chrome, 7-Zip, VLC, Notepad++
  (chosen because their installers run quickly and leave deep
  filesystem footprints).

**Template sizing baseline** (documented in `infra/guest/README.md`):

| Resource | Default | Minimum |
|----------|---------|---------|
| vCPUs | 4 cores × 2 threads | 4 |
| RAM | 8 GB | 6 GB |
| Disk | 120 GB | 80 GB |
| Resolution | 1920×1080 | 1600×900 |

### C. Hide the capture toolchain (2 days)

**Shipped** (`30a6a8f`). Code: updated
`infra/guest/configure-capture.ps1`; matching defaults in
`guest_agent/config.py` and `guest_agent/capture/procmon.py`. The
ProcMon binary is invoked as `C:\Windows\System32\SystemAudit.exe`,
the scheduled task is named `Windows-PowerManagementAudit`, and the
workspace lives under
`C:\Users\<decoy>\AppData\Local\Microsoft\PowerManagement\`.

Target: defeat process/window/driver enumeration for analysis tools.

**Changes to `infra/guest/configure-capture.ps1`:**

- Copy `Procmon.exe` to `C:\Windows\System32\SystemAudit.exe`; only
  invoke it under that name. Drop the original.
- Run ProcMon with `/BackingFile` + `/Quiet` + `/Minimized` so the
  GUI window title never exists to enumerate.
- Move the scheduled task name from `SandGNATGuest` to
  `Windows-PowerManagementAudit` (innocuous, matches Windows naming).
- Stop mapping the SMB share to drive `Z:` — call it via UNC in the
  guest agent. Rationale: an unconnected drive letter is its own
  signal.
- Hide the `C:\sandgnat\` workspace by creating it as
  `C:\Users\$user\AppData\Local\Microsoft\PowerManagement\` instead.

**Known residual signal:** the ProcMon kernel driver
(`procmon23.sys`) is Microsoft-signed and embeds the name
`PROCMON23` in `SystemModuleInformation`. Renaming breaks the
signature. We accept this for now; phase G flags samples that
specifically enumerate it.

### D. Simulate an active user (1 week)

**Shipped** (`44ce4d5`). Code: `guest_agent/activity/` package —
`simulator.py` (lifecycle manager), `base.py` (threaded loop with
warmup gate), `mouse_jiggle.py`, `cursor_tour.py`,
`keyboard_noise.py`, `window_dance.py`, `winapi.py` (ctypes shim
with Linux no-ops for CI). Wired into `guest_agent/runner.py`
around `execute_sample`. Config via env vars
(`SANDGNAT_ACTIVITY_*`); see `docs/reference/configuration.md`.

Target: defeat §5 user-interaction checks.

**New: `guest_agent/activity/` package**, started as a subprocess by
`guest_agent/runner.py` at job-submit time and terminated after capture:

- `activity/mouse_jiggle.py` — `SendInput` every 20–60s with small
  random deltas. Runs in its own thread.
- `activity/cursor_tour.py` — every few minutes, moves the cursor to
  realistic targets: taskbar, a random desktop icon, a window corner.
  Adds an occasional left-click on an empty desktop area.
- `activity/keyboard_noise.py` — opens a hidden Notepad window,
  types random strings, closes.
- `activity/window_dance.py` — every 2–5 min, opens/closes one of a
  curated window set: Notepad, Calculator, File Explorer (to a
  realistic-looking folder).

All four loops reset `LastInputTime` as a side effect, which defeats
`GetLastInputInfo` probes automatically.

**Safety:** activity is *paused* for the first 30 seconds after sample
launch so a GUI-driven installer isn't clicked through before the
analyst's behavioural window opens. After that the simulator runs.

### E. Time-acceleration defence (2 weeks)

**Shipped** (`511a8f0` DLL source; `49ad29a` Python wiring). Code:
`guest_agent/stealth/sleep_patcher/` (C++ DLL with MinHook, built
separately on Windows — see that directory's README),
`guest_agent/stealth/injector.py` (CreateRemoteThread +
LoadLibraryW via ctypes), `guest_agent/stealth/log_parser.py`. The
Python injector is import-safe on Linux; the DLL is Windows-only
and ships as a build artefact next to the frozen agent.

Target: defeat sleep-based and RDTSC-based stalling.

**New: `guest_agent/stealth/sleep_patcher.exe`** — small C++ injector,
built once and shipped as a DLL inside the PyInstaller bundle. Uses
[MinHook](https://github.com/TsudaKageyu/minhook) to hook:

- `kernel32!Sleep`
- `kernel32!SleepEx`
- `ntdll!NtDelayExecution`
- `ntdll!NtWaitForSingleObject` (when called with a large timeout)

If the requested sleep exceeds 30 s, truncate to 2 s. Log each
patched call so the orchestrator can report "sleep-pattern evasion
observed" (§G).

**Runbook caveat:** Windows driver signing doesn't cover this — we're
hooking in user-land — so it works on Win10/11 22H2 without
modifications. Tested against known evasive samples (Emotet, TrickBot)
in the spec doc `docs/reference/sleep-patch-test-matrix.md` (also to
be written).

**RDTSC patching** is harder (kernel mode) and not in scope for this
phase. We document the limit.

### F. Network realism (1 week)

**Shipped** (`c593567`). Code: `infra/inetsim/` (new directory) —
`inetsim.conf` overrides, `dns-whitelist.txt` (~50 forwarded
domains), `netem.sh` (25ms ±10ms jitter + 0.1% loss qdisc),
`responses/` with the Microsoft NCSI / Apple captive-portal magic
strings. `infra/opnsense/README.md` updated to document the
split-DNS rule and shaping qdisc.

Target: defeat §7 network-fingerprint checks.

**Changes to `infra/opnsense/`:**

- Replace the default INetSim profile with a curated HTTP response set
  that varies by host+path. See `infra/inetsim/responses/` for the new
  fixtures.
- Permit DNS resolution (no TCP follow-up) for a whitelist of ~50
  "real-world" domains: `microsoft.com`, `google.com`,
  `windowsupdate.microsoft.com`, `time.windows.com`, etc. Answers are
  real recursive lookups through a pinned upstream resolver. No
  HTTP/HTTPS traffic to those hosts is allowed.
- Add a small `tc netem` profile on `vmbr.analysis`: 25 ms ± 10 ms
  jitter, 0.1% loss. Matches residential broadband.
- Return a plausible Microsoft NCSI response
  (`msftncsi.com/ncsi.txt` → `Microsoft NCSI`) so Windows thinks it
  has internet.

**Acceptance:** `curl -s https://www.msftncsi.com/ncsi.txt` returns
the right magic string; the "check for connectivity" popup never
appears on boot.

### G. Detect + record evasion attempts (1 week)

**Shipped** (`a2b2356` detector + rules; `49ad29a` sleep-patch
indicator). Code: `orchestrator/evasion_detector.py` (pure analyzer
over ProcMon events + StaticAnalysisRow + sleep_patcher.dll's
JSONL), `infra/yara/anti_vm.yar` (six rules tagged `anti_vm`
/ `anti_analysis` / `anti_debug`). Wired into
`tasks.analyze_malware_sample` between quarantine and
`update_job_status(COMPLETED)`; flips
`analysis_jobs.evasion_observed` and logs an `evasion_observed`
audit event on any hit.

Target: observe and flag when a sample is *trying* to detect us, even
if our mitigations worked.

**New: `orchestrator/evasion_detector.py`** — a post-run analyzer
that reads the ProcMon CSV + static-analysis envelope and flags any
of:

- CPUID instruction usage patterns (from capstone disassembly).
- Registry reads under `HKLM\HARDWARE\ACPI\DSDT`, `SystemBiosVersion`,
  `VideoBiosVersion`.
- File-exists checks for known VM artifacts (see §3 file-path list).
- Process-list enumeration calls (`CreateToolhelp32Snapshot` +
  `Process32First`) where one of the known analysis-tool names is
  string-compared.
- Long `Sleep()` imports with constants > 30 000 ms observed
  post-patch.
- `GetLastInputInfo` / `GetCursorPos` in a loop.

Each hit writes `evasion_observed = TRUE` on the `analysis_jobs` row
(column already exists from migration 001) plus a structured JSON
blob in `analysis_audit_log` with the specific indicator.

**YARA companion:** `infra/yara/anti_vm.yar` ships rules keyed on the
detection patterns above (both static strings and YARA-X
`vt.behaviour.*` equivalents). Loaded by the deep-scan stage.

This matters even when evasion succeeds — an analyst looking at a
detonation where `evasion_observed=TRUE` knows the sample *tried* to
hide, which is signal about its sophistication and origin.

---

## Dependencies & integration

| Phase | Touches | New dependency |
|-------|---------|----------------|
| A | `infra/proxmox/` (new) | Proxmox 8.0+ |
| B | `infra/guest/`, seed-data | None |
| C | `infra/guest/configure-capture.ps1` | None |
| D | `guest_agent/activity/` (new) | `pywin32` (already pulled) |
| E | `guest_agent/stealth/` (new), PyInstaller bundle | MinHook (vendored) |
| F | `infra/opnsense/`, `infra/inetsim/` (new) | `tc` on Proxmox host |
| G | `orchestrator/evasion_detector.py`, `infra/yara/anti_vm.yar` | None — `evasion_observed` column exists |

None of A–G breaks the existing staging/manifest protocol; the wire
schema stays at v2 and both guests are unchanged except for the
activity-simulator subprocess added by the Windows guest.

## Verification harness

Every phase is validated against three open-source test suites run
inside the template before and after the change:

- **[pafish](https://github.com/a0rtega/pafish)** — legacy, still the
  standard smoke test for VM detection.
- **[al-khaser](https://github.com/LordNoteworthy/al-khaser)** — the
  modern successor, covers more anti-sandbox tricks.
- **[VMDE](https://github.com/hfiref0x/VMDE)** — focuses on hardware
  and hypervisor detection.

Before Phase A: expect ~80% of checks to flag. After A+B+C: expect
<30%. After A+B+C+D+E+F: target <10%.

A curated corpus of 20 known-evasive real samples (Emotet,
TrickBot, Dridex variants known to sandbox-check) is the real
measure. Track detonation-to-completion rate per phase in
`docs/reference/evasion-test-matrix.md` (to be written alongside
each phase).

## Risks + explicit non-goals

- **Hypervisor-level detection via timing** (CPUID/RDTSC deltas) can
  always find a KVM with sufficient effort. We're defeating checks a
  typical commodity packer ships with, not research-grade anti-VM.
- **Activity simulation must not interfere with the sample**. 30 s
  quiet window at start plus an opt-out manifest field
  (`CaptureConfig.suppress_activity`) for known GUI samples.
- **Whitelist DNS is an exfil channel**. We only allow DNS (never the
  follow-up HTTP), so the worst case is 32-byte DNS-tunnel leaks.
  Measurable, rate-limited, acceptable.
- **Renaming signed drivers is out of scope.** We accept the
  `procmon23.sys` signal and detect-but-tolerate in phase G.
- **Phases E and F touch the analysis-network boundary.** Each has
  its own design-doc update before implementation per the
  CLAUDE.md "network isolation is non-negotiable" rule.

## Timing

Total calendar work: ~7 weeks if serial, ~3 weeks if A/B/C/F run in
parallel and D/E are sequential (which they must be — D's
subprocess lifecycle assumes E's hooks are installed first).

Dependencies on sign-off from the isolation-model reviewer: F, and
the DNS-whitelist change specifically. Everything else is
engineer-discretion.

## Implementation record

| Phase | Commit(s)           | Shipped artefacts                                      |
|-------|---------------------|--------------------------------------------------------|
| A     | `b37d8a7`           | `infra/proxmox/harden-template.sh` + README            |
| B     | `0c83008`           | `infra/guest/seed-user-profile.ps1` + seed-data/ + README updates |
| C     | `30a6a8f`           | `configure-capture.ps1` rewrite + guest_agent/config defaults |
| D     | `44ce4d5`           | `guest_agent/activity/` package + 15 tests             |
| E     | `511a8f0`, `49ad29a` | `guest_agent/stealth/sleep_patcher/` (C++ DLL) + `stealth/injector.py` + `stealth/log_parser.py` + 10 tests |
| F     | `c593567`           | `infra/inetsim/` (config + DNS whitelist + netem + responses) + OPNsense README |
| G     | `a2b2356`           | `orchestrator/evasion_detector.py` + `infra/yara/anti_vm.yar` + tasks.py wiring + 21 tests |

All seven phases landed on `claude/intake-service-vm-manager-Azqfw`
with the suite at 187/187 passing. Operator-facing runbook:
[how-to/bake-template-for-evasion](../how-to/bake-template-for-evasion.md).

