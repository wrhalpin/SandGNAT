<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
---
layout: default
title: Bake a template with evasion mitigations
description: Operator runbook for applying Phase A-F anti-analysis mitigations to a fresh Windows template before taking the clean snapshot.
---
-->

# Bake a Windows template with evasion mitigations

End-to-end runbook for applying Phases A–F of the
[anti-analysis mitigation plan](../explanation/anti-analysis-evasion.md)
to a fresh Windows template, in the right order, before taking the
clean snapshot every linked clone reverts to.

This is one of the more exacting operations in the SandGNAT lifecycle:
three of the six scripts happen on the **Proxmox host**, three on the
**guest VM**, and one script needs input from another. Run them in
this order.

## Prerequisites

- Proxmox VE 8.0 or later. The `-hypervisor` CPU feature we depend on
  in Phase A shipped in 7.4 but only became stable on 8.
- A freshly-installed Windows 10/11 x64 VM, fully patched, with FLARE-VM
  (or equivalent) installed.
- An efidisk attached to the VM if you want OVMF instead of SeaBIOS
  (recommended but not required).
- MinHook cloned into `guest_agent/stealth/sleep_patcher/third_party/minhook/`
  on your Windows build machine (only needed for Phase E).

## Overview

| Step | Phase | Where | Script                                      |
|------|-------|-------|---------------------------------------------|
| 1    | A     | Host  | `infra/proxmox/harden-template.sh`          |
| 2    | B     | Guest | `infra/guest/seed-user-profile.ps1`         |
| 3    | C     | Guest | `infra/guest/configure-capture.ps1`         |
| 4    | E     | Guest | Deploy `sleep_patcher.dll` next to agent    |
| 5    | F     | Host  | `infra/inetsim/netem.sh` (separate workflow)|
| 6    | —     | Proxmox | Take the clean snapshot                   |

Phase D (activity simulator) and Phase G (evasion detector) are
runtime components that don't touch the template. They pick up their
config from env vars set at detonation time.

## 1. Phase A — Proxmox template hardening

Shut the template down cleanly, then on the Proxmox host:

```bash
cd /path/to/SandGNAT/infra/proxmox
DRY_RUN=1 ./harden-template.sh 9000          # preview
./harden-template.sh 9000                    # apply
```

This rewrites the VM's CPU, SMBIOS, NIC model + MAC, and primary-disk
serial. See [`infra/proxmox/README.md`](../../infra/proxmox/README.md)
for flag-by-flag rationale.

**Verify** the Proxmox-side config:
```bash
qm config 9000 | grep -E '^(cpu|args|smbios1|net0|scsi0|machine|bios):'
```

Boot the template once and from a PowerShell:
```powershell
Get-WmiObject Win32_ComputerSystem | Select Manufacturer, Model
```
You should see "Dell Inc." / "OptiPlex 7090". Nothing should reference
QEMU, VirtIO, or VBOX.

## 2. Phase B — Seed the decoy user profile

Still in the running template, stage realistic content into
`infra/guest/seed-data/Documents/`, `Downloads/`, `Pictures/` on your
build host (see [that directory's README](../../infra/guest/seed-data/README.md)).
Then copy the whole `infra/guest/` tree into the template and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\seed-user-profile.ps1
```

Save the generated username and password from the script's final
output — you need the username for Phase C. Credentials are also
recorded in `C:\Users\<user>\profile.seed.json` for later reference.

By default the script installs LibreOffice, Chrome, 7-Zip, VLC,
Notepad++, Firefox, and Zoom via `winget`. Pass `-SkipAppInstall` if
you want to stage apps manually, or override
`-AppsToInstall "id1,id2,..."` for a different set.

## 3. Phase C — Configure capture with Phase-C renaming

Deploy the frozen guest agent to `C:\Tools\SandGNAT\sandgnat_guest_agent.exe`,
then run:

```powershell
.\configure-capture.ps1 `
    -OrchestratorHost 192.168.100.1 `
    -AgentExePath "C:\Tools\SandGNAT\sandgnat_guest_agent.exe" `
    -UserName emily.carter       # from Phase B
```

This relocates `Procmon.exe` to `C:\Windows\System32\SystemAudit.exe`
(deleting the original), registers the scheduled task as
`Windows-PowerManagementAudit`, and places the workspace under
`C:\Users\emily.carter\AppData\Local\Microsoft\PowerManagement\`.

**Verify**:
```powershell
schtasks /query /tn Windows-PowerManagementAudit /v
Test-Path C:\Windows\System32\SystemAudit.exe
Test-Path C:\Tools\Procmon                         # should be False
```

## 4. Phase E — Ship sleep_patcher.dll

Build the DLL on any Windows dev machine with MSVC x64:

```powershell
cd guest_agent\stealth\sleep_patcher
git clone --depth=1 https://github.com/TsudaKageyu/minhook.git third_party\minhook
cmake -S . -B build -A x64
cmake --build build --config Release
```

Copy `build\Release\sleep_patcher.dll` into the template next to the
frozen guest agent (i.e. `C:\Tools\SandGNAT\sleep_patcher.dll`). The
runner locates it automatically at detonation time via
`guest_agent/runner.py:_locate_sleep_patcher_dll`.

Override with `SANDGNAT_SLEEP_PATCHER_DLL=<absolute path>` if you need
a non-default location.

## 5. Phase F — Network realism (separate workflow)

Phase F is applied on the **Proxmox host** and the **INetSim VM**,
not the Windows template itself:

- Merge `infra/inetsim/inetsim.conf` into the INetSim VM's config.
- Sync `infra/inetsim/responses/` to the INetSim VM's wwwroot.
- Apply `infra/inetsim/netem.sh` to `vmbr.analysis` on the Proxmox
  host (run on boot via systemd).
- Update OPNsense to forward DNS for the domains in
  `infra/inetsim/dns-whitelist.txt` to your pinned upstream resolver.

See [`infra/inetsim/README.md`](../../infra/inetsim/README.md) for the
detailed setup.

## 6. Take the clean snapshot

Inside the template:

```powershell
# Clear captures + workspace so the snapshot boots into a known-empty state.
Remove-Item C:\Users\emily.carter\AppData\Local\Microsoft\PowerManagement\captures\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item C:\Users\emily.carter\AppData\Local\Microsoft\PowerManagement\* -Recurse -Force -Exclude "captures" -ErrorAction SilentlyContinue
```

Shut down cleanly from Proxmox, then:

```bash
qm snapshot 9000 clean
```

Every linked clone for analysis reverts to this snapshot.

## Validation against `pafish`

From a booted linked clone, run
[pafish](https://github.com/a0rtega/pafish) or
[al-khaser](https://github.com/LordNoteworthy/al-khaser). Expected
counts after Phases A–F:

| Check family                         | Before | After |
|--------------------------------------|-------:|------:|
| CPUID / hypervisor                   | 6      | 0     |
| SMBIOS / DMI vendor                  | 8      | 0     |
| MAC / NIC driver                     | 4      | 0     |
| VM artifact files                    | 12     | 0–2   |
| Installed apps / profile realism     | 10     | 0–3   |
| Sleep-based stalling                 | 3      | 0 (patched live) |
| Network connectivity probe           | 4      | 0     |
| **Total surviving checks**           | ~47    | <8    |

The residual ~5% is by design: some checks need kernel-mode hooks we
don't carry (RDTSC deltas, signed-driver enumeration). Phase G's
evasion detector surfaces every one of those as
`evasion_observed = TRUE` on the analysis row, so analysts see the
signal even when a mitigation couldn't fully suppress the tell.

## Troubleshooting

- **Autologon doesn't fire after reboot.** Re-run Phase B with
  `-UserName <existing-user>` to refresh the `DefaultPassword`
  registry entry; autologon uses plaintext creds in the registry.
- **`schtasks /query /tn Windows-PowerManagementAudit` says "not found".**
  Phase C didn't run, or it ran before the decoy user existed. Re-run
  Phase C with the correct `-UserName`.
- **Samples still sleep for minutes.** Confirm the DLL is beside the
  agent: `Test-Path C:\Tools\SandGNAT\sleep_patcher.dll`. Confirm
  injection logs are being written by inspecting the workspace for
  `sleep_patches.jsonl` after a detonation that should have
  triggered (build a minimal harness that calls `Sleep(60000)`).
- **NCSI flyout appears on boot.** Phase F INetSim overrides aren't
  applied — `curl.exe -sk https://www.msftncsi.com/ncsi.txt` should
  return the literal string `Microsoft NCSI`.
