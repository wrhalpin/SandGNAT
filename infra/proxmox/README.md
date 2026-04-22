<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
-->

# Proxmox template hardening

Phase A of the anti-analysis mitigation plan
(`docs/explanation/anti-analysis-evasion.md`). These scripts adjust a
Proxmox template's configuration so the VM looks like a physical Dell
workstation rather than an obvious KVM guest, before the clean snapshot
is taken.

**Scope:** hypervisor presence, SMBIOS, NIC model + OUI, disk model +
serial, machine/BIOS type. Guest-OS realism (users, recent files,
registry keys, installed apps) lives in Phase B and is driven from
`infra/guest/seed-user-profile.ps1`.

## Requirements

- Proxmox VE 8.0 or later. The `-hypervisor` machine arg and the
  `cpu host,hidden=1` combination we depend on both landed in Proxmox
  7.4 but only became stable on 8.
- Root shell on the Proxmox node (or any user allowed to run `qm`).
- Tools already present on a stock Proxmox node: `qm`, `uuidgen`,
  `openssl`, `awk`, `base64`.

## What the script changes, and why each one matters

Each row below maps to a `qm set` invocation in `harden-template.sh`.
The "Detected by" column lists the checks you'll see flip from red to
green in `pafish` / `al-khaser` after applying Phase A.

| Setting | Value | Detected by |
|---|---|---|
| `--cpu host,hidden=1` | Clears CPUID.1.ECX[31] (the "hypervisor present" bit) | `cpuid` intrinsic, `IsProcessorFeaturePresent` polyfills |
| `--args '-cpu host,kvm=off,-hypervisor,hv_vendor_id=GenuineIntel'` | Suppresses the CPUID 0x40000000 "KVMKVMKVM" leaf | Deeper cpuid sweeps, `Red Pill`-style detectors |
| `--smbios1 manufacturer=Dell Inc.,product=OptiPlex 7090,…` | SMBIOS table 1 reads as real Dell hardware | WMI `Win32_ComputerSystem`, `Win32_BIOS`, DMI parsing |
| `--net0 e1000e=00:14:22:XX:XX:XX,bridge=vmbr.analysis` | Dell OUI + emulated NIC instead of virtio | MAC prefix lookups, `Get-NetAdapter` driver desc |
| `--scsiN ...,serial=WD-WCASY7XXXX,ssd=1` | Realistic drive model and serial | `Get-PhysicalDisk`, `WMIC diskdrive`, IOCTL_STORAGE_QUERY_PROPERTY |
| `--machine q35` | q35 ACPI tables carry believable OEM IDs | ACPI table 0/1/2 inspection |
| `--bios ovmf` (if an efidisk is attached) | Removes the "SeaBIOS" string leak | DMI table 0 vendor |

## Usage

```bash
# Show what would run without touching the VM.
DRY_RUN=1 ./harden-template.sh 9000

# Harden template vmid 9000 (Windows detonation template).
./harden-template.sh 9000

# Harden template vmid 9001 (Linux static-analysis template) with a
# laptop SMBIOS profile.
./harden-template.sh 9001 --smbios-profile dell-latitude-5520
```

The VM must be **stopped** when the script runs — many of these options
are ignored or rejected while a guest is live. The script checks this
and aborts early if the template is running.

## When to run it

1. Build the template as normal (OS install, joins, prep scripts).
2. Shut the template down cleanly.
3. Run this script against it.
4. Start it once, run `pafish` (or `al-khaser`) inside, confirm the
   expected checks now pass.
5. Shut it down again and take the **clean snapshot** used by every
   linked clone.

After Phase A, expect `pafish` to still flag ~5 items (timing,
user-interaction, process environment) — those are Phases B–E.

## Idempotency and re-running

Every `qm set` is idempotent — re-running the script on an already-
hardened template overwrites the same keys with fresh random serials
and MACs. This is fine during development. Just re-snapshot afterwards
so linked clones inherit the updated config.

## Known limitations

- The script assumes a single primary disk on `--disk-bus scsi` (the
  SandGNAT convention) or `sata`. Additional disks keep their original
  model/serial strings. If you attach a secondary corpus disk for
  dropped-file collection, harden it the same way manually.
- `hv_vendor_id=GenuineIntel` ends up in Hyper-V enlightenment leaves
  only when Hyper-V flags are also enabled. If the template runs with
  `flags=+hv_*`, verify the spoofed vendor shows up in
  `Get-WmiObject Win32_Processor | Select Manufacturer`.
- OVMF switching is gated on the presence of an `efidisk` — without one
  the guest won't boot UEFI. Provision the efidisk before flipping the
  BIOS type.

## Verification

From the Proxmox host:

```bash
qm config 9000 | grep -E '^(cpu|args|smbios1|net0|scsi0|machine|bios):'
```

From inside the booted guest (Windows PowerShell):

```powershell
Get-WmiObject Win32_ComputerSystem | Select Manufacturer, Model
Get-WmiObject Win32_BIOS           | Select Manufacturer, SMBIOSBIOSVersion
Get-NetAdapter                     | Select Name, MacAddress, InterfaceDescription
Get-PhysicalDisk                   | Select FriendlyName, SerialNumber, MediaType
```

Expected: Dell Inc. / OptiPlex 7090 / e1000e / WD-prefixed serial.
Nothing should reference QEMU, VirtIO, or VBOX.
