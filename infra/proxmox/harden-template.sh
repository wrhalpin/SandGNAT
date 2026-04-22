#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
#
# harden-template.sh — anti-analysis hardening for a SandGNAT template VM.
#
# Defeats the cheapest tier of VM-detection checks commodity malware runs
# before unpacking: CPUID hypervisor bit + KVM vendor string, SMBIOS
# manufacturer/product, virtualised disk/NIC model strings, and MAC OUIs
# that match "QEMU" or "VirtualBox" out of the box.
#
# Run ONCE per template vmid, on the Proxmox host, while the template is
# stopped. Take the clean snapshot afterwards — linked clones inherit the
# hardened config. Safe to re-run: every qm set is idempotent.
#
# Scope: Proxmox-level only. Guest-OS realism (users, recent files,
# registry artefacts) is Phase B. See
# docs/explanation/anti-analysis-evasion.md for the full plan.
#
# Requires: Proxmox VE 8.0+ (for the -hypervisor cpu feature), qm,
# uuidgen, openssl.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <vmid> [--nic-model e1000e|vmxnet3] [--disk-bus scsi|sata]
                  [--smbios-profile dell-optiplex-7090|dell-latitude-5520]
                  [--bridge <vmbrN>]

Hardens a stopped Proxmox template VM against VM-detection checks. Run
once per template before taking the clean snapshot.

Options:
  --nic-model       Emulated NIC model. Default: e1000e.
  --disk-bus        Disk bus the primary disk is attached to. Default:
                    scsi (matches sandgnat template convention).
  --smbios-profile  Preset SMBIOS vendor strings. Default:
                    dell-optiplex-7090.
  --bridge          Network bridge for the analysis NIC. Default:
                    vmbr.analysis.

Environment:
  DRY_RUN=1   Print the qm commands without running them.

Examples:
  $0 9000
  DRY_RUN=1 $0 9000 --nic-model vmxnet3 --bridge vmbr2
EOF
}

if [[ $# -lt 1 ]]; then
    usage >&2
    exit 64
fi

VMID="$1"; shift
NIC_MODEL="e1000e"
DISK_BUS="scsi"
SMBIOS_PROFILE="dell-optiplex-7090"
BRIDGE="vmbr.analysis"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nic-model) NIC_MODEL="$2"; shift 2;;
        --disk-bus) DISK_BUS="$2"; shift 2;;
        --smbios-profile) SMBIOS_PROFILE="$2"; shift 2;;
        --bridge) BRIDGE="$2"; shift 2;;
        -h|--help) usage; exit 0;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 64;;
    esac
done

if ! [[ "$VMID" =~ ^[0-9]+$ ]]; then
    echo "vmid must be numeric, got: $VMID" >&2
    exit 64
fi

case "$NIC_MODEL" in
    e1000e|vmxnet3) ;;
    *) echo "unsupported --nic-model: $NIC_MODEL (use e1000e or vmxnet3)" >&2; exit 64;;
esac

case "$DISK_BUS" in
    scsi|sata) ;;
    *) echo "unsupported --disk-bus: $DISK_BUS (use scsi or sata)" >&2; exit 64;;
esac

log() { printf '[harden %s] %s\n' "$VMID" "$*"; }
run() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        printf '  [dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 69; }
}
need qm
need uuidgen
need openssl

# 1. Preconditions — template must exist and be stopped.
if ! qm status "$VMID" >/dev/null 2>&1; then
    echo "vmid $VMID not found on this Proxmox node" >&2
    exit 70
fi

STATUS=$(qm status "$VMID" | awk '{print $2}')
if [[ "$STATUS" != "stopped" ]]; then
    echo "vmid $VMID is '$STATUS'; stop it with 'qm stop $VMID' before hardening" >&2
    exit 71
fi

# 2. CPU — hide the KVM hypervisor bit and vendor string.
#
# --cpu host,hidden=1 clears the CPUID.1.ECX[31] hypervisor bit that a
# naive `cpuid` / RDTSC check keys off of. The -hypervisor args flag
# removes the second layer (CPUID.40000000H "KVMKVMKVM" leaf) that
# sophisticated checks fall back to. hv_vendor_id spoofs it in case any
# leaf survives. kvm=off is retained for belt-and-braces; on Proxmox 8
# hidden=1 already implies it but older guests still key on the legacy
# string.
log "hiding hypervisor CPUID leaves"
run qm set "$VMID" --cpu "host,hidden=1,flags=+pcid"
run qm set "$VMID" --args '-cpu host,kvm=off,-hypervisor,hv_vendor_id=GenuineIntel'

# 3. SMBIOS — look like real hardware.
#
# Proxmox smbios1 values are base64-encoded (safer than inline escaping —
# commas in vendor strings would break the key=value parser).
emit_smbios() {
    local manufacturer product version sku
    case "$SMBIOS_PROFILE" in
        dell-optiplex-7090)
            manufacturer="Dell Inc."
            product="OptiPlex 7090"
            version="1.0.0"
            sku="0A8C"
            ;;
        dell-latitude-5520)
            manufacturer="Dell Inc."
            product="Latitude 5520"
            version="1.14.0"
            sku="0A4B"
            ;;
        *)
            echo "unknown --smbios-profile: $SMBIOS_PROFILE" >&2; exit 64;;
    esac

    local serial
    serial=$(uuidgen | tr -d - | head -c 7 | tr 'a-f' 'A-F')
    local sys_uuid
    sys_uuid=$(uuidgen)

    local b64_manufacturer b64_product b64_version b64_serial b64_sku
    b64_manufacturer=$(printf '%s' "$manufacturer" | base64 -w0)
    b64_product=$(printf '%s' "$product" | base64 -w0)
    b64_version=$(printf '%s' "$version" | base64 -w0)
    b64_serial=$(printf '%s' "$serial" | base64 -w0)
    b64_sku=$(printf '%s' "$sku" | base64 -w0)

    printf 'base64=1,manufacturer=%s,product=%s,version=%s,serial=%s,uuid=%s,sku=%s' \
        "$b64_manufacturer" "$b64_product" "$b64_version" "$b64_serial" "$sys_uuid" "$b64_sku"
}

log "setting SMBIOS profile: $SMBIOS_PROFILE"
SMBIOS=$(emit_smbios)
run qm set "$VMID" --smbios1 "$SMBIOS"

# 4. NIC — swap virtio paravirtualised NIC for an emulated model, and
# pick a MAC from a real hardware OUI.
#
# Dell OUI 00:14:22 reads as "Dell Inc." in every OUI database (IEEE,
# Wireshark, macvendors.com). vmxnet3 is VMware's — legitimate for a
# corporate laptop running inside a VDI — and e1000e is Intel (the NIC
# embedded in every Dell OptiPlex). Both are less obviously virtualised
# than virtio.
random_dell_mac() {
    # Upper 3 octets = Dell OUI 00:14:22. Lower 3 random.
    local lower
    lower=$(openssl rand -hex 3 | sed 's/\(..\)\(..\)\(..\)/\1:\2:\3/')
    printf '00:14:22:%s' "$lower"
}

MAC=$(random_dell_mac)
log "setting net0: model=$NIC_MODEL mac=$MAC bridge=$BRIDGE"
run qm set "$VMID" --net0 "$NIC_MODEL=$MAC,bridge=$BRIDGE,firewall=1"

# 5. Primary disk — force a realistic model + serial string.
#
# QEMU defaults to model="QEMU HARDDISK" / serial="QM00001", which is the
# #1 most-checked fingerprint after CPUID. A WD-style serial on a SSD-
# flagged disk reads as a consumer WD Blue SA510.
DISK_SERIAL="WD-WCASY7$(openssl rand -hex 4 | tr 'a-f' 'A-F')"
# Discover the current disk config string so we can preserve the
# storage:volume portion and just amend the opts.
CURRENT_DISK=$(qm config "$VMID" | awk -v bus="$DISK_BUS" -F'[: ]+' '$1 ~ "^"bus"[0-9]+$" {print $0; exit}' || true)

if [[ -z "$CURRENT_DISK" ]]; then
    echo "no $DISK_BUS disk attached to vmid $VMID; attach the primary disk before running hardening" >&2
    exit 72
fi

DISK_KEY=$(printf '%s' "$CURRENT_DISK" | awk -F: '{print $1}')
DISK_VOL=$(printf '%s' "$CURRENT_DISK" | sed -E "s/^${DISK_KEY}:\s*//")
DISK_VOLSPEC=$(printf '%s' "$DISK_VOL" | awk -F, '{print $1}')

log "setting $DISK_KEY serial=$DISK_SERIAL (ssd=1, model=WD Blue SA510 class)"
run qm set "$VMID" "--$DISK_KEY" \
    "$DISK_VOLSPEC,ssd=1,cache=none,discard=on,iothread=1,serial=$DISK_SERIAL"

# 6. Machine type — q35 exposes fewer legacy PC-isms than i440fx, but
# the bigger win is that recent q35 firmwares carry believable ACPI OEM
# IDs. Only set if not already q35.
CURRENT_MACHINE=$(qm config "$VMID" | awk '/^machine:/ {print $2}')
if [[ "$CURRENT_MACHINE" != q35* ]]; then
    log "switching machine type to q35"
    run qm set "$VMID" --machine q35
else
    log "machine type already q35 ($CURRENT_MACHINE), skipping"
fi

# 7. BIOS — OVMF (UEFI) matches modern OEM laptops; SeaBIOS legacy
# leaks "SeaBIOS" through DMI table 0. Only flip if no efidisk is
# attached yet, otherwise leave the operator to provision one.
CURRENT_BIOS=$(qm config "$VMID" | awk '/^bios:/ {print $2}')
HAS_EFIDISK=$(qm config "$VMID" | grep -c '^efidisk' || true)
if [[ "$CURRENT_BIOS" != "ovmf" && "$HAS_EFIDISK" -gt 0 ]]; then
    log "switching bios to ovmf"
    run qm set "$VMID" --bios ovmf
elif [[ "$CURRENT_BIOS" != "ovmf" ]]; then
    log "bios is '$CURRENT_BIOS' and no efidisk attached — leaving as-is"
    log "(add an efidisk and re-run with --bios ovmf manually if you want UEFI)"
fi

log "done. Take a clean snapshot before first linked-clone detonation."
log "verify inside the guest with pafish or al-khaser; see infra/proxmox/README.md."
