#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
#
# Apply realistic broadband jitter + packet loss to vmbr.analysis.
# Phase F of the anti-analysis mitigation plan
# (docs/explanation/anti-analysis-evasion.md).
#
# Baseline INetSim replies in <1ms with 0% loss, which is obviously
# virtualised. Residential broadband is more like 25ms ±10ms with
# 0.1% loss — samples that time their own DNS or HTTP traffic will
# see a realistic shape with this applied.
#
# Run on the Proxmox host (not on any VM). Idempotent — re-running
# replaces the existing qdisc.
#
# Usage:
#   ./netem.sh              # apply defaults to vmbr.analysis
#   ./netem.sh vmbr5        # apply to a different bridge
#   ./netem.sh vmbr.analysis clear    # remove the qdisc

set -euo pipefail

IFACE="${1:-vmbr.analysis}"
ACTION="${2:-apply}"

# Defaults — tweak in place for geography-specific profiles.
DELAY_MS="${SANDGNAT_NETEM_DELAY:-25}"
JITTER_MS="${SANDGNAT_NETEM_JITTER:-10}"
LOSS_PCT="${SANDGNAT_NETEM_LOSS:-0.1}"
RATE="${SANDGNAT_NETEM_RATE:-100mbit}"

if ! command -v tc >/dev/null 2>&1; then
    echo "tc (iproute2) not installed" >&2
    exit 69
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "interface $IFACE not found" >&2
    exit 70
fi

case "$ACTION" in
    apply)
        # Replace rather than add so re-runs don't stack qdiscs.
        tc qdisc replace dev "$IFACE" root netem \
            delay "${DELAY_MS}ms" "${JITTER_MS}ms" distribution normal \
            loss "${LOSS_PCT}%" \
            rate "$RATE"
        echo "[netem] $IFACE: delay=${DELAY_MS}ms ±${JITTER_MS}ms, loss=${LOSS_PCT}%, rate=$RATE"
        ;;
    clear)
        tc qdisc del dev "$IFACE" root 2>/dev/null || true
        echo "[netem] $IFACE: qdisc removed"
        ;;
    *)
        echo "unknown action: $ACTION (use 'apply' or 'clear')" >&2
        exit 64
        ;;
esac
