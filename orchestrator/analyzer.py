# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Turn guest artifacts into STIX objects and normalised DB rows.

The analyzer is the bridge between `guest_driver.ArtifactLocations` and
`persistence`. It's deliberately pure: no DB writes here, no Celery context,
no filesystem mutation beyond reading the artifact files. `tasks.py` is the
only module that turns an `AnalyzedBundle` into Postgres rows.

This keeps the module:
  - testable in isolation with on-disk fixture dirs,
  - re-runnable against an old completed/ directory during incident review,
  - decoupled from the parser internals — swap a parser, analyzer unchanged.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any
from uuid import UUID

from .guest_driver import ArtifactLocations
from .models import DroppedFile, NetworkIOC, RegistryModification
from .parsers.procmon import ProcmonEvent, parse_procmon_csv
from .parsers.regshot import RegistryDelta, parse_regshot_diff
from .stix_builder import (
    FileHashes,
    build_file,
    build_indicator,
    build_malware,
    build_network_traffic,
    build_process,
    stix_id,
)

log = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalyzedBundle:
    """Return value of `analyze()`: everything a Celery task needs to hand
    to `persistence` for a completed detonation."""

    stix_objects: list[dict[str, Any]] = field(default_factory=list)
    dropped_files: list[DroppedFile] = field(default_factory=list)
    registry_modifications: list[RegistryModification] = field(default_factory=list)
    network_iocs: list[NetworkIOC] = field(default_factory=list)


def analyze(
    *,
    analysis_id: UUID,
    sample_name: str,
    sample_sha256: str,
    sample_md5: str | None,
    artifacts: ArtifactLocations,
    quarantine_root: Path,
) -> AnalyzedBundle:
    """Produce an AnalyzedBundle from a guest's completed artifacts."""
    bundle = AnalyzedBundle()
    envelope = artifacts.envelope

    # --- Sample File + parent Malware --------------------------------------
    sample_file = build_file(
        analysis_id,
        name=sample_name,
        hashes=FileHashes(sha256=sample_sha256, md5=sample_md5),
    )
    bundle.stix_objects.append(sample_file)

    # --- Process objects from ProcMon --------------------------------------
    process_refs: dict[int, str] = {}  # pid -> STIX id
    dropped_by_pid: dict[int, list[str]] = {}  # pid -> dropper-written paths
    if artifacts.procmon_csv is not None:
        events = parse_procmon_csv(artifacts.procmon_csv)
        process_objs, dropped_by_pid = _build_process_objects(
            analysis_id=analysis_id,
            events=events,
            sample_sha256=sample_sha256,
            sample_binary_ref=sample_file["id"],
        )
        for obj in process_objs:
            bundle.stix_objects.append(obj)
            process_refs[obj["pid"]] = obj["id"]

    # --- Registry modifications + persistence Indicators -------------------
    if artifacts.regshot_diff is not None:
        deltas = parse_regshot_diff(artifacts.regshot_diff)
        for delta in deltas:
            bundle.registry_modifications.append(
                RegistryModification(
                    analysis_id=analysis_id,
                    action=delta.action,
                    hive=delta.hive,
                    key_path=delta.key_path,
                    value_name=delta.value_name,
                    value_data=delta.value_data,
                    persistence_indicator=delta.persistence_indicator,
                )
            )
        for indicator in _persistence_indicators(analysis_id, deltas):
            bundle.stix_objects.append(indicator)

    # --- Dropped files -----------------------------------------------------
    for dropped in envelope.dropped_files:
        if not dropped.sha256:
            # File was above max size; metadata only, no STIX observable.
            log.info(
                "Skipping oversized dropped file (no hash) for job %s: %s",
                analysis_id,
                dropped.original_path,
            )
            continue
        quarantine_path = _quarantine_path(
            quarantine_root, analysis_id, artifacts.workspace, dropped.relative_path
        )
        bundle.stix_objects.append(
            build_file(
                analysis_id,
                name=PureWindowsPath(dropped.original_path).name or dropped.sha256,
                hashes=FileHashes(sha256=dropped.sha256, md5=dropped.md5 or None),
                size=dropped.size_bytes,
                created_by_process_ref=process_refs.get(dropped.created_by_pid or -1),
                quarantine_path=str(quarantine_path) if quarantine_path else None,
                disposition="quarantined" if quarantine_path else None,
            )
        )
        bundle.dropped_files.append(
            DroppedFile(
                analysis_id=analysis_id,
                filename=PureWindowsPath(dropped.original_path).name or dropped.sha256,
                original_path=dropped.original_path,
                size_bytes=dropped.size_bytes,
                hash_sha256=dropped.sha256,
                hash_md5=dropped.md5 or None,
                quarantine_path=str(quarantine_path) if quarantine_path else None,
                verified=False,
                created_by_process_name=dropped.created_by_name,
                created_by_process_pid=dropped.created_by_pid,
            )
        )

    # --- Network traffic + IOCs -------------------------------------------
    if artifacts.pcap is not None:
        try:
            from .parsers.pcap import parse_pcap  # local import: optional dep
        except ImportError:
            log.warning("scapy not installed; skipping PCAP analysis")
        else:
            try:
                flows = parse_pcap(artifacts.pcap)
            except Exception:  # noqa: BLE001 — scapy can raise many things on bad pcaps
                log.exception("PCAP parse failed; continuing without network IOCs")
                flows = []
            for flow in flows:
                net_obj, iocs = _flow_to_stix_and_iocs(analysis_id, flow)
                bundle.stix_objects.append(net_obj)
                bundle.network_iocs.extend(iocs)

    # --- Parent Malware object (last, so object_refs is populated) ---------
    bundle.stix_objects.insert(
        0,
        build_malware(
            analysis_id,
            name=sample_name,
            sample_hash_sha256=sample_sha256,
            description=f"Runtime analysis: status={envelope.status}",
            object_refs=[o["id"] for o in bundle.stix_objects],
            confidence_level=_confidence_from_envelope(envelope, bundle),
        ),
    )
    return bundle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# ProcMon operation constants — see parsers.procmon.BEHAVIOURAL_OPERATIONS.
_WRITE_FILE_OPS = {"WriteFile"}
_PROCESS_CREATE_OPS = {"Process Create", "Process Start"}


def _build_process_objects(
    *,
    analysis_id: UUID,
    events: list[ProcmonEvent],
    sample_sha256: str,
    sample_binary_ref: str,
) -> tuple[list[dict[str, Any]], dict[int, list[str]]]:
    """Group ProcMon events by PID and emit one Process object per PID."""
    pids: dict[int, dict[str, Any]] = {}
    dropped_by_pid: dict[int, list[str]] = {}

    for ev in events:
        bucket = pids.setdefault(
            ev.pid,
            {"name": ev.process_name, "first_time": ev.time, "reg_mods": []},
        )
        if ev.operation == "RegSetValue":
            bucket["reg_mods"].append(
                {
                    "action": "set_value",
                    "key": ev.path,
                    "value_detail": ev.detail,
                }
            )
        elif ev.operation in _WRITE_FILE_OPS:
            dropped_by_pid.setdefault(ev.pid, []).append(ev.path)

    objects: list[dict[str, Any]] = []
    for pid, bucket in pids.items():
        obj = build_process(
            analysis_id,
            pid=pid,
            name=bucket["name"] or f"pid-{pid}",
            binary_ref=sample_binary_ref if bucket["name"].lower().endswith(".exe") else None,
            created_time=bucket["first_time"] or None,
            registry_modifications=bucket["reg_mods"],
        )
        objects.append(obj)
    return objects, dropped_by_pid


def _persistence_indicators(
    analysis_id: UUID, deltas: list[RegistryDelta]
) -> list[dict[str, Any]]:
    """One STIX Indicator per persistence-flagged registry delta."""
    indicators: list[dict[str, Any]] = []
    for delta in deltas:
        if not delta.persistence_indicator:
            continue
        # STIX pattern matches a windows-registry-key with the run-key path.
        # We escape single quotes in the key path to avoid breaking the pattern.
        full_key = f"{delta.hive}\\{delta.key_path}" if delta.hive else delta.key_path
        pattern = f"[windows-registry-key:key = '{full_key.replace(chr(39), chr(39)*2)}']"
        indicators.append(
            build_indicator(
                analysis_id,
                pattern=pattern,
                labels=["malicious-activity", "persistence"],
                kill_chain_phase="persistence",
                confidence_level=70,
            )
        )
    return indicators


def _flow_to_stix_and_iocs(
    analysis_id: UUID, flow: Any
) -> tuple[dict[str, Any], list[NetworkIOC]]:
    """Convert a `parsers.pcap.PcapFlow` into a network-traffic SCO + IOC rows."""
    src_ref = stix_id("ipv4-addr", analysis_id, flow.src_ip)
    dst_ref = stix_id("ipv4-addr", analysis_id, flow.dst_ip)
    obj = build_network_traffic(
        analysis_id,
        src_ref=src_ref,
        dst_ref=dst_ref,
        protocols=[flow.protocol],
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        start=_epoch_to_iso(flow.start),
        end=_epoch_to_iso(flow.end),
    )

    iocs: list[NetworkIOC] = []
    direction = _classify_direction(flow.src_ip, flow.dst_ip)
    # Only record non-private destination addresses as IOCs — internal chatter
    # between the guest and INetSim is not an indicator.
    if direction == "outbound" and not _is_private(flow.dst_ip):
        iocs.append(
            NetworkIOC(
                analysis_id=analysis_id,
                type="ipv4",
                indicator=flow.dst_ip,
                direction="outbound",
                protocol=flow.protocol,
                port=flow.dst_port,
                observed_at=datetime.fromtimestamp(flow.start, tz=timezone.utc),
                context=f"flow to {flow.dst_ip}:{flow.dst_port}",
            )
        )
    for qname in getattr(flow, "dns_queries", []):
        iocs.append(
            NetworkIOC(
                analysis_id=analysis_id,
                type="dns_query",
                indicator=qname,
                direction="outbound",
                protocol="dns",
                port=53,
                observed_at=datetime.fromtimestamp(flow.start, tz=timezone.utc),
                context="dns query",
            )
        )
    return obj, iocs


def _classify_direction(src: str, dst: str) -> str | None:
    try:
        if _is_private(src) and not _is_private(dst):
            return "outbound"
        if not _is_private(src) and _is_private(dst):
            return "inbound"
    except ValueError:
        return None
    return None


def _is_private(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def _epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _quarantine_path(
    quarantine_root: Path, analysis_id: UUID, workspace: Path, relative: str
) -> Path | None:
    if not relative:
        return None
    source = workspace / relative
    if not source.exists():
        return None
    # `relative` uses POSIX separators (`dropped/<sha>`), so Path is fine here
    # even on Windows — the staging share sees the same path in both directions.
    return quarantine_root / str(analysis_id) / Path(relative).name


def _confidence_from_envelope(envelope: Any, bundle: AnalyzedBundle) -> int:
    """Rough heuristic: more observed behaviours -> higher confidence."""
    score = 30
    if envelope.status == "completed":
        score += 10
    if any(r.persistence_indicator for r in bundle.registry_modifications):
        score += 25
    if bundle.dropped_files:
        score += 15
    if bundle.network_iocs:
        score += 15
    return min(score, 95)
