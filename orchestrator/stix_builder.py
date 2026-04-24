# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""STIX 2.1 object factories.

All STIX objects persisted by SandGNAT pass through this module. IDs are
deterministic UUIDv5s keyed on `(analysis_id, type, natural_key)` so re-ingest
is idempotent — reprocessing the same artifacts produces the same STIX IDs
instead of duplicate rows.

The `x_analysis_metadata` extension links every object back to an analysis job
for query locality. It is required on every STIX object we create.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import UUID, uuid5

# Deterministic namespace for SandGNAT STIX IDs. Treat as a constant; changing
# it breaks idempotency.
SANDGNAT_NS = UUID("4f6e7d1c-3e8b-5b6e-9a23-7a1b6c2d8e4f")

ISO_Z = "%Y-%m-%dT%H:%M:%S.%fZ"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime(ISO_Z)


def stix_id(stix_type: str, analysis_id: UUID, natural_key: str) -> str:
    """Return a deterministic STIX ID for `(analysis_id, type, natural_key)`."""
    raw = f"{analysis_id}|{stix_type}|{natural_key}"
    return f"{stix_type}--{uuid5(SANDGNAT_NS, raw)}"


def analysis_metadata(
    analysis_id: UUID,
    *,
    sample_hash_sha256: str | None = None,
    vm_uuid: UUID | None = None,
    tools_used: Iterable[str] = (),
    confidence_level: int | None = None,
    notes: str | None = None,
    execution_duration_seconds: int | None = None,
) -> dict[str, Any]:
    """Return the `x_analysis_metadata` extension block."""
    meta: dict[str, Any] = {
        "analysis_id": str(analysis_id),
        "analysis_timestamp": _now_iso(),
        "tools_used": sorted(set(tools_used)),
        "network_isolation": True,
    }
    if sample_hash_sha256:
        meta["sample_hash_sha256"] = sample_hash_sha256
    if vm_uuid:
        meta["vm_uuid"] = str(vm_uuid)
    if confidence_level is not None:
        meta["analyst_confidence_level"] = int(confidence_level)
    if notes:
        meta["notes"] = notes
    if execution_duration_seconds is not None:
        meta["execution_duration_seconds"] = int(execution_duration_seconds)
    return meta


@dataclass(frozen=True)
class FileHashes:
    """Container for everything we know that identifies a file.

    SHA-256 is required; everything else is optional. `as_stix()` serialises
    into the STIX `file.hashes` vocabulary.
    """

    sha256: str
    md5: str | None = None
    sha1: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None
    imphash: str | None = None

    def as_stix(self) -> dict[str, str]:
        """Serialise into a STIX 2.1 `file.hashes`-compatible dict.

        SSDEEP and TLSH are in the standard `hash-algorithm-ov`; imphash is
        not, so it's emitted as the `x_imphash` extension key.
        """
        # SSDEEP and TLSH are part of the STIX 2.1 hash-algorithm-ov; imphash
        # isn't, so it goes into an `x_`-prefixed extension key (still valid
        # JSON inside the file.hashes dict).
        out: dict[str, str] = {"SHA-256": self.sha256}
        if self.md5:
            out["MD5"] = self.md5
        if self.sha1:
            out["SHA-1"] = self.sha1
        if self.ssdeep:
            out["SSDEEP"] = self.ssdeep
        if self.tlsh:
            out["TLSH"] = self.tlsh
        if self.imphash:
            out["x_imphash"] = self.imphash
        return out


def build_malware(
    analysis_id: UUID,
    *,
    name: str,
    sample_hash_sha256: str,
    malware_types: Iterable[str] = ("unknown",),
    description: str | None = None,
    object_refs: Iterable[str] = (),
    confidence_level: int | None = None,
) -> dict[str, Any]:
    """Build a STIX 2.1 `malware` SDO wrapping one analysis.

    The id is derived from `(analysis_id, sample_hash_sha256)` so re-ingest
    produces the same object. `object_refs` should be every SCO + indicator
    the analyzer produced for this job.
    """
    now = _now_iso()
    obj: dict[str, Any] = {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id("malware", analysis_id, sample_hash_sha256),
        "created": now,
        "modified": now,
        "name": name,
        "malware_types": sorted(set(malware_types)) or ["unknown"],
        "is_family": False,
        "labels": ["malware"],
        "object_refs": list(object_refs),
        "x_analysis_metadata": analysis_metadata(
            analysis_id,
            sample_hash_sha256=sample_hash_sha256,
            confidence_level=confidence_level,
        ),
    }
    if description:
        obj["description"] = description
    return obj


def build_file(
    analysis_id: UUID,
    *,
    name: str,
    hashes: FileHashes,
    size: int | None = None,
    mime_type: str | None = None,
    created_by_process_ref: str | None = None,
    quarantine_path: str | None = None,
    disposition: str | None = None,
) -> dict[str, Any]:
    """Build a STIX 2.1 `file` SCO — for the sample itself or a dropped file.

    Natural key is the SHA-256, so two dropped files with identical bytes
    collapse to the same id. Use `created_by_process_ref` to link a dropped
    file back to the `process` that wrote it.
    """
    obj: dict[str, Any] = {
        "type": "file",
        "spec_version": "2.1",
        "id": stix_id("file", analysis_id, hashes.sha256),
        "hashes": hashes.as_stix(),
        "name": name,
        "x_analysis_metadata": analysis_metadata(analysis_id),
    }
    if size is not None:
        obj["size"] = int(size)
    if mime_type:
        obj["mime_type"] = mime_type
    if created_by_process_ref:
        obj["x_created_by_process_ref"] = created_by_process_ref
    if quarantine_path:
        obj["x_quarantine_path"] = quarantine_path
    if disposition:
        obj["x_artifact_disposition"] = disposition
    return obj


def build_process(
    analysis_id: UUID,
    *,
    pid: int,
    name: str,
    command_line: str | None = None,
    binary_ref: str | None = None,
    parent_ref: str | None = None,
    created_time: str | None = None,
    child_process_refs: Iterable[str] = (),
    registry_modifications: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Build a STIX 2.1 `process` SCO for one observed PID.

    One object per distinct PID, grouping its registry modifications and
    parent/child links. Registry-level detail is carried as an
    `x_registry_modifications` extension so consumers don't need to join
    the normalised `registry_modifications` table.
    """
    obj: dict[str, Any] = {
        "type": "process",
        "spec_version": "2.1",
        "id": stix_id("process", analysis_id, f"{pid}:{name}"),
        "pid": int(pid),
        "name": name,
        "x_analysis_metadata": analysis_metadata(analysis_id),
    }
    if command_line:
        obj["command_line"] = command_line
    if binary_ref:
        obj["binary_ref"] = binary_ref
    if parent_ref:
        obj["parent_ref"] = parent_ref
    if created_time:
        obj["created_time"] = created_time
    children = list(child_process_refs)
    if children:
        obj["x_child_process_refs"] = children
    regmods = list(registry_modifications)
    if regmods:
        obj["x_registry_modifications"] = regmods
    return obj


def build_network_traffic(
    analysis_id: UUID,
    *,
    src_ref: str,
    dst_ref: str,
    protocols: Iterable[str],
    src_port: int | None = None,
    dst_port: int | None = None,
    start: str | None = None,
    end: str | None = None,
    http_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a STIX 2.1 `network-traffic` SCO for one PCAP-derived flow.

    `src_ref`/`dst_ref` must already be `ipv4-addr`/`ipv6-addr`/`domain-name`
    SCO ids emitted alongside this object. HTTP headers (if recovered by
    the PCAP parser) travel as `x_http_headers`.
    """
    natural_key = f"{src_ref}->{dst_ref}:{dst_port}@{start}"
    obj: dict[str, Any] = {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": stix_id("network-traffic", analysis_id, natural_key),
        "protocols": sorted(set(protocols)),
        "src_ref": src_ref,
        "dst_ref": dst_ref,
        "x_analysis_metadata": analysis_metadata(analysis_id),
    }
    if src_port is not None:
        obj["src_port"] = int(src_port)
    if dst_port is not None:
        obj["dst_port"] = int(dst_port)
    if start:
        obj["start"] = start
    if end:
        obj["end"] = end
    if http_headers:
        obj["x_http_headers"] = dict(http_headers)
    return obj


def build_indicator(
    analysis_id: UUID,
    *,
    pattern: str,
    labels: Iterable[str] = ("malicious-activity",),
    kill_chain_phase: str | None = None,
    confidence_level: int | None = None,
    observable_refs: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a STIX 2.1 `indicator` SDO around a STIX pattern.

    Emitted for persistence-flagged registry keys and confirmed network
    IOCs. `observable_refs` links the indicator to the SCOs it matches via
    the `x_observable_refs` extension.
    """
    now = _now_iso()
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id("indicator", analysis_id, pattern),
        "created": now,
        "modified": now,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "labels": sorted(set(labels)),
        "x_analysis_metadata": analysis_metadata(
            analysis_id, confidence_level=confidence_level
        ),
    }
    if kill_chain_phase:
        obj["kill_chain_phases"] = [
            {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": kill_chain_phase}
        ]
    refs = list(observable_refs)
    if refs:
        obj["x_observable_refs"] = refs
    return obj


def build_bundle(objects: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Wrap objects in a STIX 2.1 Bundle envelope."""
    bundle_objects = list(objects)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid5(SANDGNAT_NS, json.dumps([o['id'] for o in bundle_objects], sort_keys=True))}",
        "objects": bundle_objects,
    }


# ---------------------------------------------------------------------------
# Cross-tool investigation context (GNAT-o-sphere).
#
# Canonical spec: wrhalpin/GNAT repo,
#   docs/reference/investigation-context-schema.md
#
# Three custom properties travel on every SandGNAT object that was produced
# under a GNAT investigation, plus on a wrapping Grouping. Objects emitted
# from untagged analyses look byte-identical to the pre-context output.
# ---------------------------------------------------------------------------

INVESTIGATION_ORIGIN_SANDGNAT = "sandgnat"

VALID_LINK_TYPES = frozenset({"confirmed", "inferred", "suggested"})


def apply_investigation_context(
    stix_obj: dict[str, Any],
    investigation_id: str | None,
    link_type: str = "confirmed",
) -> dict[str, Any]:
    """Stamp the three `x_gnat_investigation_*` properties on `stix_obj`.

    If `investigation_id` is falsy, the object is returned unchanged.
    Mutates and returns the same dict for caller convenience.
    """
    if not investigation_id:
        return stix_obj
    if link_type not in VALID_LINK_TYPES:
        raise ValueError(
            f"invalid link_type {link_type!r}; expected one of "
            f"{sorted(VALID_LINK_TYPES)}"
        )
    stix_obj["x_gnat_investigation_id"] = investigation_id
    stix_obj["x_gnat_investigation_origin"] = INVESTIGATION_ORIGIN_SANDGNAT
    stix_obj["x_gnat_investigation_link_type"] = link_type
    return stix_obj


def stamp_objects_with_investigation(
    objects: Iterable[dict[str, Any]],
    investigation_id: str | None,
    link_type: str = "confirmed",
) -> list[dict[str, Any]]:
    """Apply `apply_investigation_context` to every object in `objects`.

    A no-op passthrough (still returns a list) when `investigation_id` is
    None so callers don't need to branch.
    """
    materialised = list(objects)
    if not investigation_id:
        return materialised
    for obj in materialised:
        apply_investigation_context(obj, investigation_id, link_type)
    return materialised


def build_investigation_grouping(
    objects: Iterable[dict[str, Any]],
    analysis_id: UUID,
    investigation_id: str,
    link_type: str = "confirmed",
) -> dict[str, Any]:
    """Build a STIX 2.1 `Grouping` wrapping every object from one analysis.

    The Grouping carries the three `x_gnat_investigation_*` custom
    properties *and* so does each of its object_refs, so a consumer that
    only reads the Grouping still gets the full context block.
    """
    if not investigation_id:
        raise ValueError("investigation_id is required to build a Grouping")
    if link_type not in VALID_LINK_TYPES:
        raise ValueError(f"invalid link_type {link_type!r}")
    object_refs = [obj["id"] for obj in objects]
    grouping: dict[str, Any] = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": stix_id("grouping", analysis_id, f"investigation:{investigation_id}"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": f"SandGNAT analysis {analysis_id}",
        "context": "malware-analysis",
        "object_refs": object_refs,
        "x_analysis_metadata": analysis_metadata(analysis_id),
    }
    apply_investigation_context(grouping, investigation_id, link_type)
    return grouping
