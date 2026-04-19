# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Dataclasses mirroring the core Postgres tables.

These are transport objects between the orchestrator layers. They are
intentionally thin — the authoritative schema is `migrations/001_initial_schema.sql`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class JobStatus(StrEnum):
    """Lifecycle state of an `analysis_jobs` row. Transitions documented in
    `docs/reference/database-schema.md` (state-machine diagram)."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"


@dataclass(slots=True)
class AnalysisJob:
    """One row of `analysis_jobs` in Python form. Written by intake, read by
    every other layer. Phase-4 static-fingerprint fields at the bottom are
    populated by `tasks_static.static_analyze_sample`."""

    id: UUID
    sample_hash_sha256: str
    status: JobStatus
    sample_name: str | None = None
    sample_mime_type: str | None = None
    sample_hash_md5: str | None = None
    sample_hash_sha1: str | None = None
    sample_size_bytes: int | None = None
    submitted_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: int | None = None
    vm_uuid: UUID | None = None
    execution_command: str | None = None
    timeout_seconds: int = 300
    network_isolation: bool = True
    evasion_observed: bool = False
    analyst_notes: str | None = None
    result_summary: dict[str, Any] | None = None
    quarantine_path: str | None = None
    submitter: str | None = None
    intake_source: str | None = None
    intake_decision: str | None = None
    intake_notes: str | None = None
    priority: int = 5
    vt_verdict: str | None = None
    vt_detection_count: int | None = None
    vt_total_engines: int | None = None
    vt_last_seen: datetime | None = None
    yara_matches: list[str] = field(default_factory=list)
    # Static-analysis fingerprint fields (populated by Phase 4 static stage).
    imphash: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None
    static_completed_at: datetime | None = None
    near_duplicate_of: UUID | None = None
    near_duplicate_score: float | None = None


@dataclass(slots=True)
class VmLease:
    """One row of `vm_pool_leases`. The pool manager owns reads and writes;
    never construct one outside `persistence` or an in-memory test fake."""

    vmid: int
    node: str
    analysis_id: UUID | None
    status: str  # 'leased' | 'released' | 'orphaned'
    guest_type: str = "windows"  # 'windows' | 'linux'
    acquired_at: datetime | None = None
    heartbeat_at: datetime | None = None
    released_at: datetime | None = None


@dataclass(slots=True)
class StaticAnalysisRow:
    """Normalised view of one Linux-guest static-analysis result."""

    analysis_id: UUID
    file_format: str | None = None
    architecture: str | None = None
    entry_point: int | None = None
    is_packed_heuristic: bool | None = None
    section_count: int | None = None
    overall_entropy: float | None = None
    imports: dict[str, Any] | None = None
    exports: dict[str, Any] | None = None
    sections: list[dict[str, Any]] = field(default_factory=list)
    strings_summary: dict[str, Any] | None = None
    capa_capabilities: list[dict[str, Any]] = field(default_factory=list)
    deep_yara_matches: list[str] = field(default_factory=list)
    raw_envelope: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LineageEdge:
    """Parent/child relation between analyses. Emitted when the static-analysis
    short-circuit marks a submission as a near-duplicate of an earlier job."""

    child_analysis_id: UUID
    parent_analysis_id: UUID
    relation: str  # 'near_duplicate' | 'reanalysis' | 'manual_link'
    similarity_score: float | None = None


@dataclass(slots=True)
class SimilarityNeighbor:
    """One similar-sample hit returned by the /analyses/<id>/similar endpoint.

    Merges two data sources:
      * `sample_similarity` — LSH-cached pairwise edges from Phase 4.
      * `analysis_lineage` — explicit near-duplicate short-circuit parents.

    `relation` is 'near_duplicate' when the edge came from lineage (the
    scanner marked this as a clear duplicate), 'similar' when it came from
    the LSH similarity cache only.
    """

    analysis_id: UUID
    sample_sha256: str | None
    similarity: float
    flavour: str  # 'byte' | 'opcode'
    relation: str  # 'near_duplicate' | 'similar'


@dataclass(slots=True)
class DroppedFile:
    """One file dropped during detonation. Moved into quarantine after the
    analyzer emits its STIX observable."""

    analysis_id: UUID
    filename: str
    original_path: str
    size_bytes: int
    hash_sha256: str
    hash_md5: str | None = None
    quarantine_path: str | None = None
    verified: bool = False
    created_by_process_name: str | None = None
    created_by_process_pid: int | None = None


@dataclass(slots=True)
class RegistryModification:
    """One registry change observed by RegShot. `persistence_indicator` is
    True for classic Run-key / Winlogon / Services persistence locations."""

    analysis_id: UUID
    action: str  # 'added' | 'modified' | 'deleted'
    hive: str
    key_path: str
    value_name: str | None = None
    value_data: str | None = None
    value_type: str | None = None
    persistence_indicator: bool = False


@dataclass(slots=True)
class NetworkIOC:
    """One network indicator extracted from the PCAP: a resolved domain, a
    contacted IP, a DNS query, or an HTTP URL."""

    analysis_id: UUID
    type: str  # 'ipv4' | 'ipv6' | 'domain' | 'url' | 'dns_query'
    indicator: str
    direction: str | None = None  # 'inbound' | 'outbound'
    protocol: str | None = None
    port: int | None = None
    observed_at: datetime | None = None
    context: str | None = None
    confirmed_malicious: bool = False


@dataclass(slots=True)
class AuditEvent:
    """One entry in the append-only `analysis_audit_log`. Emitted at every
    meaningful lifecycle transition so operators can reconstruct a job."""

    analysis_id: UUID
    event_type: str
    details: dict[str, Any] = field(default_factory=dict)
    actor: str = "system"
