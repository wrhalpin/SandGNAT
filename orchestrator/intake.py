# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Sample intake pipeline.

Turns a raw byte buffer into either an enqueued `analysis_jobs` row or an
explicit rejection/deduplication report. The pipeline is:

    1. Size-bounds check (reject empty + reject too-large; stops DoS by upload).
    2. Hash the bytes (SHA-256 is the canonical sample identity; MD5 + SHA-1
       are computed alongside for legacy-tool interop and VT lookups).
    3. MIME sniff (best-effort; purely advisory — never rejects on type).
    4. Duplicate check against `analysis_jobs.sample_hash_sha256`.
       - If a prior analysis exists and is not failed, return a `duplicate`
         decision pointing at the existing job (no re-detonation).
       - Caller can pass `force=True` to bypass deduplication (re-analysis
         after a rule update, say).
    5. Optional VirusTotal hash lookup — never uploads; degrades to 'unknown'.
    6. Optional YARA scan of the bytes.
    7. Decide priority: high-confidence YARA or VT match bumps to 2;
       VT 'unknown' + no YARA stays at the submitted priority (default 5).
    8. Persist the job row with all intake metadata attached, then enqueue
       the Celery task.

This module deliberately takes injectable `JobStore` and `Enqueuer` callables
instead of importing `persistence` / `tasks` directly so unit tests can run
offline without Postgres or Redis.
"""

from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol
from uuid import UUID, uuid4

from .models import AnalysisJob, JobStatus
from .vt_client import VTClient, VTVerdict
from .yara_scanner import YaraMatch, YaraScanner

log = logging.getLogger(__name__)

MAX_SAMPLE_NAME_LEN = 255

# Cross-tool investigation context (migration 004). IDs are opaque to
# SandGNAT but we cap length + character set so a pathological value
# can't blow up the partial index on investigation_id.
MAX_INVESTIGATION_ID_LEN = 128
_INVESTIGATION_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]+$")
VALID_INVESTIGATION_LINK_TYPES = frozenset({"confirmed", "inferred", "suggested"})


class InvestigationValidationError(ValueError):
    """Raised when investigation_id / tenant_id / link_type fail validation."""


def validate_investigation_fields(
    investigation_id: str | None,
    investigation_tenant_id: str | None,
    investigation_link_type: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Validate the three optional investigation fields supplied at intake.

    Returns a normalised tuple `(id, tenant_id, link_type)`. If
    `investigation_id` is None, the tenant_id and link_type are
    ignored and returned as None so the downstream row stays clean.
    Raises `InvestigationValidationError` on any violation.
    """
    if not investigation_id:
        return (None, None, None)
    if len(investigation_id) > MAX_INVESTIGATION_ID_LEN:
        raise InvestigationValidationError(
            f"investigation_id exceeds {MAX_INVESTIGATION_ID_LEN} chars"
        )
    if not _INVESTIGATION_ID_RE.match(investigation_id):
        raise InvestigationValidationError(
            "investigation_id must match [A-Za-z0-9_.:-]+"
        )
    tenant = investigation_tenant_id or None
    if tenant is not None:
        if len(tenant) > MAX_INVESTIGATION_ID_LEN:
            raise InvestigationValidationError(
                f"investigation_tenant_id exceeds {MAX_INVESTIGATION_ID_LEN} chars"
            )
        if not _INVESTIGATION_ID_RE.match(tenant):
            raise InvestigationValidationError(
                "investigation_tenant_id must match [A-Za-z0-9_.:-]+"
            )
    link = investigation_link_type or "confirmed"
    if link not in VALID_INVESTIGATION_LINK_TYPES:
        raise InvestigationValidationError(
            "investigation_link_type must be one of "
            + ", ".join(sorted(VALID_INVESTIGATION_LINK_TYPES))
        )
    return (investigation_id, tenant, link)


@dataclass(frozen=True, slots=True)
class SampleHashes:
    """Hash triple + size for one submission. Canonical identity is SHA-256."""

    sha256: str
    md5: str
    sha1: str
    size_bytes: int


@dataclass(slots=True)
class IntakeReport:
    """Outcome of one intake submission.

    `decision` values:
      * 'queued'       — new row inserted, Celery task dispatched.
      * 'prioritized'  — same as queued, but bumped to high priority because
                         VT/YARA flagged it pre-detonation.
      * 'duplicate'    — hash already analysed; `duplicate_of` points at the
                         existing job_id. No new row inserted.
      * 'rejected'     — submission failed validation; `rejection_reason`
                         explains why. No row inserted.
    """

    decision: str
    sha256: str | None = None
    md5: str | None = None
    sha1: str | None = None
    size_bytes: int | None = None
    mime_type: str | None = None
    sample_name: str | None = None
    analysis_id: UUID | None = None
    duplicate_of: UUID | None = None
    rejection_reason: str | None = None
    vt_verdict: VTVerdict | None = None
    yara_matches: list[YaraMatch] = field(default_factory=list)
    priority: int = 5
    investigation_id: str | None = None
    investigation_link_type: str | None = None
    investigation_tenant_id: str | None = None


class JobStore(Protocol):
    """Subset of persistence needed by intake. Implemented in `persistence.py`."""

    def find_existing_job_by_sha256(self, sha256: str) -> AnalysisJob | None: ...

    def insert_job(self, job: AnalysisJob) -> None: ...


Enqueuer = Callable[[UUID, str, str, int, int], None]
"""Signature: (analysis_id, sample_name, sample_sha256, timeout_seconds, priority)."""


def hash_sample(data: bytes) -> SampleHashes:
    """Compute SHA-256 + MD5 + SHA-1 + size of a sample buffer.

    MD5 and SHA-1 are kept for IOC-sharing compatibility with older tooling;
    SHA-256 is the canonical identity used for dedupe and STIX IDs.
    """
    return SampleHashes(
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324 — MD5 is for IOC compatibility, not security
        sha1=hashlib.sha1(data).hexdigest(),  # noqa: S324 — ditto
        size_bytes=len(data),
    )


def sniff_mime(sample_name: str | None) -> str | None:
    """Best-effort MIME guess from the filename extension. Advisory only;
    never rejects a submission on type."""
    if not sample_name:
        return None
    mime, _ = mimetypes.guess_type(sample_name)
    return mime


def _sanitize_name(raw: str | None) -> str | None:
    if not raw:
        return None
    name = raw.strip().replace("\x00", "")
    if not name:
        return None
    # Strip any path components — never trust submitters with path syntax.
    name = name.replace("\\", "/").split("/")[-1]
    return name[:MAX_SAMPLE_NAME_LEN] or None


def _high_confidence_yara(matches: list[YaraMatch]) -> bool:
    """A YARA match is high-confidence if it carries a severity>=high meta or
    a well-known malware-family tag. Anything else is advisory only."""
    for m in matches:
        if m.meta and str(m.meta.get("severity", "")).lower() in {"high", "critical"}:
            return True
        if {"malware", "apt", "ransomware", "rat", "stealer"} & {t.lower() for t in m.tags}:
            return True
    return False


def _derive_priority(
    requested: int, vt: VTVerdict | None, yara_matches: list[YaraMatch]
) -> tuple[int, bool]:
    """Return (priority, was_prioritized). Lower number = higher priority."""
    promoted = False
    priority = max(0, min(9, requested))
    if vt and vt.is_known_malicious:
        priority = min(priority, 2)
        promoted = True
    if _high_confidence_yara(yara_matches):
        priority = min(priority, 2)
        promoted = True
    return priority, promoted


def stage_sample_bytes(
    staging_root: Path, analysis_id: UUID, sample_name: str, data: bytes
) -> Path:
    """Write `data` atomically to the canonical staging location.

    The Celery task reads from this path to verify the hash before publishing
    a manifest to the guest. Atomic rename keeps the file invisible until
    fully written, so the task can't accidentally detonate a partial file.
    """
    dest_dir = staging_root / "samples" / str(analysis_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / sample_name
    fd, tmp_name = tempfile.mkstemp(prefix=".intake-", dir=dest_dir)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_name, dest)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return dest


def ingest_submission(
    data: bytes,
    *,
    sample_name: str | None,
    store: JobStore,
    enqueue: Enqueuer,
    staging_root: Path | None = None,
    vt: VTClient | None = None,
    yara: YaraScanner | None = None,
    max_sample_bytes: int,
    min_sample_bytes: int,
    timeout_seconds: int,
    submitter: str | None = None,
    intake_source: str | None = None,
    priority: int = 5,
    force: bool = False,
    investigation_id: str | None = None,
    investigation_tenant_id: str | None = None,
    investigation_link_type: str | None = None,
) -> IntakeReport:
    """Validate, pre-classify, and enqueue a sample. See module docstring."""
    inv_id, inv_tenant, inv_link = validate_investigation_fields(
        investigation_id, investigation_tenant_id, investigation_link_type
    )
    clean_name = _sanitize_name(sample_name)

    if len(data) < min_sample_bytes:
        return IntakeReport(
            decision="rejected",
            sample_name=clean_name,
            rejection_reason=(
                f"sample too small: {len(data)} bytes < {min_sample_bytes} minimum"
            ),
        )
    if len(data) > max_sample_bytes:
        return IntakeReport(
            decision="rejected",
            sample_name=clean_name,
            size_bytes=len(data),
            rejection_reason=(
                f"sample too large: {len(data)} bytes > {max_sample_bytes} maximum"
            ),
        )

    hashes = hash_sample(data)
    mime = sniff_mime(clean_name)

    if not force:
        existing = store.find_existing_job_by_sha256(hashes.sha256)
        if existing is not None and existing.status != JobStatus.FAILED:
            return IntakeReport(
                decision="duplicate",
                sha256=hashes.sha256,
                md5=hashes.md5,
                sha1=hashes.sha1,
                size_bytes=hashes.size_bytes,
                mime_type=mime,
                sample_name=clean_name,
                analysis_id=existing.id,
                duplicate_of=existing.id,
            )

    vt_verdict = vt.lookup_hash(hashes.sha256) if vt and vt.enabled else None
    yara_matches = yara.scan_bytes(data) if yara and yara.enabled else []

    effective_priority, promoted = _derive_priority(priority, vt_verdict, yara_matches)
    decision = "prioritized" if promoted else "queued"

    job = AnalysisJob(
        id=uuid4(),
        sample_hash_sha256=hashes.sha256,
        sample_hash_md5=hashes.md5,
        sample_hash_sha1=hashes.sha1,
        sample_size_bytes=hashes.size_bytes,
        sample_name=clean_name,
        sample_mime_type=mime,
        status=JobStatus.QUEUED,
        submitter=submitter,
        intake_source=intake_source,
        intake_decision=decision,
        priority=effective_priority,
        timeout_seconds=timeout_seconds,
        vt_verdict=(vt_verdict.verdict if vt_verdict else None),
        vt_detection_count=(vt_verdict.detection_count if vt_verdict else None),
        vt_total_engines=(vt_verdict.total_engines if vt_verdict else None),
        vt_last_seen=(vt_verdict.last_seen if vt_verdict else None),
        yara_matches=[m.rule for m in yara_matches],
        investigation_id=inv_id,
        investigation_link_type=inv_link,
        investigation_tenant_id=inv_tenant,
    )
    effective_name = clean_name or f"{hashes.sha256}.bin"
    store.insert_job(job)
    if staging_root is not None:
        # Staging after insert means a failed write leaves the row behind for
        # janitor cleanup rather than a disembodied file with no DB pointer.
        stage_sample_bytes(staging_root, job.id, effective_name, data)
    enqueue(
        job.id,
        effective_name,
        hashes.sha256,
        timeout_seconds,
        effective_priority,
    )
    log.info(
        "Accepted sample job_id=%s sha256=%s decision=%s priority=%d",
        job.id,
        hashes.sha256,
        decision,
        effective_priority,
    )
    return IntakeReport(
        decision=decision,
        sha256=hashes.sha256,
        md5=hashes.md5,
        sha1=hashes.sha1,
        size_bytes=hashes.size_bytes,
        mime_type=mime,
        sample_name=clean_name,
        analysis_id=job.id,
        vt_verdict=vt_verdict,
        yara_matches=yara_matches,
        priority=effective_priority,
        investigation_id=inv_id,
        investigation_link_type=inv_link,
        investigation_tenant_id=inv_tenant,
    )
