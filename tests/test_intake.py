"""Tests for the intake pipeline.

The pipeline is exercised with in-memory fakes for the `JobStore` and
`Enqueuer` collaborators, so these tests run offline — no Postgres, no Redis,
no network. A fake VT client lets us drive the prioritisation logic through
all four branches (malicious / suspicious / unknown / error).
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from orchestrator.intake import (
    IntakeReport,
    hash_sample,
    ingest_submission,
    stage_sample_bytes,
)
from orchestrator.models import AnalysisJob, JobStatus
from orchestrator.vt_client import VTClient, VTVerdict
from orchestrator.yara_scanner import YaraMatch


SAMPLE_BYTES = b"MZ\x90\x00fake-pe-header" + b"A" * 256


class FakeStore:
    def __init__(self) -> None:
        self.jobs: dict[UUID, AnalysisJob] = {}
        self._by_sha256: dict[str, AnalysisJob] = {}

    def find_existing_job_by_sha256(self, sha256: str) -> AnalysisJob | None:
        return self._by_sha256.get(sha256)

    def insert_job(self, job: AnalysisJob) -> None:
        self.jobs[job.id] = job
        self._by_sha256[job.sample_hash_sha256] = job


class FakeEnqueuer:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(
        self,
        analysis_id: UUID,
        sample_name: str,
        sample_sha256: str,
        timeout_seconds: int,
        priority: int,
    ) -> None:
        self.calls.append(
            (analysis_id, sample_name, sample_sha256, timeout_seconds, priority)
        )


class FakeVT(VTClient):
    """VTClient subclass that skips HTTP entirely."""

    def __init__(self, verdict: VTVerdict) -> None:
        super().__init__(api_key="test-key")
        self._verdict = verdict

    def lookup_hash(self, sha256: str) -> VTVerdict:  # type: ignore[override]
        return self._verdict


class FakeYara:
    """Duck-types YaraScanner; no libyara dependency."""

    def __init__(self, matches: list[YaraMatch]) -> None:
        self._matches = matches
        self.enabled = True

    def scan_bytes(self, data: bytes) -> list[YaraMatch]:
        return self._matches


def _ingest(**overrides) -> tuple[IntakeReport, FakeStore, FakeEnqueuer]:
    store = overrides.pop("store", FakeStore())
    enq = overrides.pop("enqueue", FakeEnqueuer())
    kwargs = {
        "data": SAMPLE_BYTES,
        "sample_name": "evil.exe",
        "store": store,
        "enqueue": enq,
        "max_sample_bytes": 10 * 1024 * 1024,
        "min_sample_bytes": 16,
        "timeout_seconds": 120,
        **overrides,
    }
    data = kwargs.pop("data")
    report = ingest_submission(data, **kwargs)
    return report, store, enq


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_rejects_empty_submission() -> None:
    report, store, enq = _ingest(data=b"")
    assert report.decision == "rejected"
    assert "too small" in (report.rejection_reason or "")
    assert not store.jobs
    assert not enq.calls


def test_rejects_oversized_submission() -> None:
    report, store, _ = _ingest(data=b"A" * 2000, max_sample_bytes=1024)
    assert report.decision == "rejected"
    assert "too large" in (report.rejection_reason or "")
    assert not store.jobs


def test_sanitises_sample_name_strips_path_components() -> None:
    report, _, _ = _ingest(sample_name=r"..\..\windows\system32\evil.exe")
    # Path separators stripped, only filename retained
    assert report.sample_name == "evil.exe"


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def test_hash_sample_computes_all_three_hashes() -> None:
    h = hash_sample(b"hello")
    assert len(h.sha256) == 64
    assert len(h.sha1) == 40
    assert len(h.md5) == 32
    assert h.size_bytes == 5


# ---------------------------------------------------------------------------
# Dedupe
# ---------------------------------------------------------------------------

def test_duplicate_hash_short_circuits_enqueue() -> None:
    store = FakeStore()
    report_first, _, enq_first = _ingest(store=store, enqueue=FakeEnqueuer())
    assert report_first.decision in {"queued", "prioritized"}
    assert len(enq_first.calls) == 1

    # Same bytes on second submission -> duplicate.
    report_second, _, enq_second = _ingest(store=store, enqueue=FakeEnqueuer())
    assert report_second.decision == "duplicate"
    assert report_second.duplicate_of == report_first.analysis_id
    assert not enq_second.calls


def test_force_bypasses_duplicate_check() -> None:
    store = FakeStore()
    _first, _, _ = _ingest(store=store)
    second, _, enq = _ingest(store=store, force=True)
    assert second.decision in {"queued", "prioritized"}
    assert len(enq.calls) == 1


def test_duplicate_skipped_for_previously_failed_job() -> None:
    store = FakeStore()
    _first, _, _ = _ingest(store=store)
    # Flip status to FAILED: dedupe should let us re-submit.
    for job in store.jobs.values():
        job.status = JobStatus.FAILED
    report, _, enq = _ingest(store=store)
    assert report.decision in {"queued", "prioritized"}
    assert len(enq.calls) == 1


# ---------------------------------------------------------------------------
# VT + YARA prioritisation
# ---------------------------------------------------------------------------

def test_vt_malicious_bumps_priority() -> None:
    vt = FakeVT(VTVerdict(verdict="malicious", detection_count=45, total_engines=70))
    report, _, enq = _ingest(vt=vt, priority=5)
    assert report.decision == "prioritized"
    assert report.priority <= 2
    # Enqueue priority matches report priority
    assert enq.calls[0][4] == report.priority


def test_vt_unknown_preserves_caller_priority() -> None:
    vt = FakeVT(VTVerdict(verdict="unknown"))
    report, _, _ = _ingest(vt=vt, priority=5)
    assert report.decision == "queued"
    assert report.priority == 5


def test_yara_high_severity_bumps_priority() -> None:
    yara = FakeYara([YaraMatch(rule="EvilCorp_Stealer", tags=("stealer",))])
    report, store, _ = _ingest(yara=yara, priority=7)
    assert report.decision == "prioritized"
    assert report.priority <= 2
    job = next(iter(store.jobs.values()))
    assert job.yara_matches == ["EvilCorp_Stealer"]


def test_yara_advisory_match_does_not_promote() -> None:
    yara = FakeYara([YaraMatch(rule="Generic_Entropy_High", tags=("advisory",))])
    report, _, _ = _ingest(yara=yara, priority=5)
    assert report.decision == "queued"
    assert report.priority == 5


# ---------------------------------------------------------------------------
# Staging
# ---------------------------------------------------------------------------

def test_ingest_stages_bytes_when_staging_root_provided(tmp_path: Path) -> None:
    report, _, _ = _ingest(staging_root=tmp_path)
    assert report.decision in {"queued", "prioritized"}
    staged = tmp_path / "samples" / str(report.analysis_id) / "evil.exe"
    assert staged.exists()
    assert staged.read_bytes() == SAMPLE_BYTES


def test_stage_sample_bytes_is_atomic(tmp_path: Path) -> None:
    job_id = UUID("12345678-1234-5678-1234-567812345678")
    dest = stage_sample_bytes(tmp_path, job_id, "x.bin", b"content")
    assert dest.read_bytes() == b"content"
    # No leftover temp files.
    assert [p.name for p in dest.parent.iterdir()] == ["x.bin"]


# ---------------------------------------------------------------------------
# Report wiring
# ---------------------------------------------------------------------------

def test_job_row_carries_intake_metadata() -> None:
    vt = FakeVT(
        VTVerdict(verdict="suspicious", detection_count=3, total_engines=70)
    )
    report, store, _ = _ingest(vt=vt, submitter="analyst@example", priority=4)
    job = store.jobs[report.analysis_id]
    assert job.submitter == "analyst@example"
    assert job.vt_verdict == "suspicious"
    assert job.vt_detection_count == 3
    assert job.vt_total_engines == 70
    assert job.intake_decision in {"queued", "prioritized"}
    assert job.priority == report.priority


def test_priority_bounds_clamp_extremes() -> None:
    report, _, _ = _ingest(priority=99)
    assert 0 <= report.priority <= 9

    report, _, _ = _ingest(priority=-5)
    assert 0 <= report.priority <= 9
