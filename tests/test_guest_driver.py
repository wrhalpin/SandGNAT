"""Tests for the host-side guest_driver.

These exercise the filesystem protocol (pending/, completed/, result.json)
without touching the actual Proxmox/Windows stack.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest

from orchestrator.guest_driver import (
    GuestDriverError,
    stage_sample,
    submit_job,
    wait_for_result,
)
from orchestrator.schema import (
    PROCMON_CSV,
    RESULT_FILENAME,
    SCHEMA_VERSION,
    ResultEnvelope,
)


ANALYSIS_ID = UUID("33333333-3333-3333-3333-333333333333")


def test_stage_sample_copies_and_hashes(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    source = tmp_path / "sample.exe"
    source.write_bytes(b"hello")
    staged_path, sha = stage_sample(staging, ANALYSIS_ID, source)
    assert staged_path.exists()
    assert staged_path.read_bytes() == b"hello"
    assert len(sha) == 64


def test_submit_job_writes_manifest(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    submit_job(
        staging,
        ANALYSIS_ID,
        sample_name="x.exe",
        sample_sha256="d" * 64,
        timeout_seconds=60,
    )
    pending = staging / "pending" / f"{ANALYSIS_ID}.json"
    assert pending.exists()
    payload = json.loads(pending.read_text())
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["sample_sha256"] == "d" * 64
    assert payload["timeout_seconds"] == 60


def test_wait_for_result_reads_envelope(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    workspace = staging / "completed" / str(ANALYSIS_ID)
    workspace.mkdir(parents=True)
    (workspace / PROCMON_CSV).write_text("")  # create one recognised artifact
    envelope = ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id=str(ANALYSIS_ID),
        status="completed",
        started_at="2026-04-17T12:00:00.000000Z",
        completed_at="2026-04-17T12:01:00.000000Z",
        execution_duration_seconds=60.0,
        sample_pid=42,
        sample_exit_code=0,
        timed_out=False,
    )
    (workspace / RESULT_FILENAME).write_text(envelope.to_json())

    artifacts = wait_for_result(staging, ANALYSIS_ID, timeout_seconds=5, poll_interval=0.05)
    assert artifacts.envelope.status == "completed"
    assert artifacts.procmon_csv is not None
    assert artifacts.pcap is None  # not written in this test


def test_wait_for_result_times_out(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    (staging / "completed" / str(ANALYSIS_ID)).mkdir(parents=True)
    with pytest.raises(GuestDriverError):
        wait_for_result(staging, ANALYSIS_ID, timeout_seconds=0.3, poll_interval=0.05)
