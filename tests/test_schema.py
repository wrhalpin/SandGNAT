"""Round-trip tests for the shared wire schema."""

from __future__ import annotations

import json

import pytest

from orchestrator.schema import (
    SCHEMA_VERSION,
    CaptureConfig,
    CaptureOutcome,
    DroppedFileRecord,
    JobManifest,
    ResultEnvelope,
    guest_sample_path,
    staging_subpath,
)


def _sample_manifest() -> JobManifest:
    return JobManifest(
        schema_version=SCHEMA_VERSION,
        job_id="11111111-1111-1111-1111-111111111111",
        sample_sha256="a" * 64,
        sample_guest_path=r"C:\sandgnat\11111111-1111-1111-1111-111111111111\sample.exe",
        sample_name="sample.exe",
        arguments=["--run"],
        timeout_seconds=120,
        capture=CaptureConfig(tshark=False),
    )


def test_manifest_roundtrip() -> None:
    original = _sample_manifest()
    parsed = JobManifest.from_json(original.to_json())
    assert parsed == original


def test_manifest_rejects_wrong_schema_version() -> None:
    payload = json.loads(_sample_manifest().to_json())
    payload["schema_version"] = 999
    with pytest.raises(ValueError):
        JobManifest.from_json(json.dumps(payload))


def test_envelope_roundtrip_with_children() -> None:
    env = ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id="22222222-2222-2222-2222-222222222222",
        status="completed",
        started_at="2026-04-17T12:00:00.000000Z",
        completed_at="2026-04-17T12:02:00.000000Z",
        execution_duration_seconds=120.5,
        sample_pid=1234,
        sample_exit_code=0,
        timed_out=False,
        captures=[CaptureOutcome(tool="procmon", started=True, stopped_cleanly=True)],
        dropped_files=[
            DroppedFileRecord(
                sha256="b" * 64,
                md5="c" * 32,
                size_bytes=1024,
                original_path=r"C:\Users\Analyst\AppData\Roaming\payload.dll",
                relative_path="dropped/" + "b" * 64,
                created_by_pid=1234,
                created_by_name="sample.exe",
            )
        ],
    )
    parsed = ResultEnvelope.from_json(env.to_json())
    assert parsed == env
    assert parsed.captures[0].tool == "procmon"
    assert parsed.dropped_files[0].sha256 == "b" * 64


def test_guest_sample_path_is_windows_style() -> None:
    p = guest_sample_path("job-1", "sample.exe")
    assert p.startswith("C:\\sandgnat\\")
    assert p.endswith("sample.exe")


def test_staging_subpath_rejects_unknown_kinds() -> None:
    assert staging_subpath("pending", "job-1").parts == ("pending", "job-1")
    with pytest.raises(ValueError):
        staging_subpath("bogus", "job-1")
