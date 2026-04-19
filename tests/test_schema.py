# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Round-trip tests for the shared wire schema."""

from __future__ import annotations

import json

import pytest

from orchestrator.schema import (
    MODE_DETONATION,
    MODE_STATIC_ANALYSIS,
    SCHEMA_VERSION,
    CaptureConfig,
    CaptureOutcome,
    DroppedFileRecord,
    JobManifest,
    ResultEnvelope,
    StaticAnalysisOptions,
    guest_sample_path,
    linux_guest_sample_path,
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


def test_manifest_defaults_to_detonation_mode() -> None:
    manifest = _sample_manifest()
    assert manifest.mode == MODE_DETONATION
    assert isinstance(manifest.static, StaticAnalysisOptions)


def test_manifest_static_analysis_mode_roundtrip() -> None:
    manifest = JobManifest(
        schema_version=SCHEMA_VERSION,
        job_id="abcdef01-2345-6789-abcd-ef0123456789",
        sample_sha256="b" * 64,
        sample_guest_path=linux_guest_sample_path("abcdef01-2345-6789-abcd-ef0123456789", "x.elf"),
        sample_name="x.elf",
        timeout_seconds=240,
        mode=MODE_STATIC_ANALYSIS,
        static=StaticAnalysisOptions(capa=False, trigrams_opcode=False),
    )
    rebuilt = JobManifest.from_json(manifest.to_json())
    assert rebuilt == manifest
    assert rebuilt.mode == MODE_STATIC_ANALYSIS
    assert rebuilt.static.capa is False
    assert rebuilt.static.trigrams_opcode is False


def test_envelope_static_summary_roundtrip() -> None:
    env = ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id="abcdef01-2345-6789-abcd-ef0123456789",
        status="completed",
        started_at="2026-04-17T12:00:00.000000Z",
        completed_at="2026-04-17T12:00:30.000000Z",
        execution_duration_seconds=0.0,
        sample_pid=None,
        sample_exit_code=None,
        timed_out=False,
        mode=MODE_STATIC_ANALYSIS,
        static_summary={
            "file_format": "elf64",
            "imphash": None,
            "ssdeep": "96:abc:def",
            "yara_match_count": 2,
        },
    )
    rebuilt = ResultEnvelope.from_json(env.to_json())
    assert rebuilt == env
    assert rebuilt.static_summary["file_format"] == "elf64"


def test_linux_guest_sample_path_is_posix_style() -> None:
    p = linux_guest_sample_path("job-x", "sample.elf")
    assert p.startswith("/srv/sandgnat/samples/")
    assert p.endswith("sample.elf")
    assert "\\" not in p
