"""End-to-end test of the analyzer against an on-disk fixture workspace.

We fabricate a completed/ directory with a ProcMon CSV, a RegShot diff, and
a dropped-files manifest, then verify the analyzer produces the expected
STIX objects and normalised rows.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from orchestrator.analyzer import analyze
from orchestrator.guest_driver import ArtifactLocations
from orchestrator.schema import (
    PROCMON_CSV,
    REGSHOT_DIFF,
    SCHEMA_VERSION,
    DroppedFileRecord,
    ResultEnvelope,
)


ANALYSIS_ID = UUID("44444444-4444-4444-4444-444444444444")
SAMPLE_SHA = "e" * 64


PROCMON_FIXTURE = """\
"Time of Day","Process Name","PID","Operation","Path","Result","Detail"
"10:00:00.000","sample.exe","1234","RegSetValue","HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run","SUCCESS","Type: REG_SZ, Length: 10, Data: payload"
"10:00:00.100","sample.exe","1234","WriteFile","C:\\\\Users\\\\Analyst\\\\AppData\\\\Roaming\\\\payload.dll","SUCCESS","Offset: 0, Length: 4096"
"""

REGSHOT_FIXTURE = """\
Keys added: 1
----------------------------
HKLM\\Software\\Evil

Values added: 1
----------------------------
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware: "C:\\\\Users\\\\Analyst\\\\AppData\\\\Roaming\\\\payload.dll"
"""


def _build_fixture(tmp_path: Path) -> ArtifactLocations:
    workspace = tmp_path / "completed"
    workspace.mkdir()
    (workspace / PROCMON_CSV).write_text(PROCMON_FIXTURE)
    (workspace / REGSHOT_DIFF).write_text(REGSHOT_FIXTURE)

    dropped_dir = workspace / "dropped"
    dropped_dir.mkdir()
    (dropped_dir / ("f" * 64)).write_bytes(b"dropped-payload-bytes")

    envelope = ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id=str(ANALYSIS_ID),
        status="completed",
        started_at="2026-04-17T12:00:00.000000Z",
        completed_at="2026-04-17T12:01:00.000000Z",
        execution_duration_seconds=60.0,
        sample_pid=1234,
        sample_exit_code=0,
        timed_out=False,
        dropped_files=[
            DroppedFileRecord(
                sha256="f" * 64,
                md5="0" * 32,
                size_bytes=len(b"dropped-payload-bytes"),
                original_path=r"C:\Users\Analyst\AppData\Roaming\payload.dll",
                relative_path=f"dropped/{'f' * 64}",
                created_by_pid=1234,
                created_by_name="sample.exe",
            )
        ],
    )
    return ArtifactLocations(
        workspace=workspace,
        envelope=envelope,
        procmon_csv=workspace / PROCMON_CSV,
        pcap=None,
        regshot_diff=workspace / REGSHOT_DIFF,
        dropped_dir=dropped_dir,
    )


def test_analyze_produces_malware_file_process(tmp_path: Path) -> None:
    artifacts = _build_fixture(tmp_path)
    bundle = analyze(
        analysis_id=ANALYSIS_ID,
        sample_name="sample.exe",
        sample_sha256=SAMPLE_SHA,
        sample_md5=None,
        artifacts=artifacts,
        quarantine_root=tmp_path / "quarantine",
    )

    types = {o["type"] for o in bundle.stix_objects}
    assert "malware" in types
    assert "file" in types
    assert "process" in types
    assert "indicator" in types  # persistence Run-key indicator

    malware = next(o for o in bundle.stix_objects if o["type"] == "malware")
    # Malware must reference every other object in the bundle.
    other_ids = {o["id"] for o in bundle.stix_objects if o["id"] != malware["id"]}
    assert set(malware["object_refs"]) == other_ids


def test_analyze_records_dropped_file_row(tmp_path: Path) -> None:
    artifacts = _build_fixture(tmp_path)
    bundle = analyze(
        analysis_id=ANALYSIS_ID,
        sample_name="sample.exe",
        sample_sha256=SAMPLE_SHA,
        sample_md5=None,
        artifacts=artifacts,
        quarantine_root=tmp_path / "quarantine",
    )
    assert len(bundle.dropped_files) == 1
    row = bundle.dropped_files[0]
    assert row.hash_sha256 == "f" * 64
    assert row.created_by_process_pid == 1234
    assert row.filename == "payload.dll"


def test_analyze_flags_persistence_indicator(tmp_path: Path) -> None:
    artifacts = _build_fixture(tmp_path)
    bundle = analyze(
        analysis_id=ANALYSIS_ID,
        sample_name="sample.exe",
        sample_sha256=SAMPLE_SHA,
        sample_md5=None,
        artifacts=artifacts,
        quarantine_root=tmp_path / "quarantine",
    )
    indicators = [o for o in bundle.stix_objects if o["type"] == "indicator"]
    assert indicators
    assert any("persistence" in i["labels"] for i in indicators)

    # Normalised registry-modifications rows should also flag persistence.
    persistent_rows = [r for r in bundle.registry_modifications if r.persistence_indicator]
    assert persistent_rows
