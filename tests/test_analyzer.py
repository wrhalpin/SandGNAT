# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""End-to-end test of the analyzer against an on-disk fixture workspace.

We fabricate a completed/ directory with a ProcMon CSV, a RegShot diff, and
a dropped-files manifest, then verify the analyzer produces the expected
STIX objects and normalised rows.
"""

from __future__ import annotations

from dataclasses import replace
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


def test_analyze_without_investigation_id_produces_no_grouping(tmp_path: Path) -> None:
    """Acceptance criterion 4: untagged output is byte-identical to pre-change."""
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
    assert "grouping" not in types
    for obj in bundle.stix_objects:
        assert "x_gnat_investigation_id" not in obj


def test_analyze_with_investigation_stamps_every_object(tmp_path: Path) -> None:
    """Acceptance criterion 2: Grouping present + all objects stamped."""
    artifacts = _build_fixture(tmp_path)
    bundle = analyze(
        analysis_id=ANALYSIS_ID,
        sample_name="sample.exe",
        sample_sha256=SAMPLE_SHA,
        sample_md5=None,
        artifacts=artifacts,
        quarantine_root=tmp_path / "quarantine",
        investigation_id="IC-2026-0001",
        investigation_link_type="confirmed",
    )
    # First object is the Grouping (acceptance: "at the top of the bundle").
    assert bundle.stix_objects[0]["type"] == "grouping"
    assert bundle.stix_objects[0]["x_gnat_investigation_id"] == "IC-2026-0001"
    assert bundle.stix_objects[0]["x_gnat_investigation_origin"] == "sandgnat"
    # Every other object carries the three custom properties.
    for obj in bundle.stix_objects[1:]:
        assert obj["x_gnat_investigation_id"] == "IC-2026-0001"
        assert obj["x_gnat_investigation_origin"] == "sandgnat"
        assert obj["x_gnat_investigation_link_type"] == "confirmed"


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


def test_analyze_emits_ipv4_addr_scos_so_network_refs_resolve(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression: network-traffic SCOs must not reference ipv4-addr objects
    that are absent from the bundle (dangling src_ref/dst_ref => invalid graph)."""
    from orchestrator.parsers import pcap as pcap_mod
    from orchestrator.parsers.pcap import PcapFlow

    flow = PcapFlow(
        src_ip="192.168.100.50",
        dst_ip="93.184.216.34",
        src_port=51000,
        dst_port=443,
        protocol="tcp",
        start=1_700_000_000.0,
        end=1_700_000_001.0,
        packets=10,
        bytes_=4096,
        dns_queries=["example.com"],
    )
    monkeypatch.setattr(pcap_mod, "parse_pcap", lambda _path: [flow])

    artifacts = _build_fixture(tmp_path)
    artifacts = replace(artifacts, pcap=artifacts.workspace / "capture.pcap")

    bundle = analyze(
        analysis_id=ANALYSIS_ID,
        sample_name="sample.exe",
        sample_sha256=SAMPLE_SHA,
        sample_md5=None,
        artifacts=artifacts,
        quarantine_root=tmp_path / "quarantine",
    )

    objs_by_id = {o["id"]: o for o in bundle.stix_objects}
    net_objs = [o for o in bundle.stix_objects if o["type"] == "network-traffic"]
    assert net_objs, "expected a network-traffic SCO"
    for o in net_objs:
        assert o["src_ref"] in objs_by_id, "src_ref dangles"
        assert o["dst_ref"] in objs_by_id, "dst_ref dangles"
        assert objs_by_id[o["src_ref"]]["type"] == "ipv4-addr"
        assert objs_by_id[o["dst_ref"]]["type"] == "ipv4-addr"

    # One flow with two distinct endpoints => exactly two address SCOs (deduped).
    addrs = [o for o in bundle.stix_objects if o["type"] == "ipv4-addr"]
    assert len(addrs) == 2
    assert {a["value"] for a in addrs} == {"192.168.100.50", "93.184.216.34"}
