"""End-to-end test for the Linux guest's static-analysis runner.

We feed in a fabricated 'sample' (just bytes on disk; static analysis
doesn't execute anything), drive the runner, and assert that:
  * a `static_analysis.json` envelope is written with the expected sections,
  * a `trigrams_byte.bin` MinHash blob is written and is the right size,
  * the `ResultEnvelope` carries `mode=static_analysis` + a populated
    `static_summary`.

This test runs offline — pefile / capa / yara aren't required. The tools
each report `available: False` or `skipped: True` when their underlying
deps are missing, and the runner still produces a valid envelope.
"""

from __future__ import annotations

import json
from pathlib import Path

from linux_guest_agent.config import LinuxGuestConfig
from linux_guest_agent.runner import run_static_job
from orchestrator.schema import (
    MODE_STATIC_ANALYSIS,
    SCHEMA_VERSION,
    STATIC_ANALYSIS_JSON,
    TRIGRAMS_BYTE_BIN,
    JobManifest,
    StaticAnalysisOptions,
)
from orchestrator.trigrams import NUM_PERMUTATIONS


def _config(tmp_path: Path) -> LinuxGuestConfig:
    return LinuxGuestConfig(
        staging_root=tmp_path / "staging",
        poll_interval=0.1,
        capa_exe="",  # disable capa — no binary to invoke
        yara_deep_rules_dir="",  # disable yara
        max_strings_bytes=64 * 1024,
    )


def _manifest(sample_path: Path, *, capa: bool = False, opcode: bool = False) -> JobManifest:
    return JobManifest(
        schema_version=SCHEMA_VERSION,
        job_id="abcdef01-2345-6789-abcd-ef0123456789",
        sample_sha256="d" * 64,
        sample_guest_path=str(sample_path),
        sample_name=sample_path.name,
        timeout_seconds=120,
        mode=MODE_STATIC_ANALYSIS,
        static=StaticAnalysisOptions(
            capa=capa,
            yara_deep=False,
            trigrams_opcode=opcode,
        ),
    )


def test_runner_produces_envelope_and_byte_signature(tmp_path: Path) -> None:
    sample = tmp_path / "fake.bin"
    sample.write_bytes(b"MZ\x90\x00" + b"\x90" * 256 + b"hello sandgnat" * 200)

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    cfg = _config(tmp_path)
    envelope = run_static_job(_manifest(sample), cfg, workspace)

    assert envelope.status == "completed"
    assert envelope.mode == MODE_STATIC_ANALYSIS
    assert envelope.static_summary is not None
    assert envelope.static_summary["yara_match_count"] == 0

    payload = json.loads((workspace / STATIC_ANALYSIS_JSON).read_text())
    assert "pe_elf" in payload
    assert "fuzzy" in payload
    assert "strings_summary" in payload
    assert "trigrams" in payload

    blob = (workspace / TRIGRAMS_BYTE_BIN).read_bytes()
    assert len(blob) == NUM_PERMUTATIONS * 4


def test_runner_handles_missing_sample(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    bogus = tmp_path / "does-not-exist.bin"
    envelope = run_static_job(_manifest(bogus), _config(tmp_path), workspace)
    assert envelope.status == "failed"
    assert any("missing" in e for e in envelope.errors)


def test_runner_writes_envelope_even_if_capa_disabled(tmp_path: Path) -> None:
    sample = tmp_path / "fake.bin"
    sample.write_bytes(b"\x7fELF" + b"A" * 1024)
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    envelope = run_static_job(_manifest(sample, capa=False), _config(tmp_path), workspace)
    assert envelope.status == "completed"
    payload = json.loads((workspace / STATIC_ANALYSIS_JSON).read_text())
    # CAPA was disabled in the manifest -> the section should not be present.
    assert "capa_capabilities" not in payload
