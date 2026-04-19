# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for `orchestrator.static_analysis.parse_static_workspace`.

We fabricate a `completed/` workspace containing a static envelope JSON
plus binary trigram blobs, then verify the parser produces the expected
StaticAnalysisBundle / StaticAnalysisRow.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest

from orchestrator.schema import (
    STATIC_ANALYSIS_JSON,
    TRIGRAMS_BYTE_BIN,
    TRIGRAMS_OPCODE_BIN,
)
from orchestrator.static_analysis import parse_static_workspace
from orchestrator.trigrams import minhash_bytes


ANALYSIS_ID = UUID("55555555-5555-5555-5555-555555555555")


def _envelope_payload() -> dict:
    return {
        "sample_sha256": "f" * 64,
        "job_id": str(ANALYSIS_ID),
        "pe_elf": {
            "available": True,
            "skipped": False,
            "file_format": "pe64",
            "architecture": "x86_64",
            "entry_point": 0x1400,
            "is_packed_heuristic": True,
            "imphash": "deadbeefcafef00d" * 2,
            "sections": [
                {"name": ".text", "vsize": 4096, "rsize": 4096, "entropy": 7.4, "flags": ["EXECUTE", "READ"]},
                {"name": ".data", "vsize": 1024, "rsize": 1024, "entropy": 3.1, "flags": ["READ", "WRITE"]},
            ],
            "imports": {"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
            "exports": [],
        },
        "fuzzy": {
            "available": True,
            "ssdeep": "96:abc123:def456",
            "tlsh": "T1ABCDE" + "0" * 65,
        },
        "strings_summary": {"ascii_count": 12, "utf16_count": 3, "urls": [], "ips": []},
        "yara_matches": ["TestRule_Family_X"],
        "yara_detail": {"available": True, "skipped": False, "matches": []},
        "capa_capabilities": [
            {"rule": "execute payload", "namespace": "host-interaction", "scope": "function", "attack": []}
        ],
        "trigrams": {"byte_count": 5000, "opcode_count": 1500},
    }


def _build_workspace(tmp_path: Path, *, write_byte: bool = True, write_opcode: bool = True) -> Path:
    workspace = tmp_path / "completed"
    workspace.mkdir()
    (workspace / STATIC_ANALYSIS_JSON).write_text(json.dumps(_envelope_payload()))
    if write_byte:
        (workspace / TRIGRAMS_BYTE_BIN).write_bytes(minhash_bytes(b"x" * 1024).to_bytes())
    if write_opcode:
        (workspace / TRIGRAMS_OPCODE_BIN).write_bytes(minhash_bytes(b"y" * 1024).to_bytes())
    return workspace


def test_parse_returns_populated_bundle(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path)
    bundle = parse_static_workspace(analysis_id=ANALYSIS_ID, workspace=workspace)

    assert bundle.row.analysis_id == ANALYSIS_ID
    assert bundle.row.file_format == "pe64"
    assert bundle.row.architecture == "x86_64"
    assert bundle.row.is_packed_heuristic is True
    assert bundle.row.section_count == 2
    assert bundle.row.imports == {"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]}
    assert bundle.row.deep_yara_matches == ["TestRule_Family_X"]
    assert len(bundle.row.capa_capabilities) == 1

    assert bundle.imphash == "deadbeefcafef00d" * 2
    assert bundle.ssdeep == "96:abc123:def456"
    assert bundle.tlsh.startswith("T1ABCDE")

    assert bundle.byte_signature is not None
    assert bundle.byte_trigram_count == 5000
    assert bundle.opcode_signature is not None
    assert bundle.opcode_trigram_count == 1500


def test_parse_tolerates_missing_opcode_blob(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path, write_opcode=False)
    bundle = parse_static_workspace(analysis_id=ANALYSIS_ID, workspace=workspace)
    assert bundle.byte_signature is not None
    assert bundle.opcode_signature is None
    assert bundle.opcode_trigram_count == 0


def test_parse_raises_when_envelope_missing(tmp_path: Path) -> None:
    workspace = tmp_path / "completed"
    workspace.mkdir()
    with pytest.raises(FileNotFoundError):
        parse_static_workspace(analysis_id=ANALYSIS_ID, workspace=workspace)


def test_parse_size_weights_section_entropy(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path)
    bundle = parse_static_workspace(analysis_id=ANALYSIS_ID, workspace=workspace)
    # Size-weighted: (7.4*4096 + 3.1*1024) / 5120 ≈ 6.54
    assert bundle.row.overall_entropy is not None
    assert 6.4 < bundle.row.overall_entropy < 6.7
