# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for the STIX builder — no Postgres or Proxmox dependency."""

from __future__ import annotations

from uuid import UUID

from orchestrator.stix_builder import (
    FileHashes,
    build_file,
    build_indicator,
    build_malware,
    build_process,
    stix_id,
)


ANALYSIS_ID = UUID("11111111-1111-1111-1111-111111111111")


def test_stix_id_is_deterministic() -> None:
    a = stix_id("file", ANALYSIS_ID, "abc")
    b = stix_id("file", ANALYSIS_ID, "abc")
    assert a == b
    assert a.startswith("file--")


def test_stix_id_differs_per_analysis() -> None:
    other_analysis = UUID("22222222-2222-2222-2222-222222222222")
    assert stix_id("file", ANALYSIS_ID, "abc") != stix_id("file", other_analysis, "abc")


def test_build_file_required_fields() -> None:
    obj = build_file(
        ANALYSIS_ID,
        name="sample.exe",
        hashes=FileHashes(sha256="a" * 64, md5="b" * 32),
        size=1234,
    )
    assert obj["type"] == "file"
    assert obj["spec_version"] == "2.1"
    assert obj["hashes"]["SHA-256"] == "a" * 64
    assert obj["hashes"]["MD5"] == "b" * 32
    assert obj["size"] == 1234
    assert obj["x_analysis_metadata"]["analysis_id"] == str(ANALYSIS_ID)


def test_build_malware_links_object_refs() -> None:
    file_obj = build_file(
        ANALYSIS_ID, name="sample.exe", hashes=FileHashes(sha256="c" * 64)
    )
    malware = build_malware(
        ANALYSIS_ID,
        name="sample.exe",
        sample_hash_sha256="c" * 64,
        object_refs=[file_obj["id"]],
    )
    assert malware["type"] == "malware"
    assert malware["object_refs"] == [file_obj["id"]]
    assert malware["is_family"] is False


def test_build_process_optional_fields_omitted_when_empty() -> None:
    proc = build_process(ANALYSIS_ID, pid=1234, name="sample.exe")
    assert "x_child_process_refs" not in proc
    assert "x_registry_modifications" not in proc


def test_build_indicator_includes_pattern_type() -> None:
    indicator = build_indicator(
        ANALYSIS_ID,
        pattern="[file:hashes.'SHA-256' = 'd']",
        kill_chain_phase="persistence",
    )
    assert indicator["pattern_type"] == "stix"
    assert indicator["kill_chain_phases"][0]["phase_name"] == "persistence"
