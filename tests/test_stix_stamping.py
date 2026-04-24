# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Phase 2 of the cross-tool investigation-context plan.

Covers the stamping helper + the investigation-Grouping factory in
`orchestrator.stix_builder`.
"""

from __future__ import annotations

import uuid

import pytest

from orchestrator.stix_builder import (
    INVESTIGATION_ORIGIN_SANDGNAT,
    apply_investigation_context,
    build_file,
    build_investigation_grouping,
    stamp_objects_with_investigation,
    FileHashes,
)


# --- apply_investigation_context ------------------------------------------


def test_apply_stamps_all_three_properties():
    analysis_id = uuid.uuid4()
    obj = build_file(
        analysis_id,
        name="sample.exe",
        hashes=FileHashes(sha256="a" * 64),
    )
    stamped = apply_investigation_context(obj, "IC-2026-0001", "confirmed")
    assert stamped is obj  # mutates in place
    assert obj["x_gnat_investigation_id"] == "IC-2026-0001"
    assert obj["x_gnat_investigation_origin"] == INVESTIGATION_ORIGIN_SANDGNAT
    assert obj["x_gnat_investigation_link_type"] == "confirmed"


def test_apply_is_noop_when_investigation_id_missing():
    analysis_id = uuid.uuid4()
    obj = build_file(
        analysis_id, name="sample.exe", hashes=FileHashes(sha256="a" * 64)
    )
    before = dict(obj)
    apply_investigation_context(obj, None)
    apply_investigation_context(obj, "")
    assert obj == before


def test_apply_rejects_invalid_link_type():
    obj = {"id": "file--x"}
    with pytest.raises(ValueError, match="link_type"):
        apply_investigation_context(obj, "IC-2026-0001", "speculative")


def test_stamp_objects_with_investigation_handles_multiple():
    objs = [{"id": f"file--{i}", "type": "file"} for i in range(3)]
    stamped = stamp_objects_with_investigation(objs, "IC-2026-0001", "inferred")
    # Each entry in the returned list is the same dict as the original
    # (mutated in place); the list wrapper may or may not be identical.
    assert len(stamped) == len(objs)
    for out, original in zip(stamped, objs):
        assert out is original
        assert out["x_gnat_investigation_id"] == "IC-2026-0001"
        assert out["x_gnat_investigation_link_type"] == "inferred"


def test_stamp_objects_is_noop_without_id():
    objs = [{"id": "file--x"}]
    before = [dict(o) for o in objs]
    result = stamp_objects_with_investigation(objs, None)
    assert result == before


# --- build_investigation_grouping ----------------------------------------


def test_grouping_wraps_all_object_refs():
    analysis_id = uuid.uuid4()
    objs = [{"id": f"file--{i}", "type": "file"} for i in range(4)]
    grouping = build_investigation_grouping(
        objs, analysis_id=analysis_id, investigation_id="IC-2026-0001"
    )
    assert grouping["type"] == "grouping"
    assert grouping["context"] == "malware-analysis"
    assert grouping["name"] == f"SandGNAT analysis {analysis_id}"
    assert grouping["object_refs"] == [o["id"] for o in objs]
    assert grouping["x_gnat_investigation_id"] == "IC-2026-0001"
    assert grouping["x_gnat_investigation_origin"] == INVESTIGATION_ORIGIN_SANDGNAT
    assert grouping["x_gnat_investigation_link_type"] == "confirmed"


def test_grouping_id_is_deterministic():
    analysis_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    objs = [{"id": "file--a"}]
    g1 = build_investigation_grouping(objs, analysis_id, "IC-2026-0001")
    g2 = build_investigation_grouping(objs, analysis_id, "IC-2026-0001")
    assert g1["id"] == g2["id"]


def test_grouping_requires_investigation_id():
    with pytest.raises(ValueError, match="investigation_id is required"):
        build_investigation_grouping([], uuid.uuid4(), "")


def test_grouping_rejects_invalid_link_type():
    with pytest.raises(ValueError):
        build_investigation_grouping(
            [], uuid.uuid4(), "IC-2026-0001", link_type="bogus"
        )
