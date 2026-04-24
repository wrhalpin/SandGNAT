# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Phase 1 of the cross-tool investigation-context plan.

Validates that investigation_id / tenant_id / link_type flow through
intake, land on the AnalysisJob row, and round-trip via the
IntakeReport echo. The validator itself is also exercised here so a
malformed ID never reaches the persistence layer.
"""

from __future__ import annotations

import pytest

from orchestrator.intake import (
    InvestigationValidationError,
    validate_investigation_fields,
)
from tests.test_intake import FakeStore, FakeEnqueuer, SAMPLE_BYTES, _ingest


# --- validator ------------------------------------------------------------


def test_validator_accepts_well_formed_id():
    inv_id, tenant, link = validate_investigation_fields(
        "IC-2026-0001", "acme", "confirmed"
    )
    assert inv_id == "IC-2026-0001"
    assert tenant == "acme"
    assert link == "confirmed"


def test_validator_defaults_link_type_to_confirmed():
    _, _, link = validate_investigation_fields("IC-2026-0001", None, None)
    assert link == "confirmed"


def test_validator_returns_all_none_when_id_absent():
    # Tenant and link are ignored without a primary investigation_id.
    inv_id, tenant, link = validate_investigation_fields(None, "acme", "inferred")
    assert inv_id is None
    assert tenant is None
    assert link is None


def test_validator_rejects_oversize_id():
    with pytest.raises(InvestigationValidationError, match="128"):
        validate_investigation_fields("X" * 129, None, None)


def test_validator_rejects_bad_characters():
    with pytest.raises(InvestigationValidationError):
        validate_investigation_fields("IC 2026 0001", None, None)


def test_validator_rejects_unknown_link_type():
    with pytest.raises(InvestigationValidationError, match="link_type"):
        validate_investigation_fields("IC-2026-0001", None, "speculative")


def test_validator_rejects_oversize_tenant():
    with pytest.raises(InvestigationValidationError, match="tenant"):
        validate_investigation_fields("IC-2026-0001", "X" * 129, None)


# --- ingest_submission ---------------------------------------------------


def test_ingest_persists_investigation_fields_on_job():
    report, store, _ = _ingest(
        investigation_id="IC-2026-0042",
        investigation_tenant_id="acme-co",
        investigation_link_type="confirmed",
    )
    assert report.decision in {"queued", "prioritized"}
    assert report.investigation_id == "IC-2026-0042"
    assert report.investigation_link_type == "confirmed"
    assert report.investigation_tenant_id == "acme-co"

    job = store.jobs[report.analysis_id]
    assert job.investigation_id == "IC-2026-0042"
    assert job.investigation_link_type == "confirmed"
    assert job.investigation_tenant_id == "acme-co"


def test_ingest_without_investigation_is_unchanged():
    report, store, _ = _ingest()
    assert report.investigation_id is None
    assert report.investigation_link_type is None
    assert report.investigation_tenant_id is None
    job = store.jobs[report.analysis_id]
    assert job.investigation_id is None


def test_ingest_rejects_malformed_investigation_id():
    with pytest.raises(InvestigationValidationError):
        _ingest(investigation_id="spaces are bad")
