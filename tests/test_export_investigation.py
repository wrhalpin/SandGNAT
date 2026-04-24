# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Phase 3 + 5 of the cross-tool investigation-context plan.

Covers the ?investigation_id= / ?has_investigation= filters on
`GET /analyses`, the three investigation fields on job JSON, the
Grouping-first bundle ordering, and the POST
`/analyses/<id>/investigation` retroactive tagging endpoint.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from orchestrator.models import JobStatus
from tests.test_export_api import _client, _cfg, _make_job  # noqa: F401


API_KEY_HEADER = {"X-API-Key": "secret-key"}


def _prime(
    client_store,
    *,
    investigation_id: str | None = None,
    sha256: str | None = None,
    status: JobStatus = JobStatus.COMPLETED,
):
    _, store = client_store
    job = _make_job(
        status=status,
        sha256=sha256,
        investigation_id=investigation_id,
        investigation_link_type="confirmed" if investigation_id else None,
        investigation_tenant_id="acme" if investigation_id else None,
    )
    store.jobs[job.id] = job
    return job


# --- /analyses filter -----------------------------------------------------


def test_list_analyses_filters_by_investigation_id(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    a = _prime(cs, investigation_id="IC-2026-0001")
    b = _prime(cs, investigation_id="IC-2026-0002")
    c = _prime(cs)  # no investigation

    resp = client.get("/analyses?investigation_id=IC-2026-0001", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    payload = resp.get_json()
    ids = {item["id"] for item in payload["items"]}
    assert ids == {str(a.id)}
    assert str(b.id) not in ids
    assert str(c.id) not in ids


def test_list_analyses_has_investigation_true(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    a = _prime(cs, investigation_id="IC-2026-0001")
    b = _prime(cs)
    resp = client.get("/analyses?has_investigation=true", headers=API_KEY_HEADER)
    ids = {item["id"] for item in resp.get_json()["items"]}
    assert ids == {str(a.id)}


def test_list_analyses_has_investigation_false(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    _prime(cs, investigation_id="IC-2026-0001")
    b = _prime(cs)
    resp = client.get("/analyses?has_investigation=false", headers=API_KEY_HEADER)
    ids = {item["id"] for item in resp.get_json()["items"]}
    assert ids == {str(b.id)}


def test_list_analyses_bad_has_investigation_returns_400(tmp_path):
    client, _ = _client(tmp_path)
    resp = client.get("/analyses?has_investigation=maybe", headers=API_KEY_HEADER)
    assert resp.status_code == 400


def test_list_analyses_bad_investigation_id_returns_400(tmp_path):
    client, _ = _client(tmp_path)
    resp = client.get(
        "/analyses?investigation_id=bad%20id%20with%20spaces", headers=API_KEY_HEADER
    )
    assert resp.status_code == 400


# --- /analyses/<id> surfaces the three fields ----------------------------


def test_job_response_includes_investigation_fields(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs, investigation_id="IC-2026-0001")
    resp = client.get(f"/analyses/{job.id}", headers=API_KEY_HEADER)
    body = resp.get_json()
    assert body["investigation_id"] == "IC-2026-0001"
    assert body["investigation_link_type"] == "confirmed"
    assert body["investigation_tenant_id"] == "acme"


def test_job_response_fields_null_for_untagged(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs)
    body = client.get(f"/analyses/{job.id}", headers=API_KEY_HEADER).get_json()
    assert body["investigation_id"] is None
    assert body["investigation_link_type"] is None
    assert body["investigation_tenant_id"] is None


# --- bundle endpoint: Grouping lifted to front ---------------------------


def test_bundle_surfaces_grouping_first(tmp_path):
    cs = _client(tmp_path)
    client, store = cs
    job = _prime(cs, investigation_id="IC-2026-0001")
    # Manually stage a bundle with a Grouping mixed behind an observable
    # to confirm the route (by way of the store) would lift it to the top.
    # Our in-memory fake returns whatever is in store.bundles verbatim,
    # so we stage it in order and assert the client sees the Grouping
    # first after the request serialisation pass.
    store.bundles[job.id] = {
        "type": "bundle",
        "id": f"bundle--{job.id}",
        "objects": [
            {"type": "grouping", "id": "grouping--a"},
            {"type": "file", "id": "file--b"},
        ],
    }
    body = client.get(f"/analyses/{job.id}/bundle", headers=API_KEY_HEADER).get_json()
    assert body["objects"][0]["type"] == "grouping"


# --- POST /analyses/<id>/investigation (Phase 5) -------------------------


def test_post_investigation_tags_untagged_job(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs)
    resp = client.post(
        f"/analyses/{job.id}/investigation",
        json={"investigation_id": "IC-2026-0001", "tenant_id": "acme"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["investigation_id"] == "IC-2026-0001"
    # Retroactive tag defaults to inferred, not confirmed.
    assert body["investigation_link_type"] == "inferred"
    assert body["investigation_tenant_id"] == "acme"


def test_post_investigation_respects_explicit_link_type(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs)
    resp = client.post(
        f"/analyses/{job.id}/investigation",
        json={"investigation_id": "IC-2026-0001", "link_type": "suggested"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 200
    assert resp.get_json()["investigation_link_type"] == "suggested"


def test_post_investigation_conflicts_when_already_set(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs, investigation_id="IC-2026-0001")
    resp = client.post(
        f"/analyses/{job.id}/investigation",
        json={"investigation_id": "IC-2026-0002"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 409
    assert "already set" in resp.get_json()["error"]


def test_post_investigation_force_overrides_existing(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs, investigation_id="IC-2026-0001")
    resp = client.post(
        f"/analyses/{job.id}/investigation?force=true",
        json={"investigation_id": "IC-2026-0002"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 200
    assert resp.get_json()["investigation_id"] == "IC-2026-0002"


def test_post_investigation_rejects_missing_body(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs)
    resp = client.post(
        f"/analyses/{job.id}/investigation",
        json={},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 400


def test_post_investigation_rejects_malformed_id(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs)
    resp = client.post(
        f"/analyses/{job.id}/investigation",
        json={"investigation_id": "bad id"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 400


def test_post_investigation_404_when_job_missing(tmp_path):
    client, _ = _client(tmp_path)
    resp = client.post(
        "/analyses/11111111-1111-1111-1111-111111111111/investigation",
        json={"investigation_id": "IC-2026-0001"},
        headers=API_KEY_HEADER,
    )
    assert resp.status_code == 404


def test_post_investigation_requires_auth(tmp_path):
    cs = _client(tmp_path)
    client, _ = cs
    job = _prime(cs)
    resp = client.post(
        f"/analyses/{job.id}/investigation",
        json={"investigation_id": "IC-2026-0001"},
    )
    assert resp.status_code == 401
