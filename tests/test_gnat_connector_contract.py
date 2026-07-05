# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Contract tests for the gnat.connectors.sandgnat integration.

These pin the exact HTTP shapes and job-row keys that GNAT's SandGNAT
connector (gnat/connectors/sandgnat/client.py in wrhalpin/GNAT) reads.
The connector consumes everything via `.get(...)`, so a field rename on
our side wouldn't crash it — it would silently yield None. That's the
"silent break" these tests exist to catch: rename or drop a key the
connector depends on and one of these fails, pointing you at the GNAT
consumer before the integration quietly loses data.

If the connector legitimately changes what it reads, update the
CONNECTOR_* sets here in the same change.
"""

from __future__ import annotations

from orchestrator.export_api import _job_to_json
from tests.test_export_api import _client, _make_job

API_KEY = {"X-API-Key": "secret-key"}


# Keys the connector reads off an /analyses job row in
# SandGNATClient._to_stix_malware_analysis (+ _hashes). Mirror of the
# GNAT-side x_sandgnat block; keep in sync with that connector.
CONNECTOR_JOB_KEYS = frozenset(
    {
        "id",
        "sample_hash_sha256",
        "sample_hash_md5",
        "sample_name",
        "status",
        "vt_verdict",
        "vt_detection_count",
        "vt_total_engines",
        "evasion_observed",
        "yara_matches",
        "investigation_id",
        "imphash",
        "ssdeep",
        "tlsh",
        "started_at",
    }
)

# Filters the connector sends to GET /analyses (list_objects).
CONNECTOR_LIST_FILTERS = frozenset(
    {"sha256", "status", "since", "investigation_id", "has_investigation"}
)


# --- job-row key contract -------------------------------------------------


def test_job_json_emits_every_key_the_connector_reads() -> None:
    job = _make_job(
        investigation_id="IC-2026-0001",
        imphash="abc",
        ssdeep="96:x:y",
        tlsh="T1ABC",
        vt_verdict="malicious",
        vt_detection_count=42,
        vt_total_engines=70,
        evasion_observed=True,
    )
    payload = _job_to_json(job)
    missing = CONNECTOR_JOB_KEYS - payload.keys()
    assert not missing, f"job JSON dropped connector-required keys: {sorted(missing)}"


def test_job_json_yara_matches_is_a_list() -> None:
    # The connector does list(native.get("yara_matches") or []) — the read
    # side must be a list (of rule-name strings), not the /submit dict shape.
    job = _make_job(yara_matches=["EvilCorp_Stealer"])
    payload = _job_to_json(job)
    assert isinstance(payload["yara_matches"], list)
    assert all(isinstance(m, str) for m in payload["yara_matches"])


# --- endpoint shape contract ----------------------------------------------


def test_healthz_shape(tmp_path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json().get("status") == "ok"


def test_get_analysis_returns_job_dict(tmp_path) -> None:
    cs = _client(tmp_path)
    client, store = cs
    job = _make_job()
    store.jobs[job.id] = job
    resp = client.get(f"/analyses/{job.id}", headers=API_KEY)
    assert resp.status_code == 200
    body = resp.get_json()
    assert CONNECTOR_JOB_KEYS <= body.keys()


def test_list_analyses_returns_items_envelope(tmp_path) -> None:
    cs = _client(tmp_path)
    client, store = cs
    job = _make_job()
    store.jobs[job.id] = job
    resp = client.get("/analyses", headers=API_KEY)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "items" in body and isinstance(body["items"], list)
    assert CONNECTOR_JOB_KEYS <= body["items"][0].keys()


def test_list_analyses_accepts_every_connector_filter(tmp_path) -> None:
    cs = _client(tmp_path)
    client, store = cs
    job = _make_job(investigation_id="IC-2026-0001")
    store.jobs[job.id] = job
    # Each filter the connector may send must be accepted (not 400).
    params = {
        "sha256": "a" * 64,
        "status": "completed",
        "since": "2026-01-01T00:00:00Z",
        "investigation_id": "IC-2026-0001",
        "has_investigation": "true",
        "limit": 200,
        "offset": 0,
    }
    resp = client.get("/analyses", query_string=params, headers=API_KEY)
    assert resp.status_code == 200


def test_bundle_shape_is_bundle_with_objects(tmp_path) -> None:
    cs = _client(tmp_path)
    client, store = cs
    job = _make_job()  # COMPLETED
    store.jobs[job.id] = job
    store.bundles[job.id] = {
        "type": "bundle",
        "id": f"bundle--{job.id}",
        "objects": [{"type": "malware", "id": "malware--x"}],
    }
    resp = client.get(f"/analyses/{job.id}/bundle", headers=API_KEY)
    assert resp.status_code == 200
    body = resp.get_json()
    # Connector rejects anything whose type != "bundle".
    assert body["type"] == "bundle"
    assert isinstance(body["objects"], list)


def test_similar_returns_items_envelope(tmp_path) -> None:
    cs = _client(tmp_path)
    client, store = cs
    job = _make_job()
    store.jobs[job.id] = job
    resp = client.get(f"/analyses/{job.id}/similar", headers=API_KEY)
    assert resp.status_code == 200
    assert "items" in resp.get_json()


def test_investigation_tag_endpoint_exists(tmp_path) -> None:
    # The connector's only non-submit write: POST /analyses/<id>/investigation.
    cs = _client(tmp_path)
    client, store = cs
    job = _make_job()
    store.jobs[job.id] = job
    resp = client.post(
        f"/analyses/{job.id}/investigation",
        json={"investigation_id": "IC-2026-0001", "link_type": "inferred"},
        headers=API_KEY,
    )
    assert resp.status_code == 200
    assert resp.get_json()["investigation_id"] == "IC-2026-0001"
