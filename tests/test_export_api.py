# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for the read-only export API.

We build the Flask app through `intake_api.create_app` so both the intake
and export blueprints are registered under the same auth — that's how a
real GNAT connector deployment will see them. All DB calls go through an
in-memory fake `_Store` with the shape the export blueprint expects; no
Postgres, no network, no Celery.
"""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from orchestrator.config import IntakeConfig
from orchestrator.intake_api import create_app
from orchestrator.models import (
    AnalysisJob,
    JobStatus,
    SimilarityNeighbor,
    StaticAnalysisRow,
)
from orchestrator.vt_client import VTClient, VTVerdict


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _Store:
    def __init__(self) -> None:
        self.jobs: dict[UUID, AnalysisJob] = {}
        self.static: dict[UUID, StaticAnalysisRow] = {}
        self.similar: dict[UUID, list[SimilarityNeighbor]] = {}
        self.bundles: dict[UUID, dict] = {}
        self._by_sha: dict[str, AnalysisJob] = {}

    # Intake-side surface (already exercised by test_intake_api.py).
    def find_existing_job_by_sha256(self, sha256: str) -> AnalysisJob | None:
        return self._by_sha.get(sha256)

    def insert_job(self, job: AnalysisJob) -> None:
        self.jobs[job.id] = job
        self._by_sha[job.sample_hash_sha256] = job

    def get_job(self, job_id: UUID) -> AnalysisJob | None:
        return self.jobs.get(job_id)

    # Export-side surface.
    def list_jobs(
        self,
        *,
        sha256: str | None = None,
        status: JobStatus | None = None,
        since: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AnalysisJob]:
        items = list(self.jobs.values())
        if sha256 is not None:
            items = [j for j in items if j.sample_hash_sha256 == sha256]
        if status is not None:
            items = [j for j in items if j.status == status]
        if since is not None:
            items = [
                j for j in items if j.submitted_at is not None and j.submitted_at >= since
            ]
        items.sort(
            key=lambda j: j.submitted_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        return items[offset : offset + limit]

    def get_static_analysis(self, analysis_id: UUID) -> StaticAnalysisRow | None:
        return self.static.get(analysis_id)

    def list_similar(
        self,
        analysis_id: UUID,
        *,
        threshold: float = 0.5,
        limit: int = 25,
        flavour: str = "either",
    ) -> list[SimilarityNeighbor]:
        items = [
            n
            for n in self.similar.get(analysis_id, [])
            if n.similarity >= threshold
            and (flavour == "either" or n.flavour == flavour)
        ]
        items.sort(key=lambda n: n.similarity, reverse=True)
        return items[:limit]

    def export_bundle(self, analysis_id: UUID) -> dict:
        return self.bundles.get(
            analysis_id, {"type": "bundle", "id": f"bundle--{analysis_id}", "objects": []}
        )


def _cfg(api_key: str = "secret-key") -> IntakeConfig:
    return IntakeConfig(
        max_sample_bytes=10 * 1024 * 1024,
        min_sample_bytes=16,
        api_key=api_key,
        bind_host="127.0.0.1",
        bind_port=0,
        yara_rules_dir="",
        vt_api_key="",
        vt_base_url="https://vt.example/api/v3",
        vt_timeout_seconds=1.0,
    )


class _StubVT(VTClient):
    def __init__(self) -> None:
        super().__init__(api_key="stub")

    def lookup_hash(self, sha256: str) -> VTVerdict:  # type: ignore[override]
        return VTVerdict(verdict="unknown")


def _client(tmp_path: Path, *, store: _Store | None = None):  # type: ignore[no-untyped-def]
    resolved_store = store or _Store()
    app = create_app(
        config=_cfg(),
        store=resolved_store,
        enqueue=lambda *a, **k: None,
        vt=_StubVT(),
        yara=None,
        staging_root=tmp_path / "staging",
        timeout_seconds=120,
    )
    app.testing = True
    return app.test_client(), resolved_store


def _make_job(
    status: JobStatus = JobStatus.COMPLETED,
    sha256: str | None = None,
    minutes_ago: int = 0,
    **overrides,
) -> AnalysisJob:  # type: ignore[no-untyped-def]
    now = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    kwargs: dict = dict(
        id=uuid4(),
        sample_hash_sha256=sha256 or ("a" * 64),
        sample_name="x.exe",
        status=status,
        submitted_at=now,
        sample_hash_md5="b" * 32,
        sample_hash_sha1="c" * 40,
        sample_size_bytes=1024,
    )
    kwargs.update(overrides)
    return AnalysisJob(**kwargs)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/analyses",
        "/analyses/11111111-1111-1111-1111-111111111111",
        "/analyses/11111111-1111-1111-1111-111111111111/bundle",
        "/analyses/11111111-1111-1111-1111-111111111111/static",
        "/analyses/11111111-1111-1111-1111-111111111111/similar",
    ],
)
def test_all_export_endpoints_require_api_key(tmp_path: Path, path: str) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(path)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /analyses
# ---------------------------------------------------------------------------


def test_list_analyses_returns_all_with_defaults(tmp_path: Path) -> None:
    store = _Store()
    for i in range(3):
        j = _make_job(minutes_ago=i)
        store.jobs[j.id] = j
    client, _ = _client(tmp_path, store=store)
    resp = client.get("/analyses", headers={"X-API-Key": "secret-key"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert len(body["items"]) == 3
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["count"] == 3


def test_list_analyses_filters_by_sha256(tmp_path: Path) -> None:
    store = _Store()
    wanted = _make_job(sha256="d" * 64)
    store.jobs[wanted.id] = wanted
    other = _make_job(sha256="e" * 64)
    store.jobs[other.id] = other
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        "/analyses", query_string={"sha256": "d" * 64},
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 200
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(wanted.id)


def test_list_analyses_filters_by_status(tmp_path: Path) -> None:
    store = _Store()
    store.jobs[uuid4()] = _make_job(status=JobStatus.COMPLETED)
    store.jobs[uuid4()] = _make_job(status=JobStatus.FAILED)
    store.jobs[uuid4()] = _make_job(status=JobStatus.RUNNING)
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        "/analyses", query_string={"status": "completed"},
        headers={"X-API-Key": "secret-key"},
    )
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0]["status"] == "completed"


def test_list_analyses_filters_by_since(tmp_path: Path) -> None:
    store = _Store()
    store.jobs[uuid4()] = _make_job(minutes_ago=120)  # too old
    recent = _make_job(minutes_ago=5)
    store.jobs[recent.id] = recent
    client, _ = _client(tmp_path, store=store)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    resp = client.get(
        "/analyses", query_string={"since": cutoff},
        headers={"X-API-Key": "secret-key"},
    )
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(recent.id)


def test_list_analyses_rejects_bad_sha256(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(
        "/analyses", query_string={"sha256": "NOT-HEX"},
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 400


def test_list_analyses_rejects_bad_status(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(
        "/analyses", query_string={"status": "quantum"},
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 400


def test_list_analyses_rejects_limit_over_max(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(
        "/analyses", query_string={"limit": "500"},
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 400


def test_list_analyses_rejects_negative_offset(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(
        "/analyses", query_string={"offset": "-1"},
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 400


def test_list_analyses_pagination(tmp_path: Path) -> None:
    store = _Store()
    for i in range(7):
        j = _make_job(minutes_ago=i)
        store.jobs[j.id] = j
    client, _ = _client(tmp_path, store=store)

    resp = client.get(
        "/analyses", query_string={"limit": "3", "offset": "0"},
        headers={"X-API-Key": "secret-key"},
    )
    first = resp.get_json()["items"]
    assert len(first) == 3

    resp = client.get(
        "/analyses", query_string={"limit": "3", "offset": "3"},
        headers={"X-API-Key": "secret-key"},
    )
    second = resp.get_json()["items"]
    assert len(second) == 3
    assert {j["id"] for j in first} & {j["id"] for j in second} == set()


# ---------------------------------------------------------------------------
# GET /analyses/<id>
# ---------------------------------------------------------------------------


def test_get_analysis_returns_job(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job()
    store.jobs[j.id] = j
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 200
    assert resp.get_json()["id"] == str(j.id)


def test_get_analysis_rejects_malformed_uuid(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get("/analyses/not-a-uuid", headers={"X-API-Key": "secret-key"})
    assert resp.status_code == 400


def test_get_analysis_returns_404_for_unknown(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(
        f"/analyses/{uuid4()}", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /analyses/<id>/bundle
# ---------------------------------------------------------------------------


def test_bundle_returns_stix_for_completed_job(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job(status=JobStatus.COMPLETED)
    store.jobs[j.id] = j
    store.bundles[j.id] = {
        "type": "bundle",
        "id": f"bundle--{j.id}",
        "spec_version": "2.1",
        "objects": [{"type": "malware", "id": "malware--00000000-0000-0000-0000-000000000001"}],
    }
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/bundle", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["type"] == "bundle"
    assert body["objects"][0]["type"] == "malware"


def test_bundle_409_when_not_completed(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job(status=JobStatus.RUNNING)
    store.jobs[j.id] = j
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/bundle", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 409
    assert resp.get_json()["status"] == "running"


def test_bundle_404_for_unknown(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(
        f"/analyses/{uuid4()}/bundle", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /analyses/<id>/static
# ---------------------------------------------------------------------------


def test_static_returns_row_with_fingerprint_from_job(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job(
        imphash="imphash123",
        ssdeep="96:abc:def",
        tlsh="T1ABCDE" + "0" * 65,
    )
    store.jobs[j.id] = j
    store.static[j.id] = StaticAnalysisRow(
        analysis_id=j.id,
        file_format="pe64",
        architecture="x86_64",
        entry_point=4096,
        is_packed_heuristic=False,
        section_count=4,
        overall_entropy=5.2,
        imports={"kernel32.dll": ["LoadLibraryA"]},
        exports=[],
        sections=[{"name": ".text", "entropy": 6.0}],
        strings_summary={"ascii_count": 12},
        capa_capabilities=[{"rule": "test"}],
        deep_yara_matches=["Demo_Rule"],
        raw_envelope={"pe_elf": {}},
    )
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/static", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["file_format"] == "pe64"
    assert body["imphash"] == "imphash123"
    assert body["ssdeep"] == "96:abc:def"
    assert body["deep_yara_matches"] == ["Demo_Rule"]
    # raw_envelope deliberately omitted from the response.
    assert "raw_envelope" not in body


def test_static_404_when_no_row(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job()
    store.jobs[j.id] = j  # job exists but no static row
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/static", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /analyses/<id>/similar
# ---------------------------------------------------------------------------


def test_similar_returns_sorted_neighbours(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job()
    store.jobs[j.id] = j
    peer_low = uuid4()
    peer_high = uuid4()
    store.similar[j.id] = [
        SimilarityNeighbor(
            analysis_id=peer_low, sample_sha256="f" * 64,
            similarity=0.62, flavour="byte", relation="similar",
        ),
        SimilarityNeighbor(
            analysis_id=peer_high, sample_sha256="e" * 64,
            similarity=0.94, flavour="byte", relation="near_duplicate",
        ),
    ]
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/similar", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 200
    items = resp.get_json()["items"]
    assert len(items) == 2
    assert items[0]["similarity"] == 0.94
    assert items[0]["relation"] == "near_duplicate"


def test_similar_respects_threshold(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job()
    store.jobs[j.id] = j
    store.similar[j.id] = [
        SimilarityNeighbor(
            analysis_id=uuid4(), sample_sha256="f" * 64,
            similarity=0.55, flavour="byte", relation="similar",
        ),
        SimilarityNeighbor(
            analysis_id=uuid4(), sample_sha256="e" * 64,
            similarity=0.91, flavour="byte", relation="near_duplicate",
        ),
    ]
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/similar",
        query_string={"threshold": "0.8"},
        headers={"X-API-Key": "secret-key"},
    )
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0]["similarity"] == 0.91


def test_similar_filters_by_flavour(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job()
    store.jobs[j.id] = j
    store.similar[j.id] = [
        SimilarityNeighbor(
            analysis_id=uuid4(), sample_sha256="f" * 64,
            similarity=0.9, flavour="byte", relation="similar",
        ),
        SimilarityNeighbor(
            analysis_id=uuid4(), sample_sha256="e" * 64,
            similarity=0.88, flavour="opcode", relation="similar",
        ),
    ]
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/similar",
        query_string={"flavour": "opcode"},
        headers={"X-API-Key": "secret-key"},
    )
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0]["flavour"] == "opcode"


def test_similar_rejects_bad_threshold(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job()
    store.jobs[j.id] = j
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/similar",
        query_string={"threshold": "2.5"},
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 400


def test_similar_404_for_unknown_base_job(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.get(
        f"/analyses/{uuid4()}/similar", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 404


def test_similar_empty_items_when_no_neighbours(tmp_path: Path) -> None:
    store = _Store()
    j = _make_job()
    store.jobs[j.id] = j
    client, _ = _client(tmp_path, store=store)
    resp = client.get(
        f"/analyses/{j.id}/similar", headers={"X-API-Key": "secret-key"}
    )
    assert resp.status_code == 200
    assert resp.get_json()["items"] == []


# ---------------------------------------------------------------------------
# Intake endpoints still work after the refactor
# ---------------------------------------------------------------------------


def test_intake_post_submit_still_works(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    resp = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"A" * 64), "x.exe")},
        content_type="multipart/form-data",
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 202


def test_intake_healthz_still_works(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)
    assert client.get("/healthz").status_code == 200
