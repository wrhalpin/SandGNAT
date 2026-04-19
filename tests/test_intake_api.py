# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for the Flask intake API.

We build the app with injected fakes — no Postgres, no Celery, no VT. The
goal is to cover the HTTP contract: auth, happy-path submission, duplicate
replies, rejection, job-lookup.
"""

from __future__ import annotations

import io
from pathlib import Path
from uuid import UUID

import pytest

from orchestrator.config import IntakeConfig
from orchestrator.intake_api import create_app
from orchestrator.models import AnalysisJob, JobStatus
from orchestrator.vt_client import VTClient, VTVerdict


class _Store:
    def __init__(self) -> None:
        self.jobs: dict[UUID, AnalysisJob] = {}
        self._by_sha: dict[str, AnalysisJob] = {}

    def find_existing_job_by_sha256(self, sha256: str) -> AnalysisJob | None:
        return self._by_sha.get(sha256)

    def insert_job(self, job: AnalysisJob) -> None:
        self.jobs[job.id] = job
        self._by_sha[job.sample_hash_sha256] = job

    def get_job(self, job_id: UUID) -> AnalysisJob | None:
        return self.jobs.get(job_id)


class _Enqueue:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(self, *args) -> None:  # type: ignore[no-untyped-def]
        self.calls.append(args)


class _VT(VTClient):
    def __init__(self, verdict: VTVerdict) -> None:
        super().__init__(api_key="stub")
        self._verdict = verdict

    def lookup_hash(self, sha256: str) -> VTVerdict:  # type: ignore[override]
        return self._verdict


def _cfg(tmp_path: Path, **overrides) -> IntakeConfig:  # type: ignore[no-untyped-def]
    return IntakeConfig(
        max_sample_bytes=overrides.get("max_sample_bytes", 10 * 1024 * 1024),
        min_sample_bytes=overrides.get("min_sample_bytes", 16),
        api_key=overrides.get("api_key", "secret-key"),
        bind_host="127.0.0.1",
        bind_port=0,
        yara_rules_dir="",
        vt_api_key="",
        vt_base_url="https://vt.example/api/v3",
        vt_timeout_seconds=1.0,
    )


def _client(tmp_path: Path, **overrides):  # type: ignore[no-untyped-def]
    store = overrides.pop("store", _Store())
    enq = overrides.pop("enqueue", _Enqueue())
    vt = overrides.pop("vt", _VT(VTVerdict(verdict="unknown")))
    app = create_app(
        config=_cfg(tmp_path, **overrides),
        store=store,
        enqueue=enq,
        vt=vt,
        yara=None,
        staging_root=tmp_path / "staging",
        timeout_seconds=120,
    )
    app.testing = True
    return app.test_client(), store, enq


def test_healthz_open_to_unauthenticated() -> None:
    app = create_app(
        config=_cfg(Path(".")),
        store=_Store(),
        enqueue=_Enqueue(),
        vt=_VT(VTVerdict(verdict="unknown")),
        yara=None,
        staging_root=Path("."),
        timeout_seconds=60,
    )
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_submit_requires_api_key(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    resp = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"A" * 64), "x.exe")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 401


def test_submit_accepts_sample(tmp_path: Path) -> None:
    client, store, enq = _client(tmp_path)
    resp = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"A" * 64), "x.exe"), "priority": "5"},
        content_type="multipart/form-data",
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 202
    payload = resp.get_json()
    assert payload["decision"] == "queued"
    assert payload["sha256"]
    assert payload["size_bytes"] == 64

    # Job row was inserted and task enqueued.
    assert len(store.jobs) == 1
    assert len(enq.calls) == 1

    # Sample was staged to disk.
    staged = tmp_path / "staging" / "samples" / payload["analysis_id"] / "x.exe"
    assert staged.exists()
    assert staged.read_bytes() == b"A" * 64


def test_submit_too_small_returns_400(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    resp = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"x"), "tiny.bin")},
        content_type="multipart/form-data",
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 400
    assert resp.get_json()["decision"] == "rejected"


def test_submit_duplicate_returns_200(tmp_path: Path) -> None:
    client, _, enq = _client(tmp_path)
    first = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"A" * 64), "x.exe")},
        content_type="multipart/form-data",
        headers={"X-API-Key": "secret-key"},
    )
    assert first.status_code == 202

    second = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"A" * 64), "x.exe")},
        content_type="multipart/form-data",
        headers={"X-API-Key": "secret-key"},
    )
    assert second.status_code == 200
    payload = second.get_json()
    assert payload["decision"] == "duplicate"
    assert payload["duplicate_of"] == first.get_json()["analysis_id"]
    # Enqueued exactly once, not twice.
    assert len(enq.calls) == 1


def test_submit_with_vt_malicious_reports_prioritized(tmp_path: Path) -> None:
    vt = _VT(VTVerdict(verdict="malicious", detection_count=50, total_engines=70))
    client, _, _ = _client(tmp_path, vt=vt)
    resp = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"A" * 64), "x.exe")},
        content_type="multipart/form-data",
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 202
    payload = resp.get_json()
    assert payload["decision"] == "prioritized"
    assert payload["priority"] <= 2
    assert payload["vt"]["verdict"] == "malicious"
    assert payload["vt"]["detection_count"] == 50


def test_get_job_returns_404_for_unknown(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    resp = client.get(
        "/jobs/11111111-1111-1111-1111-111111111111",
        headers={"X-API-Key": "secret-key"},
    )
    assert resp.status_code == 404


def test_get_job_returns_row_after_submission(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    submit = client.post(
        "/submit",
        data={"file": (io.BytesIO(b"A" * 64), "x.exe")},
        content_type="multipart/form-data",
        headers={"X-API-Key": "secret-key"},
    )
    job_id = submit.get_json()["analysis_id"]
    resp = client.get(f"/jobs/{job_id}", headers={"X-API-Key": "secret-key"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == job_id
    assert body["status"] == "queued"


def test_create_app_requires_api_key_env() -> None:
    # With require_api_key True and empty key, the factory refuses to start.
    cfg = _cfg(Path("."), api_key="")
    with pytest.raises(RuntimeError):
        create_app(
            config=cfg,
            store=_Store(),
            enqueue=_Enqueue(),
            vt=_VT(VTVerdict(verdict="unknown")),
            yara=None,
            staging_root=Path("."),
        )
