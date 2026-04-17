"""HTTP intake service for sample submissions.

Thin Flask front-end over `intake.ingest_submission`. The API does three things:

    POST /submit       accept a multipart upload, run the intake pipeline,
                       return an IntakeReport as JSON.
    GET  /jobs/<uuid>  return the row from analysis_jobs for status polling.
    GET  /healthz      liveness probe.

Auth is a shared API key in the `X-API-Key` header, loaded from
`INTAKE_API_KEY`. If the env var is empty the server refuses to start — we
never want an unauthenticated sample uploader accessible on the analysis
network.

Why Flask and not FastAPI: fewer transitive deps (no pydantic/starlette),
and the surface here is small enough that the typing wins from FastAPI
aren't worth the weight.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from functools import wraps
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from .config import IntakeConfig, get_settings
from .intake import IntakeReport, ingest_submission
from .vt_client import VTClient
from .yara_scanner import YaraScanner

log = logging.getLogger(__name__)


def create_app(
    *,
    config: IntakeConfig | None = None,
    store: Any = None,
    enqueue: Callable[..., None] | None = None,
    vt: VTClient | None = None,
    yara: YaraScanner | None = None,
    staging_root: Path | None = None,
    timeout_seconds: int | None = None,
    require_api_key: bool = True,
) -> Flask:
    """Build a Flask app wired to the intake pipeline.

    Dependencies are injectable so tests can spin up the app without Postgres,
    Redis, or network access. Production callers pass nothing and the factory
    resolves `persistence.PostgresJobStore`, the Celery enqueuer, a VT client,
    and a YARA scanner from `get_settings()`.
    """
    cfg = config or get_settings().intake
    if require_api_key and not cfg.api_key:
        raise RuntimeError(
            "INTAKE_API_KEY is not set; refusing to start an unauthenticated intake API"
        )

    resolved_store = store or _default_store()
    resolved_enqueue = enqueue or _default_enqueuer()
    resolved_vt = vt if vt is not None else VTClient(
        api_key=cfg.vt_api_key,
        base_url=cfg.vt_base_url,
        timeout_seconds=cfg.vt_timeout_seconds,
    )
    resolved_yara = yara if yara is not None else YaraScanner(cfg.yara_rules_dir or None)
    effective_staging_root = (
        staging_root
        if staging_root is not None
        else Path(get_settings().artifact_staging_root)
    )
    effective_timeout = timeout_seconds or get_settings().default_timeout_seconds

    app = Flask("sandgnat-intake")
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_sample_bytes + 64 * 1024  # headroom

    def _auth(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if require_api_key:
                presented = request.headers.get("X-API-Key", "")
                if not presented or presented != cfg.api_key:
                    return jsonify({"error": "unauthorized"}), 401
            return fn(*args, **kwargs)

        return wrapper

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):  # type: ignore[no-untyped-def]
        return jsonify({"error": exc.name, "detail": exc.description}), exc.code or 500

    @app.get("/healthz")
    def healthz() -> Any:
        return jsonify({"status": "ok"})

    @app.post("/submit")
    @_auth
    def submit() -> Any:
        upload = request.files.get("file")
        if upload is None:
            return jsonify({"error": "missing file field"}), 400
        data = upload.read()
        if not data:
            return jsonify({"error": "empty upload"}), 400

        submitter = request.headers.get("X-Submitter") or request.form.get("submitter")
        priority_raw = request.form.get("priority", "5")
        try:
            priority = int(priority_raw)
        except ValueError:
            return jsonify({"error": f"invalid priority: {priority_raw!r}"}), 400
        force = request.form.get("force", "").lower() in {"1", "true", "yes"}

        report = ingest_submission(
            data,
            sample_name=upload.filename or request.form.get("name"),
            store=resolved_store,
            enqueue=resolved_enqueue,
            staging_root=effective_staging_root,
            vt=resolved_vt,
            yara=resolved_yara,
            max_sample_bytes=cfg.max_sample_bytes,
            min_sample_bytes=cfg.min_sample_bytes,
            timeout_seconds=effective_timeout,
            submitter=submitter,
            intake_source=request.headers.get("X-Intake-Source") or "http",
            priority=priority,
            force=force,
        )

        status = 202 if report.decision in {"queued", "prioritized"} else 200
        if report.decision == "rejected":
            status = 400
        return jsonify(_report_to_json(report)), status

    @app.get("/jobs/<job_id>")
    @_auth
    def get_job(job_id: str) -> Any:
        try:
            uid = UUID(job_id)
        except ValueError:
            return jsonify({"error": "invalid job id"}), 400
        job = resolved_store.get_job(uid) if hasattr(resolved_store, "get_job") else None
        if job is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(_job_to_json(job))

    return app


def _default_store() -> Any:
    # Imported lazily so tests can build the app without psycopg installed in
    # their minimal virtualenv.
    from .persistence import PostgresJobStore

    return PostgresJobStore()


def _default_enqueuer() -> Callable[..., None]:
    from .tasks import enqueue_analysis

    return enqueue_analysis


def _report_to_json(report: IntakeReport) -> dict[str, Any]:
    vt = report.vt_verdict
    return {
        "decision": report.decision,
        "analysis_id": str(report.analysis_id) if report.analysis_id else None,
        "duplicate_of": str(report.duplicate_of) if report.duplicate_of else None,
        "rejection_reason": report.rejection_reason,
        "sha256": report.sha256,
        "md5": report.md5,
        "sha1": report.sha1,
        "size_bytes": report.size_bytes,
        "mime_type": report.mime_type,
        "sample_name": report.sample_name,
        "priority": report.priority,
        "vt": (
            {
                "verdict": vt.verdict,
                "detection_count": vt.detection_count,
                "total_engines": vt.total_engines,
                "last_seen": vt.last_seen.isoformat() if vt.last_seen else None,
            }
            if vt
            else None
        ),
        "yara_matches": [
            {"rule": m.rule, "tags": list(m.tags), "meta": m.meta or {}}
            for m in report.yara_matches
        ],
    }


def _job_to_json(job: Any) -> dict[str, Any]:
    data = asdict(job)
    for key, value in list(data.items()):
        if isinstance(value, UUID):
            data[key] = str(value)
        elif hasattr(value, "isoformat"):
            data[key] = value.isoformat()
        elif hasattr(value, "value") and not isinstance(value, (int, str)):
            data[key] = value.value
    return data
