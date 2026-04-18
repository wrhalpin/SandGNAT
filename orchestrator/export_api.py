"""Read-only HTTP API for analysis results.

Target consumer: the `gnat.connectors.sandgnat` connector in the GNAT
repo, which queries SandGNAT over HTTP rather than poking at our Postgres.
The routes are pull-only (GET); nothing here mutates state.

Routes (all gated by X-API-Key, served under /analyses):

    GET /analyses                    list + filters (sha256/status/since) + pagination
    GET /analyses/<uuid>             one job row
    GET /analyses/<uuid>/bundle      full STIX 2.1 bundle (409 if not completed)
    GET /analyses/<uuid>/static      static-analysis findings (404 if absent)
    GET /analyses/<uuid>/similar     LSH + lineage neighbours (empty list ok)

The blueprint is registered onto the existing intake Flask app by
`intake_api.create_app()`. It shares the same `X-API-Key` contract so the
GNAT connector only needs one secret.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Protocol
from uuid import UUID

from flask import Blueprint, jsonify, request

from .config import IntakeConfig
from .models import AnalysisJob, JobStatus, SimilarityNeighbor, StaticAnalysisRow

log = logging.getLogger(__name__)

# Operator-tunable defaults. Kept here (not in config.py) because they're
# purely API-surface concerns, not deployment-shape concerns.
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200
DEFAULT_SIMILAR_LIMIT = 25
MAX_SIMILAR_LIMIT = 100
DEFAULT_SIMILAR_THRESHOLD = 0.5


class ExportStore(Protocol):
    """Subset of persistence used by the export API.

    Implemented by `persistence.PostgresJobStore`; tests wire in an
    in-memory fake.
    """

    def get_job(self, job_id: UUID) -> AnalysisJob | None: ...

    def list_jobs(
        self,
        *,
        sha256: str | None = None,
        status: JobStatus | None = None,
        since: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AnalysisJob]: ...

    def get_static_analysis(self, analysis_id: UUID) -> StaticAnalysisRow | None: ...

    def list_similar(
        self,
        analysis_id: UUID,
        *,
        threshold: float = 0.5,
        limit: int = 25,
        flavour: str = "either",
    ) -> list[SimilarityNeighbor]: ...

    def export_bundle(self, analysis_id: UUID) -> dict[str, Any]: ...


def make_api_key_auth(cfg: IntakeConfig | None, *, require_api_key: bool) -> Callable:
    """Build a decorator that gates a view on the `X-API-Key` header.

    Factored out of intake_api so both blueprints share the same auth
    contract — a connector deployed with one key gets access to everything
    it's authorised to see. A future phase can split read vs write keys if
    that becomes necessary.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if require_api_key:
                presented = request.headers.get("X-API-Key", "")
                if not cfg or not cfg.api_key or presented != cfg.api_key:
                    return jsonify({"error": "unauthorized"}), 401
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def create_export_blueprint(
    store: ExportStore,
    *,
    cfg: IntakeConfig | None = None,
    require_api_key: bool = True,
) -> Blueprint:
    bp = Blueprint("sandgnat-export", __name__)
    auth = make_api_key_auth(cfg, require_api_key=require_api_key)

    @bp.get("/analyses")
    @auth
    def list_analyses() -> Any:
        try:
            filters = _parse_list_filters(request.args)
        except _BadRequest as exc:
            return jsonify({"error": exc.message}), 400
        items = store.list_jobs(**filters)
        return jsonify(
            {
                "items": [_job_to_json(j) for j in items],
                "limit": filters["limit"],
                "offset": filters["offset"],
                "count": len(items),
            }
        )

    @bp.get("/analyses/<analysis_id>")
    @auth
    def get_analysis(analysis_id: str) -> Any:
        uid = _parse_uuid_or_400(analysis_id)
        if isinstance(uid, tuple):
            return uid
        job = store.get_job(uid)
        if job is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(_job_to_json(job))

    @bp.get("/analyses/<analysis_id>/bundle")
    @auth
    def get_bundle(analysis_id: str) -> Any:
        uid = _parse_uuid_or_400(analysis_id)
        if isinstance(uid, tuple):
            return uid
        job = store.get_job(uid)
        if job is None:
            return jsonify({"error": "not found"}), 404
        # Bundle exists when the job reached a terminal state that produced
        # STIX: either COMPLETED via detonation, or COMPLETED via
        # near-duplicate short-circuit (which lineage-links back to a parent
        # bundle, so we still serve it via export_bundle).
        if job.status != JobStatus.COMPLETED:
            return jsonify(
                {
                    "error": "bundle not available",
                    "status": job.status.value,
                    "detail": "analysis has not produced a STIX bundle yet",
                }
            ), 409
        bundle = store.export_bundle(uid)
        return jsonify(bundle)

    @bp.get("/analyses/<analysis_id>/static")
    @auth
    def get_static(analysis_id: str) -> Any:
        uid = _parse_uuid_or_400(analysis_id)
        if isinstance(uid, tuple):
            return uid
        row = store.get_static_analysis(uid)
        if row is None:
            return jsonify({"error": "no static analysis for this job"}), 404
        # We still need the job row so we can surface imphash / ssdeep / tlsh
        # (those live on analysis_jobs, not static_analysis, because they're
        # also sample-identity fields).
        job = store.get_job(uid)
        return jsonify(_static_to_json(row, job))

    @bp.get("/analyses/<analysis_id>/similar")
    @auth
    def get_similar(analysis_id: str) -> Any:
        uid = _parse_uuid_or_400(analysis_id)
        if isinstance(uid, tuple):
            return uid
        if store.get_job(uid) is None:
            return jsonify({"error": "not found"}), 404
        try:
            params = _parse_similar_params(request.args)
        except _BadRequest as exc:
            return jsonify({"error": exc.message}), 400
        neighbours = store.list_similar(uid, **params)
        return jsonify({"items": [_neighbor_to_json(n) for n in neighbours]})

    return bp


# ---------------------------------------------------------------------------
# Query-parameter parsing
# ---------------------------------------------------------------------------


class _BadRequest(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _parse_list_filters(args) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    limit_raw = args.get("limit", str(DEFAULT_LIST_LIMIT))
    offset_raw = args.get("offset", "0")
    try:
        limit = int(limit_raw)
        offset = int(offset_raw)
    except ValueError as exc:
        raise _BadRequest(f"invalid limit/offset: {exc}") from exc
    if not (1 <= limit <= MAX_LIST_LIMIT):
        raise _BadRequest(f"limit must be between 1 and {MAX_LIST_LIMIT}")
    if offset < 0:
        raise _BadRequest("offset must be >= 0")

    status_raw = args.get("status")
    status: JobStatus | None = None
    if status_raw:
        try:
            status = JobStatus(status_raw)
        except ValueError as exc:
            raise _BadRequest(f"invalid status: {status_raw!r}") from exc

    since_raw = args.get("since")
    since: datetime | None = None
    if since_raw:
        since = _parse_iso_or_400(since_raw)

    sha256 = args.get("sha256")
    if sha256 is not None:
        sha256 = sha256.strip().lower()
        if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
            raise _BadRequest("sha256 must be 64 hex chars")

    return {
        "sha256": sha256,
        "status": status,
        "since": since,
        "limit": limit,
        "offset": offset,
    }


def _parse_similar_params(args) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    threshold_raw = args.get("threshold", str(DEFAULT_SIMILAR_THRESHOLD))
    limit_raw = args.get("limit", str(DEFAULT_SIMILAR_LIMIT))
    try:
        threshold = float(threshold_raw)
        limit = int(limit_raw)
    except ValueError as exc:
        raise _BadRequest(f"invalid threshold/limit: {exc}") from exc
    if not (0.0 <= threshold <= 1.0):
        raise _BadRequest("threshold must be between 0.0 and 1.0")
    if not (1 <= limit <= MAX_SIMILAR_LIMIT):
        raise _BadRequest(f"limit must be between 1 and {MAX_SIMILAR_LIMIT}")

    flavour = args.get("flavour", "either")
    if flavour not in {"byte", "opcode", "either"}:
        raise _BadRequest(f"invalid flavour: {flavour!r}")

    return {"threshold": threshold, "limit": limit, "flavour": flavour}


def _parse_uuid_or_400(raw: str):  # type: ignore[no-untyped-def]
    try:
        return UUID(raw)
    except ValueError:
        return jsonify({"error": f"invalid uuid: {raw!r}"}), 400


def _parse_iso_or_400(raw: str) -> datetime:
    # Accept both "...Z" and offset-aware forms. datetime.fromisoformat
    # handles the latter directly; swap Z for +00:00 for the former.
    try:
        normalised = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalised)
    except ValueError as exc:
        raise _BadRequest(f"invalid ISO-8601 timestamp: {raw!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def _iso_or_none(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _job_to_json(job: AnalysisJob) -> dict[str, Any]:
    data = asdict(job)
    for key, value in list(data.items()):
        if isinstance(value, UUID):
            data[key] = str(value)
        elif isinstance(value, datetime):
            data[key] = _iso_or_none(value)
        elif isinstance(value, JobStatus):
            data[key] = value.value
    # yara_matches is stored as list[str]; asdict already handles it.
    return data


def _static_to_json(row: StaticAnalysisRow, job: AnalysisJob | None) -> dict[str, Any]:
    # Deliberately drop raw_envelope from the response: callers who need
    # the per-tool sections can hit /analyses/<id>/bundle for the STIX
    # view, or a future dedicated envelope endpoint. Sending back a
    # potentially large JSON blob on every poll is wasteful.
    payload: dict[str, Any] = {
        "analysis_id": str(row.analysis_id),
        "file_format": row.file_format,
        "architecture": row.architecture,
        "entry_point": row.entry_point,
        "is_packed_heuristic": row.is_packed_heuristic,
        "section_count": row.section_count,
        "overall_entropy": row.overall_entropy,
        "imports": row.imports,
        "exports": row.exports,
        "sections": row.sections,
        "strings_summary": row.strings_summary,
        "capa_capabilities": row.capa_capabilities,
        "deep_yara_matches": row.deep_yara_matches,
    }
    if job is not None:
        payload["imphash"] = _attr_or_none(job, "imphash")
        payload["ssdeep"] = _attr_or_none(job, "ssdeep")
        payload["tlsh"] = _attr_or_none(job, "tlsh")
        payload["static_completed_at"] = _iso_or_none(
            _attr_or_none(job, "static_completed_at")
        )
    return payload


def _neighbor_to_json(n: SimilarityNeighbor) -> dict[str, Any]:
    return {
        "analysis_id": str(n.analysis_id),
        "sample_sha256": n.sample_sha256,
        "similarity": round(n.similarity, 3),
        "flavour": n.flavour,
        "relation": n.relation,
    }


def _attr_or_none(obj: Any, name: str) -> Any:
    """Safe getattr that returns None if the attr isn't on the object.

    `AnalysisJob` may or may not have the static-fingerprint columns
    populated depending on whether Phase 4's static stage ran; this helper
    keeps the serializer resilient across migrations.
    """
    return getattr(obj, name, None)
