"""The only module that writes to Postgres.

Keeping SQL localised here means parsers and the STIX builder stay pure and
easy to test, and we have exactly one audit point for schema drift.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import UUID

from psycopg.types.json import Jsonb

from .db import connection
from .models import (
    AnalysisJob,
    AuditEvent,
    DroppedFile,
    JobStatus,
    NetworkIOC,
    RegistryModification,
)


# ---------------------------------------------------------------------------
# Analysis jobs
# ---------------------------------------------------------------------------

def insert_job(job: AnalysisJob) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO analysis_jobs (
                id, sample_hash_sha256, sample_name, sample_mime_type, status,
                timeout_seconds, network_isolation, execution_command
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                job.id,
                job.sample_hash_sha256,
                job.sample_name,
                job.sample_mime_type,
                job.status.value,
                job.timeout_seconds,
                job.network_isolation,
                job.execution_command,
            ),
        )


def update_job_status(
    job_id: UUID,
    status: JobStatus,
    *,
    vm_uuid: UUID | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    duration_seconds: int | None = None,
    evasion_observed: bool | None = None,
    result_summary: dict[str, Any] | None = None,
    quarantine_path: str | None = None,
) -> None:
    fields: list[str] = ["status = %s"]
    values: list[Any] = [status.value]
    if vm_uuid is not None:
        fields.append("vm_uuid = %s")
        values.append(vm_uuid)
    if started_at is not None:
        fields.append("started_at = %s")
        values.append(started_at)
    if completed_at is not None:
        fields.append("completed_at = %s")
        values.append(completed_at)
    if duration_seconds is not None:
        fields.append("duration_seconds = %s")
        values.append(duration_seconds)
    if evasion_observed is not None:
        fields.append("evasion_observed = %s")
        values.append(evasion_observed)
    if result_summary is not None:
        fields.append("result_summary = %s")
        values.append(Jsonb(result_summary))
    if quarantine_path is not None:
        fields.append("quarantine_path = %s")
        values.append(quarantine_path)

    values.append(job_id)
    sql = f"UPDATE analysis_jobs SET {', '.join(fields)} WHERE id = %s"
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, values)


# ---------------------------------------------------------------------------
# STIX persistence
# ---------------------------------------------------------------------------

def _stix_uuid(stix_obj: dict[str, Any]) -> UUID:
    return UUID(stix_obj["id"].split("--", 1)[1])


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def persist_stix_objects(analysis_id: UUID, objects: Iterable[dict[str, Any]]) -> None:
    """Insert each STIX object into its type-appropriate table.

    Idempotent at the STIX-ID level thanks to UUIDv5 generation in the builder.
    Uses ON CONFLICT DO NOTHING so re-ingest is safe.
    """
    malware_rows: list[tuple] = []
    observable_rows: list[tuple] = []
    indicator_rows: list[tuple] = []

    for obj in objects:
        obj_id = _stix_uuid(obj)
        obj_type = obj["type"]
        if obj_type == "malware":
            malware_rows.append(
                (
                    obj_id,
                    analysis_id,
                    _parse_iso(obj["created"]),
                    _parse_iso(obj["modified"]),
                    obj.get("name"),
                    obj.get("description"),
                    obj.get("malware_types", []),
                    obj.get("labels", ["malware"]),
                    [_stix_uuid({"id": r}) for r in obj.get("object_refs", [])],
                    obj.get("x_analysis_metadata", {}).get("analyst_confidence_level"),
                    Jsonb(obj),
                )
            )
        elif obj_type == "indicator":
            indicator_rows.append(
                (
                    obj_id,
                    analysis_id,
                    _parse_iso(obj["created"]),
                    _parse_iso(obj["modified"]),
                    obj["pattern"],
                    obj.get("labels", []),
                    Jsonb(obj.get("kill_chain_phases")) if obj.get("kill_chain_phases") else None,
                    obj.get("x_analysis_metadata", {}).get("analyst_confidence_level"),
                    [_stix_uuid({"id": r}) for r in obj.get("x_observable_refs", [])],
                    Jsonb(obj),
                )
            )
        else:
            observable_rows.append(
                (
                    obj_id,
                    analysis_id,
                    obj_type,
                    obj.get("name"),
                    _parse_iso(obj.get("created")),
                    _parse_iso(obj.get("modified")),
                    Jsonb(obj),
                )
            )

    with connection() as conn, conn.cursor() as cur:
        if malware_rows:
            cur.executemany(
                """
                INSERT INTO stix_malware (
                    id, analysis_id, created, modified, name, description,
                    malware_types, labels, object_refs, confidence_level, stix_object
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
                """,
                malware_rows,
            )
        if observable_rows:
            cur.executemany(
                """
                INSERT INTO stix_observables (
                    id, analysis_id, type, name, created, modified, observable
                ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
                """,
                observable_rows,
            )
        if indicator_rows:
            cur.executemany(
                """
                INSERT INTO stix_indicators (
                    id, analysis_id, created, modified, pattern, labels,
                    kill_chain_phases, confidence_level, observable_refs, stix_object
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
                """,
                indicator_rows,
            )


# ---------------------------------------------------------------------------
# Normalised artifact tables
# ---------------------------------------------------------------------------

def insert_dropped_files(files: Iterable[DroppedFile]) -> None:
    rows = [
        (
            f.analysis_id,
            f.filename,
            f.original_path,
            f.size_bytes,
            f.hash_sha256,
            f.hash_md5,
            f.quarantine_path,
            f.verified,
            f.created_by_process_name,
            f.created_by_process_pid,
        )
        for f in files
    ]
    if not rows:
        return
    with connection() as conn, conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO dropped_files (
                analysis_id, filename, original_path, size_bytes,
                hash_sha256, hash_md5, quarantine_path, verified,
                created_by_process_name, created_by_process_pid
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_registry_modifications(mods: Iterable[RegistryModification]) -> None:
    rows = [
        (
            m.analysis_id,
            m.action,
            m.hive,
            m.key_path,
            m.value_name,
            m.value_data,
            m.value_type,
            m.persistence_indicator,
        )
        for m in mods
    ]
    if not rows:
        return
    with connection() as conn, conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO registry_modifications (
                analysis_id, action, hive, key_path, value_name,
                value_data, value_type, persistence_indicator
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_network_iocs(iocs: Iterable[NetworkIOC]) -> None:
    rows = [
        (
            i.analysis_id,
            i.type,
            i.indicator,
            i.direction,
            i.protocol,
            i.port,
            i.observed_at,
            i.context,
            i.confirmed_malicious,
        )
        for i in iocs
    ]
    if not rows:
        return
    with connection() as conn, conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO network_iocs (
                analysis_id, type, indicator, direction, protocol,
                port, observed_at, context, confirmed_malicious
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def log_event(event: AuditEvent) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO analysis_audit_log (analysis_id, event_type, details, actor)
            VALUES (%s, %s, %s, %s)
            """,
            (event.analysis_id, event.event_type, Jsonb(event.details), event.actor),
        )


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def export_bundle(analysis_id: UUID) -> dict[str, Any]:
    """Assemble every STIX object for an analysis into a 2.1 Bundle."""
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT stix_object FROM stix_malware WHERE analysis_id = %s", (analysis_id,))
        malware = [row[0] for row in cur.fetchall()]

        cur.execute("SELECT observable FROM stix_observables WHERE analysis_id = %s", (analysis_id,))
        observables = [row[0] for row in cur.fetchall()]

        cur.execute("SELECT stix_object FROM stix_indicators WHERE analysis_id = %s", (analysis_id,))
        indicators = [row[0] for row in cur.fetchall()]

    # Defer bundle construction to stix_builder to keep ID derivation consistent.
    from .stix_builder import build_bundle

    return build_bundle([*malware, *observables, *indicators])


def serialize_bundle(analysis_id: UUID) -> str:
    return json.dumps(export_bundle(analysis_id), indent=2, sort_keys=True)
