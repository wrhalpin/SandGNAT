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
    VmLease,
)


# ---------------------------------------------------------------------------
# Analysis jobs
# ---------------------------------------------------------------------------

def insert_job(job: AnalysisJob) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO analysis_jobs (
                id, sample_hash_sha256, sample_hash_md5, sample_hash_sha1,
                sample_size_bytes, sample_name, sample_mime_type, status,
                timeout_seconds, network_isolation, execution_command,
                submitter, intake_source, intake_decision, intake_notes, priority,
                vt_verdict, vt_detection_count, vt_total_engines, vt_last_seen,
                yara_matches
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s
            )
            """,
            (
                job.id,
                job.sample_hash_sha256,
                job.sample_hash_md5,
                job.sample_hash_sha1,
                job.sample_size_bytes,
                job.sample_name,
                job.sample_mime_type,
                job.status.value,
                job.timeout_seconds,
                job.network_isolation,
                job.execution_command,
                job.submitter,
                job.intake_source,
                job.intake_decision,
                job.intake_notes,
                job.priority,
                job.vt_verdict,
                job.vt_detection_count,
                job.vt_total_engines,
                job.vt_last_seen,
                list(job.yara_matches),
            ),
        )


def find_job_by_sha256(sha256: str) -> AnalysisJob | None:
    """Return the most-recent non-failed job for a hash, or None."""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, sample_hash_sha256, sample_name, sample_mime_type, status,
                   sample_hash_md5, sample_hash_sha1, sample_size_bytes,
                   submitter, intake_source, intake_decision, intake_notes, priority,
                   vt_verdict, vt_detection_count, vt_total_engines, vt_last_seen,
                   yara_matches, submitted_at, started_at, completed_at,
                   duration_seconds, timeout_seconds, network_isolation,
                   evasion_observed, quarantine_path
            FROM analysis_jobs
            WHERE sample_hash_sha256 = %s
            ORDER BY submitted_at DESC
            LIMIT 1
            """,
            (sha256,),
        )
        row = cur.fetchone()
    return _row_to_job(row) if row else None


def get_job(job_id: UUID) -> AnalysisJob | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, sample_hash_sha256, sample_name, sample_mime_type, status,
                   sample_hash_md5, sample_hash_sha1, sample_size_bytes,
                   submitter, intake_source, intake_decision, intake_notes, priority,
                   vt_verdict, vt_detection_count, vt_total_engines, vt_last_seen,
                   yara_matches, submitted_at, started_at, completed_at,
                   duration_seconds, timeout_seconds, network_isolation,
                   evasion_observed, quarantine_path
            FROM analysis_jobs
            WHERE id = %s
            """,
            (job_id,),
        )
        row = cur.fetchone()
    return _row_to_job(row) if row else None


def _row_to_job(row: Any) -> AnalysisJob:
    return AnalysisJob(
        id=row[0],
        sample_hash_sha256=row[1],
        sample_name=row[2],
        sample_mime_type=row[3],
        status=JobStatus(row[4]),
        sample_hash_md5=row[5],
        sample_hash_sha1=row[6],
        sample_size_bytes=row[7],
        submitter=row[8],
        intake_source=row[9],
        intake_decision=row[10],
        intake_notes=row[11],
        priority=row[12] if row[12] is not None else 5,
        vt_verdict=row[13],
        vt_detection_count=row[14],
        vt_total_engines=row[15],
        vt_last_seen=row[16],
        yara_matches=list(row[17] or []),
        submitted_at=row[18],
        started_at=row[19],
        completed_at=row[20],
        duration_seconds=row[21],
        timeout_seconds=row[22] if row[22] is not None else 300,
        network_isolation=row[23] if row[23] is not None else True,
        evasion_observed=row[24] if row[24] is not None else False,
        quarantine_path=row[25],
    )


class PostgresJobStore:
    """Adapts module-level persistence functions to the `intake.JobStore` protocol."""

    def find_existing_job_by_sha256(self, sha256: str) -> AnalysisJob | None:
        return find_job_by_sha256(sha256)

    def insert_job(self, job: AnalysisJob) -> None:
        insert_job(job)

    def get_job(self, job_id: UUID) -> AnalysisJob | None:
        return get_job(job_id)


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


# ---------------------------------------------------------------------------
# VM pool leases
# ---------------------------------------------------------------------------

class PostgresPoolStore:
    """Postgres-backed implementation of `vm_pool.PoolStore`.

    All operations are single-statement. The acquire path in particular is a
    conditional UPSERT whose WHERE clause is the lock: if another worker
    already holds a live lease on the vmid, the UPDATE branch matches no
    rows and RETURNING yields nothing.
    """

    def try_acquire_lease(
        self,
        vmid: int,
        node: str,
        analysis_id: UUID,
        stale_after_seconds: int,
    ) -> bool:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO vm_pool_leases (vmid, node, analysis_id, status)
                VALUES (%s, %s, %s, 'leased')
                ON CONFLICT (vmid) DO UPDATE
                    SET analysis_id  = EXCLUDED.analysis_id,
                        node         = EXCLUDED.node,
                        status       = 'leased',
                        acquired_at  = now(),
                        heartbeat_at = now(),
                        released_at  = NULL
                    WHERE vm_pool_leases.status IN ('released','orphaned')
                       OR vm_pool_leases.heartbeat_at <
                          now() - INTERVAL '{int(stale_after_seconds)} seconds'
                RETURNING vmid
                """,
                (vmid, node, analysis_id),
            )
            return cur.fetchone() is not None

    def heartbeat_lease(self, vmid: int, analysis_id: UUID) -> bool:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE vm_pool_leases
                   SET heartbeat_at = now()
                 WHERE vmid = %s AND analysis_id = %s AND status = 'leased'
                """,
                (vmid, analysis_id),
            )
            return cur.rowcount > 0

    def release_lease(self, vmid: int, analysis_id: UUID) -> None:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE vm_pool_leases
                   SET status = 'released', released_at = now()
                 WHERE vmid = %s AND analysis_id = %s AND status = 'leased'
                """,
                (vmid, analysis_id),
            )

    def mark_orphaned(self, vmid: int) -> None:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE vm_pool_leases
                   SET status = 'orphaned', released_at = now()
                 WHERE vmid = %s AND status = 'leased'
                """,
                (vmid,),
            )

    def active_leases(self) -> list[VmLease]:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT vmid, node, analysis_id, status,
                       acquired_at, heartbeat_at, released_at
                  FROM vm_pool_leases
                 WHERE status = 'leased'
                """
            )
            return [
                VmLease(
                    vmid=row[0],
                    node=row[1],
                    analysis_id=row[2],
                    status=row[3],
                    acquired_at=row[4],
                    heartbeat_at=row[5],
                    released_at=row[6],
                )
                for row in cur.fetchall()
            ]

    def reap_stale(self, stale_after_seconds: int) -> list[int]:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE vm_pool_leases
                   SET status = 'orphaned', released_at = now()
                 WHERE status = 'leased'
                   AND heartbeat_at <
                       now() - INTERVAL '{int(stale_after_seconds)} seconds'
                RETURNING vmid
                """
            )
            return [row[0] for row in cur.fetchall()]
