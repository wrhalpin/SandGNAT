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
    LineageEdge,
    NetworkIOC,
    RegistryModification,
    SimilarityNeighbor,
    StaticAnalysisRow,
    VmLease,
)
from .trigrams import MinHashSignature, NUM_BANDS

# Shared SELECT list for analysis_jobs reads. Keep this in sync with
# _row_to_job() below — adding a column means updating both.
_JOB_COLUMNS = """
    id, sample_hash_sha256, sample_name, sample_mime_type, status,
    sample_hash_md5, sample_hash_sha1, sample_size_bytes,
    submitter, intake_source, intake_decision, intake_notes, priority,
    vt_verdict, vt_detection_count, vt_total_engines, vt_last_seen,
    yara_matches, submitted_at, started_at, completed_at,
    duration_seconds, timeout_seconds, network_isolation,
    evasion_observed, quarantine_path,
    imphash, ssdeep, tlsh, static_completed_at,
    near_duplicate_of, near_duplicate_score
"""


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
            f"""
            SELECT {_JOB_COLUMNS}
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
            f"""
            SELECT {_JOB_COLUMNS}
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
        imphash=row[26],
        ssdeep=row[27],
        tlsh=row[28],
        static_completed_at=row[29],
        near_duplicate_of=row[30],
        near_duplicate_score=float(row[31]) if row[31] is not None else None,
    )


def list_jobs(
    *,
    sha256: str | None = None,
    status: JobStatus | None = None,
    since: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[AnalysisJob]:
    """Filtered, paginated list of analysis jobs.

    All filters are optional; with none set this returns the most-recent
    `limit` rows. The query is assembled with bind parameters only — never
    string-interpolate user input into SQL.
    """
    clauses: list[str] = []
    params: list[Any] = []
    if sha256 is not None:
        clauses.append("sample_hash_sha256 = %s")
        params.append(sha256)
    if status is not None:
        clauses.append("status = %s")
        params.append(status.value)
    if since is not None:
        clauses.append("submitted_at >= %s")
        params.append(since)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT {_JOB_COLUMNS}
        FROM analysis_jobs
        {where}
        ORDER BY submitted_at DESC
        LIMIT %s OFFSET %s
    """
    params.extend([int(limit), int(offset)])
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    return [_row_to_job(row) for row in rows]


def get_static_analysis(analysis_id: UUID) -> StaticAnalysisRow | None:
    """Read the static_analysis row for a job, or None if absent.

    Absent is normal: static analysis is opt-in (`STATIC_ANALYSIS_ENABLED=1`),
    and jobs that haven't reached static yet won't have a row either.
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT analysis_id, file_format, architecture, entry_point,
                   is_packed_heuristic, section_count, overall_entropy,
                   imports, exports, sections, strings_summary,
                   capa_capabilities, deep_yara_matches, raw_envelope
            FROM static_analysis
            WHERE analysis_id = %s
            """,
            (analysis_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return StaticAnalysisRow(
        analysis_id=row[0],
        file_format=row[1],
        architecture=row[2],
        entry_point=row[3],
        is_packed_heuristic=row[4],
        section_count=row[5],
        overall_entropy=float(row[6]) if row[6] is not None else None,
        imports=row[7],
        exports=row[8],
        sections=row[9] or [],
        strings_summary=row[10],
        capa_capabilities=row[11] or [],
        deep_yara_matches=list(row[12] or []),
        raw_envelope=row[13] or {},
    )


def list_similar(
    analysis_id: UUID,
    *,
    threshold: float = 0.5,
    limit: int = 25,
    flavour: str = "either",
) -> list[SimilarityNeighbor]:
    """Similarity neighbours for `analysis_id`, union of two sources.

    `sample_similarity` stores pairwise edges keyed by `left<right`, so we
    query both directions and normalise the peer analysis_id.
    `analysis_lineage` stores parent edges when the job was marked a
    near-duplicate; those are always 'near_duplicate' relations.

    Peers are deduped keeping the highest score; 'near_duplicate' always
    wins the relation tie because the pipeline explicitly flagged it.
    """
    flavour_clauses = ""
    flavour_params: list[Any] = []
    if flavour in {"byte", "opcode"}:
        flavour_clauses = " AND flavour = %s"
        flavour_params.append(flavour)
    elif flavour != "either":
        raise ValueError(f"unknown flavour {flavour!r}")

    peers: dict[UUID, SimilarityNeighbor] = {}

    with connection() as conn, conn.cursor() as cur:
        # sample_similarity: peer could be on either side of the canonical
        # (left<right) ordering — fetch both directions and normalise.
        cur.execute(
            f"""
            SELECT right_analysis_id AS peer, flavour, similarity_score
              FROM sample_similarity
             WHERE left_analysis_id = %s AND similarity_score >= %s
                   {flavour_clauses}
            UNION ALL
            SELECT left_analysis_id AS peer, flavour, similarity_score
              FROM sample_similarity
             WHERE right_analysis_id = %s AND similarity_score >= %s
                   {flavour_clauses}
            """,
            [analysis_id, threshold, *flavour_params,
             analysis_id, threshold, *flavour_params],
        )
        similarity_rows = cur.fetchall()

        # analysis_lineage: child->parent edges, near_duplicate relations.
        cur.execute(
            """
            SELECT parent_analysis_id, similarity_score
              FROM analysis_lineage
             WHERE child_analysis_id = %s
                   AND relation = 'near_duplicate'
                   AND (similarity_score IS NULL OR similarity_score >= %s)
            """,
            (analysis_id, threshold),
        )
        lineage_rows = cur.fetchall()

        # Fetch peer sample_sha256 in one lookup — small N, one IN query.
        peer_ids: set[UUID] = {r[0] for r in similarity_rows} | {r[0] for r in lineage_rows}
        sha_by_id: dict[UUID, str] = {}
        if peer_ids:
            cur.execute(
                "SELECT id, sample_hash_sha256 FROM analysis_jobs WHERE id = ANY(%s)",
                (list(peer_ids),),
            )
            sha_by_id = dict(cur.fetchall())

    for peer_id, peer_flavour, score in similarity_rows:
        neighbor = SimilarityNeighbor(
            analysis_id=peer_id,
            sample_sha256=sha_by_id.get(peer_id),
            similarity=float(score),
            flavour=peer_flavour,
            relation="similar",
        )
        _merge_neighbor(peers, neighbor)

    for peer_id, score in lineage_rows:
        effective_flavour = flavour if flavour in {"byte", "opcode"} else "byte"
        neighbor = SimilarityNeighbor(
            analysis_id=peer_id,
            sample_sha256=sha_by_id.get(peer_id),
            similarity=float(score) if score is not None else 1.0,
            flavour=effective_flavour,
            relation="near_duplicate",
        )
        _merge_neighbor(peers, neighbor)

    ranked = sorted(peers.values(), key=lambda n: n.similarity, reverse=True)
    return ranked[: max(0, limit)]


def _merge_neighbor(
    peers: dict[UUID, SimilarityNeighbor], incoming: SimilarityNeighbor
) -> None:
    """Dedupe by peer id, keeping the best (higher score; near_duplicate
    wins ties)."""
    existing = peers.get(incoming.analysis_id)
    if existing is None:
        peers[incoming.analysis_id] = incoming
        return
    if incoming.similarity > existing.similarity:
        peers[incoming.analysis_id] = incoming
        return
    if (
        incoming.similarity == existing.similarity
        and incoming.relation == "near_duplicate"
        and existing.relation != "near_duplicate"
    ):
        peers[incoming.analysis_id] = incoming


class PostgresJobStore:
    """Adapts module-level persistence functions to the `intake.JobStore` protocol."""

    def find_existing_job_by_sha256(self, sha256: str) -> AnalysisJob | None:
        return find_job_by_sha256(sha256)

    def insert_job(self, job: AnalysisJob) -> None:
        insert_job(job)

    def get_job(self, job_id: UUID) -> AnalysisJob | None:
        return get_job(job_id)

    # Read-side wrappers consumed by export_api.create_export_blueprint.
    def list_jobs(
        self,
        *,
        sha256: str | None = None,
        status: JobStatus | None = None,
        since: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AnalysisJob]:
        return list_jobs(
            sha256=sha256, status=status, since=since, limit=limit, offset=offset
        )

    def get_static_analysis(self, analysis_id: UUID) -> StaticAnalysisRow | None:
        return get_static_analysis(analysis_id)

    def list_similar(
        self,
        analysis_id: UUID,
        *,
        threshold: float = 0.5,
        limit: int = 25,
        flavour: str = "either",
    ) -> list[SimilarityNeighbor]:
        return list_similar(
            analysis_id, threshold=threshold, limit=limit, flavour=flavour
        )

    def export_bundle(self, analysis_id: UUID) -> dict[str, Any]:
        return export_bundle(analysis_id)


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
        guest_type: str = "windows",
    ) -> bool:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO vm_pool_leases (vmid, node, analysis_id, status, guest_type)
                VALUES (%s, %s, %s, 'leased', %s)
                ON CONFLICT (vmid) DO UPDATE
                    SET analysis_id  = EXCLUDED.analysis_id,
                        node         = EXCLUDED.node,
                        guest_type   = EXCLUDED.guest_type,
                        status       = 'leased',
                        acquired_at  = now(),
                        heartbeat_at = now(),
                        released_at  = NULL
                    WHERE vm_pool_leases.status IN ('released','orphaned')
                       OR vm_pool_leases.heartbeat_at <
                          now() - INTERVAL '{int(stale_after_seconds)} seconds'
                RETURNING vmid
                """,
                (vmid, node, analysis_id, guest_type),
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
                SELECT vmid, node, analysis_id, status, guest_type,
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
                    guest_type=row[4],
                    acquired_at=row[5],
                    heartbeat_at=row[6],
                    released_at=row[7],
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


# ---------------------------------------------------------------------------
# Static analysis + trigrams + similarity + lineage
# ---------------------------------------------------------------------------

def insert_static_analysis(row: StaticAnalysisRow) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO static_analysis (
                analysis_id, file_format, architecture, entry_point,
                is_packed_heuristic, section_count, overall_entropy,
                imports, exports, sections, strings_summary,
                capa_capabilities, deep_yara_matches, raw_envelope
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s
            )
            ON CONFLICT (analysis_id) DO UPDATE SET
                file_format          = EXCLUDED.file_format,
                architecture         = EXCLUDED.architecture,
                entry_point          = EXCLUDED.entry_point,
                is_packed_heuristic  = EXCLUDED.is_packed_heuristic,
                section_count        = EXCLUDED.section_count,
                overall_entropy      = EXCLUDED.overall_entropy,
                imports              = EXCLUDED.imports,
                exports              = EXCLUDED.exports,
                sections             = EXCLUDED.sections,
                strings_summary      = EXCLUDED.strings_summary,
                capa_capabilities    = EXCLUDED.capa_capabilities,
                deep_yara_matches    = EXCLUDED.deep_yara_matches,
                raw_envelope         = EXCLUDED.raw_envelope,
                completed_at         = now()
            """,
            (
                row.analysis_id,
                row.file_format,
                row.architecture,
                row.entry_point,
                row.is_packed_heuristic,
                row.section_count,
                row.overall_entropy,
                Jsonb(row.imports) if row.imports is not None else None,
                Jsonb(row.exports) if row.exports is not None else None,
                Jsonb(row.sections),
                Jsonb(row.strings_summary) if row.strings_summary is not None else None,
                Jsonb(row.capa_capabilities),
                list(row.deep_yara_matches),
                Jsonb(row.raw_envelope),
            ),
        )


def update_job_static_fingerprint(
    job_id: UUID,
    *,
    imphash: str | None,
    ssdeep: str | None,
    tlsh: str | None,
) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE analysis_jobs
               SET imphash              = COALESCE(%s, imphash),
                   ssdeep               = COALESCE(%s, ssdeep),
                   tlsh                 = COALESCE(%s, tlsh),
                   static_completed_at  = now()
             WHERE id = %s
            """,
            (imphash, ssdeep, tlsh, job_id),
        )


def mark_near_duplicate(
    job_id: UUID, parent_id: UUID, score: float
) -> None:
    """Stamp the job as a near-duplicate of `parent_id` and add a lineage edge."""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE analysis_jobs
               SET near_duplicate_of    = %s,
                   near_duplicate_score = %s,
                   intake_decision      = 'near_duplicate'
             WHERE id = %s
            """,
            (parent_id, round(score, 3), job_id),
        )
        cur.execute(
            """
            INSERT INTO analysis_lineage (
                child_analysis_id, parent_analysis_id, relation, similarity_score
            ) VALUES (%s, %s, 'near_duplicate', %s)
            ON CONFLICT (child_analysis_id) DO UPDATE
                SET parent_analysis_id = EXCLUDED.parent_analysis_id,
                    relation           = EXCLUDED.relation,
                    similarity_score   = EXCLUDED.similarity_score,
                    created_at         = now()
            """,
            (job_id, parent_id, round(score, 3)),
        )


def insert_lineage(edge: LineageEdge) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO analysis_lineage (
                child_analysis_id, parent_analysis_id, relation, similarity_score
            ) VALUES (%s, %s, %s, %s)
            ON CONFLICT (child_analysis_id) DO UPDATE
                SET parent_analysis_id = EXCLUDED.parent_analysis_id,
                    relation           = EXCLUDED.relation,
                    similarity_score   = EXCLUDED.similarity_score,
                    created_at         = now()
            """,
            (
                edge.child_analysis_id,
                edge.parent_analysis_id,
                edge.relation,
                edge.similarity_score,
            ),
        )


class PostgresSimilarityStore:
    """Postgres backing for `similarity.SimilarityStore`.

    Signatures live in `sample_trigrams`; bands live in `sample_minhash_bands`
    indexed for cheap candidate lookup; cached pairwise scores live in
    `sample_similarity` with the canonical `left < right` ordering enforced
    by a CHECK constraint.
    """

    def candidate_ids(self, flavour: str, bands: list[bytes]) -> set[UUID]:
        if not bands:
            return set()
        # Build a single multi-row IN-list for the (band_index, band_value)
        # pairs so the index can serve them all at once.
        params: list[Any] = [flavour]
        clauses: list[str] = []
        for idx, value in enumerate(bands):
            clauses.append("(band_index = %s AND band_value = %s)")
            params.extend([idx, value])
        sql = (
            "SELECT DISTINCT analysis_id FROM sample_minhash_bands "
            "WHERE flavour = %s AND (" + " OR ".join(clauses) + ")"
        )
        with connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return {row[0] for row in cur.fetchall()}

    def load_signature(
        self, analysis_id: UUID, flavour: str
    ) -> tuple[str, MinHashSignature] | None:
        column = "byte_minhash" if flavour == "byte" else "opcode_minhash"
        count_col = "byte_trigram_count" if flavour == "byte" else "opcode_trigram_count"
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sample_sha256, {column}, {count_col}, signature_version
                  FROM sample_trigrams
                 WHERE analysis_id = %s
                """,
                (analysis_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        sha, blob, cardinality, version = row
        if blob is None:
            return None
        return sha, MinHashSignature.from_bytes(
            bytes(blob), cardinality=cardinality or 0, version=version
        )

    def store_signature(
        self,
        analysis_id: UUID,
        sample_sha256: str,
        flavour: str,
        signature: MinHashSignature,
    ) -> None:
        with connection() as conn, conn.cursor() as cur:
            if flavour == "byte":
                cur.execute(
                    """
                    INSERT INTO sample_trigrams (
                        analysis_id, sample_sha256, signature_version,
                        byte_minhash, byte_trigram_count
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (analysis_id) DO UPDATE
                        SET sample_sha256       = EXCLUDED.sample_sha256,
                            signature_version   = EXCLUDED.signature_version,
                            byte_minhash        = EXCLUDED.byte_minhash,
                            byte_trigram_count  = EXCLUDED.byte_trigram_count,
                            extracted_at        = now()
                    """,
                    (
                        analysis_id,
                        sample_sha256,
                        signature.version,
                        signature.to_bytes(),
                        signature.cardinality,
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO sample_trigrams (
                        analysis_id, sample_sha256, signature_version,
                        byte_minhash, byte_trigram_count,
                        opcode_minhash, opcode_trigram_count
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (analysis_id) DO UPDATE
                        SET opcode_minhash        = EXCLUDED.opcode_minhash,
                            opcode_trigram_count  = EXCLUDED.opcode_trigram_count,
                            extracted_at          = now()
                    """,
                    (
                        analysis_id,
                        sample_sha256,
                        signature.version,
                        b"",  # placeholder (NOT NULL); overwritten if byte-row exists
                        0,
                        signature.to_bytes(),
                        signature.cardinality,
                    ),
                )
            # Re-write the bands. Easiest correct semantics: delete-then-insert
            # for this (analysis_id, flavour) since signatures are not partial.
            cur.execute(
                "DELETE FROM sample_minhash_bands WHERE analysis_id = %s AND flavour = %s",
                (analysis_id, flavour),
            )
            band_rows = [
                (analysis_id, flavour, idx, value)
                for idx, value in enumerate(signature.bands())
            ]
            if len(band_rows) != NUM_BANDS:
                raise RuntimeError(
                    f"signature emitted {len(band_rows)} bands, expected {NUM_BANDS}"
                )
            cur.executemany(
                """
                INSERT INTO sample_minhash_bands (
                    analysis_id, flavour, band_index, band_value
                ) VALUES (%s, %s, %s, %s)
                """,
                band_rows,
            )

    def store_similarity_edge(
        self, left: UUID, right: UUID, flavour: str, similarity: float
    ) -> None:
        if left >= right:
            raise ValueError(f"non-canonical edge {left} >= {right}")
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sample_similarity (
                    left_analysis_id, right_analysis_id, flavour, similarity_score
                ) VALUES (%s, %s, %s, %s)
                ON CONFLICT (left_analysis_id, right_analysis_id, flavour)
                DO UPDATE SET
                    similarity_score = EXCLUDED.similarity_score,
                    computed_at      = now()
                """,
                (left, right, flavour, round(similarity, 3)),
            )
