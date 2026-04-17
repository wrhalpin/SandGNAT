"""Pre-detonation static-analysis Celery task.

This task runs *before* `analyze_malware_sample` in the new pipeline shape:

    intake -> static_analyze_sample -> [near-duplicate?]
                |                          |
                | (no)                     | (yes)
                v                          v
       analyze_malware_sample       mark COMPLETED + lineage
       (existing detonation)        edge to the parent analysis;
                                    skip detonation entirely.

The task acquires a Linux VM from the dedicated Linux pool (vmid range
9200–9299 by default), publishes a `mode="static_analysis"` manifest, waits
for the guest to write `static_analysis.json` + `trigrams_byte.bin` +
`trigrams_opcode.bin`, parses them into a bundle, persists everything,
runs an LSH similarity lookup, and decides whether to short-circuit.

Why a separate task instead of a stage inside `analyze_malware_sample`?
Because the two stages live on different VM pools and different Celery
queues — operators tune them independently (more Linux workers when the
backlog is static-bound, more Windows workers when detonations are slow).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from celery import shared_task

from .celery_app import app  # noqa: F401  — registers the Celery app on import
from .config import get_settings
from .guest_driver import (
    GuestDriverError,
    cleanup_completed,
    submit_job,
    wait_for_result,
)
from .models import AuditEvent, JobStatus, LineageEdge
from .persistence import (
    PostgresPoolStore,
    PostgresSimilarityStore,
    insert_lineage,
    insert_static_analysis,
    log_event,
    mark_near_duplicate,
    update_job_static_fingerprint,
    update_job_status,
)
from .proxmox_client import GuestVM, ProxmoxClient
from .schema import MODE_STATIC_ANALYSIS, StaticAnalysisOptions
from .similarity import (
    SimilarityHit,
    cache_top_edges,
    find_similar,
    short_circuit_decision,
)
from .static_analysis import StaticAnalysisBundle, parse_static_workspace
from .tasks import staged_sample_path
from .vm_pool import PoolExhausted, VmPool

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enqueue helper for intake.
# ---------------------------------------------------------------------------

def enqueue_static_analysis(
    analysis_id: UUID,
    sample_name: str,
    sample_sha256: str,
    timeout_seconds: int,
    priority: int,
) -> None:
    """Dispatch the static-analysis task. Detonation chains automatically
    after, unless the static stage finds a near-duplicate."""
    static_analyze_sample.apply_async(
        args=[str(analysis_id), sample_sha256, sample_name, timeout_seconds, priority],
        priority=priority,
        queue="static",
    )


# ---------------------------------------------------------------------------
# Main task.
# ---------------------------------------------------------------------------

@shared_task(bind=True, name="sandgnat.static_analyze_sample", max_retries=2)
def static_analyze_sample(
    self,  # noqa: ANN001 — Celery bound-task self
    analysis_id: str,
    sample_hash_sha256: str,
    sample_name: str,
    timeout_seconds: int | None = None,
    priority: int = 5,
) -> dict[str, object]:
    settings = get_settings()
    job_id = UUID(analysis_id)
    effective_timeout = timeout_seconds or settings.static.timeout_seconds

    log_event(AuditEvent(job_id, "static_analysis_started", {"sha256": sample_hash_sha256}))
    update_job_status(job_id, JobStatus.RUNNING, started_at=datetime.now(timezone.utc))

    staging_root = Path(settings.artifact_staging_root)

    sample_path = staged_sample_path(staging_root, job_id, sample_name)
    if not sample_path.exists():
        _fail(job_id, f"staged sample missing at {sample_path}")
        raise FileNotFoundError(str(sample_path))

    client = ProxmoxClient()
    pool = VmPool(
        PostgresPoolStore(),
        vmid_min=settings.linux_vm_pool.vmid_min,
        vmid_max=settings.linux_vm_pool.vmid_max,
        node=settings.proxmox.node,
        stale_lease_seconds=settings.linux_vm_pool.stale_lease_seconds,
        guest_type="linux",
    )
    similarity_store = PostgresSimilarityStore()

    acquired_vmid: int | None = None
    vm: GuestVM | None = None
    try:
        try:
            acquired_vmid = pool.acquire(job_id)
        except PoolExhausted as exc:
            log.warning("Linux pool exhausted for job %s; deferring", job_id)
            raise self.retry(exc=exc, countdown=15) from exc

        vm = _clone_and_start(client, acquired_vmid, job_id, settings)
        log_event(AuditEvent(job_id, "linux_vm_spun_up", {"vmid": vm.vmid}))

        submit_job(
            staging_root,
            job_id,
            sample_name=sample_name,
            sample_sha256=sample_hash_sha256,
            timeout_seconds=effective_timeout,
            mode=MODE_STATIC_ANALYSIS,
            static=StaticAnalysisOptions(),
        )
        log_event(AuditEvent(job_id, "static_job_submitted_to_guest", {}))

        host_timeout = effective_timeout + 60
        artifacts = wait_for_result(staging_root, job_id, timeout_seconds=host_timeout)

        bundle = parse_static_workspace(analysis_id=job_id, workspace=artifacts.workspace)
        insert_static_analysis(bundle.row)
        update_job_static_fingerprint(
            job_id,
            imphash=bundle.imphash,
            ssdeep=bundle.ssdeep,
            tlsh=bundle.tlsh,
        )
        log_event(
            AuditEvent(
                job_id,
                "static_findings_persisted",
                {
                    "format": bundle.row.file_format,
                    "yara_count": len(bundle.deep_yara_matches),
                    "capa_count": len(bundle.capa_capabilities),
                },
            )
        )

        # Persist signatures + bands; then look for near-duplicates.
        best_hit = _persist_and_find_similar(
            job_id, sample_hash_sha256, bundle, similarity_store, settings
        )

        cleanup_completed(staging_root, job_id)

        if best_hit is not None:
            mark_near_duplicate(job_id, best_hit.analysis_id, best_hit.similarity)
            log_event(
                AuditEvent(
                    job_id,
                    "near_duplicate_short_circuit",
                    {
                        "parent": str(best_hit.analysis_id),
                        "score": best_hit.similarity,
                        "flavour": best_hit.flavour,
                    },
                )
            )
            update_job_status(
                job_id,
                JobStatus.COMPLETED,
                completed_at=datetime.now(timezone.utc),
                result_summary={
                    "near_duplicate_of": str(best_hit.analysis_id),
                    "near_duplicate_score": best_hit.similarity,
                    "flavour": best_hit.flavour,
                    "detonation_skipped": True,
                },
            )
            return {
                "job_id": str(job_id),
                "status": "near_duplicate",
                "parent": str(best_hit.analysis_id),
                "score": best_hit.similarity,
            }

        # Otherwise chain into the existing Windows detonation pipeline.
        from .tasks import analyze_malware_sample  # local import: avoids cycle on celery_app load

        analyze_malware_sample.apply_async(
            args=[str(job_id), sample_hash_sha256, sample_name, timeout_seconds],
            priority=priority,
            queue="analysis",
        )
        log_event(AuditEvent(job_id, "detonation_chained", {}))
        return {
            "job_id": str(job_id),
            "status": "chained_to_detonation",
        }

    except GuestDriverError as exc:
        log.exception("Linux guest did not complete for job %s", job_id)
        _fail(job_id, f"static_guest_timeout: {exc}")
        raise
    except Exception as exc:
        log.exception("Static analysis failed for job %s", job_id)
        _fail(job_id, f"static_failed: {exc}")
        raise
    finally:
        if vm is not None:
            try:
                client.revert_snapshot(vm, snapshot=settings.linux_vm_pool.clean_snapshot)
                log_event(AuditEvent(job_id, "linux_vm_reverted", {"vmid": vm.vmid}))
            except Exception:
                log.exception("Failed to revert Linux VM %s for job %s", vm.vmid, job_id)
        if acquired_vmid is not None:
            try:
                pool.release(acquired_vmid, job_id)
            except Exception:
                log.exception("Failed to release linux vmid %s for job %s", acquired_vmid, job_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clone_and_start(
    client: ProxmoxClient, vmid: int, job_id: UUID, settings
) -> GuestVM:
    # The Linux pool uses a different template than the Windows one — we can't
    # reuse `proxmox_client.clone_from_template` directly because it pulls
    # template_vmid from settings.proxmox. Open-coded clone here keeps the
    # narrow ProxmoxClient surface untouched.
    node = client._api.nodes(settings.proxmox.node)  # noqa: SLF001 — narrow API
    node.qemu(settings.linux_vm_pool.template_vmid).clone.post(
        newid=vmid,
        name=f"sandgnat-static-{vmid}",
        snapname=settings.linux_vm_pool.clean_snapshot,
        full=0,
    )
    vm = GuestVM(vmid=vmid, node=settings.proxmox.node)
    client.start(vm)
    client.wait_for_status(vm, "running")
    return vm


def _persist_and_find_similar(
    job_id: UUID,
    sample_sha256: str,
    bundle: StaticAnalysisBundle,
    store: PostgresSimilarityStore,
    settings,
) -> SimilarityHit | None:
    """Store byte + opcode signatures (if present); return the best similarity
    hit at or above the configured short-circuit threshold."""
    threshold = settings.static.short_circuit_threshold
    flavour_pref = settings.static.short_circuit_flavour

    candidates_by_flavour: dict[str, SimilarityHit | None] = {}
    for flavour, sig in (
        ("byte", bundle.byte_signature),
        ("opcode", bundle.opcode_signature),
    ):
        if sig is None:
            candidates_by_flavour[flavour] = None
            continue
        store.store_signature(job_id, sample_sha256, flavour, sig)
        hits = find_similar(
            analysis_id=job_id,
            sample_sha256=sample_sha256,
            signature=sig,
            flavour=flavour,
            store=store,
        )
        cache_top_edges(analysis_id=job_id, hits=hits, store=store)
        candidates_by_flavour[flavour] = short_circuit_decision(hits, threshold)

    # Apply the operator-chosen preference between the two flavours.
    if flavour_pref == "byte":
        return candidates_by_flavour.get("byte")
    if flavour_pref == "opcode":
        return candidates_by_flavour.get("opcode")
    # 'either' — take whichever scored higher.
    best: SimilarityHit | None = None
    for hit in candidates_by_flavour.values():
        if hit is not None and (best is None or hit.similarity > best.similarity):
            best = hit
    return best


def _fail(job_id: UUID, reason: str) -> None:
    update_job_status(job_id, JobStatus.FAILED, completed_at=datetime.now(timezone.utc))
    log_event(AuditEvent(job_id, "static_analysis_failed", {"error": reason}))
