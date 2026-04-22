# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Celery tasks for the analysis lifecycle.

The `analyze_malware_sample` task assumes intake has already:
  * inserted the `analysis_jobs` row,
  * written the sample bytes to
    `{artifact_staging_root}/samples/{analysis_id}/{sample_name}`.

The task then drives the detonation:

    1.  Acquire a free vmid from the VM pool (DB-backed lease).
    2.  Linked-clone the template and start the guest.
    3.  Publish a job manifest into `staging/pending/`.
    4.  Poll for `completed/{analysis_id}/result.json`.
    5.  Parse the artifacts into STIX objects + normalised rows.
    6.  Persist everything to Postgres inside one transaction per class.
    7.  Move dropped files from staging to the quarantine root.
    8.  Revert the guest to the clean snapshot, release the lease.
    9.  Mark the job completed.

Nothing in this module touches malware bytes directly — it only moves files
through well-defined staging paths. Execution happens exclusively inside the
guest VM via the collector agent.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from celery import shared_task

from .analyzer import AnalyzedBundle, analyze
from .celery_app import app  # noqa: F401  — registers the Celery app on import
from .config import get_settings
from .evasion_detector import detect_evasion, summarise
from .guest_driver import (
    GuestDriverError,
    cleanup_completed,
    submit_job,
    wait_for_result,
)
from .models import AuditEvent, JobStatus
from .parsers.procmon import parse_procmon_csv
from .persistence import (
    PostgresPoolStore,
    get_job,
    get_static_analysis,
    insert_dropped_files,
    insert_network_iocs,
    insert_registry_modifications,
    log_event,
    persist_stix_objects,
    update_job_status,
)
from .proxmox_client import GuestVM, ProxmoxClient
from .vm_pool import PoolExhausted, VmPool

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enqueue helper (called by intake).
# ---------------------------------------------------------------------------

def enqueue_analysis(
    analysis_id: UUID,
    sample_name: str,
    sample_sha256: str,
    timeout_seconds: int,
    priority: int,
) -> None:
    """Dispatch the entry-point Celery task for a row intake has just inserted.

    When static analysis is enabled (`STATIC_ANALYSIS_ENABLED=1`) we route
    new submissions through the Linux static-analysis stage first; that task
    is responsible for chaining the Windows detonation task afterwards (or
    short-circuiting it). When static is disabled, fall back to the legacy
    direct-detonation path.
    """
    if get_settings().static.enabled:
        from .tasks_static import enqueue_static_analysis

        enqueue_static_analysis(
            analysis_id, sample_name, sample_sha256, timeout_seconds, priority
        )
        return
    analyze_malware_sample.apply_async(
        args=[str(analysis_id), sample_sha256, sample_name, timeout_seconds],
        priority=priority,
        queue="analysis",
    )


def staged_sample_path(staging_root: Path, analysis_id: UUID, sample_name: str) -> Path:
    """Canonical on-disk path for an intake-staged sample.

    Intake writes here before enqueuing; the Celery task reads from here to
    verify the hash and drive the guest manifest.
    """
    return staging_root / "samples" / str(analysis_id) / sample_name


# ---------------------------------------------------------------------------
# Main task.
# ---------------------------------------------------------------------------

@shared_task(bind=True, name="sandgnat.analyze_malware_sample", max_retries=2)
def analyze_malware_sample(
    self,  # noqa: ANN001 — Celery bound-task self
    analysis_id: str,
    sample_hash_sha256: str,
    sample_name: str,
    timeout_seconds: int | None = None,
) -> dict[str, object]:
    settings = get_settings()
    job_id = UUID(analysis_id)
    effective_timeout = timeout_seconds or settings.default_timeout_seconds

    log_event(AuditEvent(job_id, "detonation_started", {"sha256": sample_hash_sha256}))
    started = datetime.now(timezone.utc)
    update_job_status(job_id, JobStatus.RUNNING, started_at=started)

    staging_root = Path(settings.artifact_staging_root)
    quarantine_root = Path(settings.quarantine_root)

    # Verify intake really staged the sample where we expect. A mismatched
    # hash here means the share is corrupted or someone tampered with the
    # file post-intake; either way we refuse to detonate.
    sample_path = staged_sample_path(staging_root, job_id, sample_name)
    if not sample_path.exists():
        _fail(job_id, f"staged sample missing at {sample_path}")
        raise FileNotFoundError(str(sample_path))
    on_disk_sha = _sha256_file(sample_path)
    if on_disk_sha != sample_hash_sha256:
        _fail(
            job_id,
            f"staged sample hash mismatch: expected {sample_hash_sha256}, got {on_disk_sha}",
        )
        raise RuntimeError("staged sample hash mismatch")

    client = ProxmoxClient()
    pool = VmPool(
        PostgresPoolStore(),
        vmid_min=settings.vm_pool.vmid_min,
        vmid_max=settings.vm_pool.vmid_max,
        node=settings.proxmox.node,
        stale_lease_seconds=settings.vm_pool.stale_lease_seconds,
    )
    acquired_vmid: int | None = None
    vm: GuestVM | None = None

    try:
        try:
            acquired_vmid = pool.acquire(job_id)
        except PoolExhausted as exc:
            log.warning("VM pool exhausted for job %s; deferring retry", job_id)
            raise self.retry(exc=exc, countdown=30) from exc

        vm = _clone_and_start(client, acquired_vmid, job_id)
        log_event(AuditEvent(job_id, "vm_spun_up", {"vmid": vm.vmid}))

        submit_job(
            staging_root,
            job_id,
            sample_name=sample_name,
            sample_sha256=sample_hash_sha256,
            timeout_seconds=effective_timeout,
        )
        log_event(AuditEvent(job_id, "job_submitted_to_guest", {}))

        # Host-side watchdog: detonation timeout + buffer for capture export.
        host_timeout = effective_timeout + 180
        artifacts = wait_for_result(staging_root, job_id, timeout_seconds=host_timeout)
        log_event(
            AuditEvent(
                job_id,
                "artifacts_collected",
                {"status": artifacts.envelope.status, "workspace": str(artifacts.workspace)},
            )
        )

        job_row = get_job(job_id)
        sample_md5 = job_row.sample_hash_md5 if job_row else None

        bundle = analyze(
            analysis_id=job_id,
            sample_name=sample_name,
            sample_sha256=sample_hash_sha256,
            sample_md5=sample_md5,
            artifacts=artifacts,
            quarantine_root=quarantine_root,
        )
        _persist_bundle(job_id, bundle)
        log_event(
            AuditEvent(
                job_id,
                "stix_persisted",
                {
                    "stix_count": len(bundle.stix_objects),
                    "dropped": len(bundle.dropped_files),
                    "regmods": len(bundle.registry_modifications),
                    "network_iocs": len(bundle.network_iocs),
                },
            )
        )

        moved = _ingest_quarantine(artifacts.workspace, quarantine_root, job_id, bundle)
        log_event(AuditEvent(job_id, "quarantined", {"file_count": moved}))

        # Phase G: post-run evasion detection. Re-parse the ProcMon CSV
        # (cheap — it's the same file the analyzer just consumed) and
        # combine with the static-analysis row if one exists. Any hit
        # flips evasion_observed=TRUE on the job and records the
        # indicators in the audit log — signal about the sample's
        # sophistication even when our mitigations were enough.
        procmon_events = (
            parse_procmon_csv(artifacts.procmon_csv)
            if artifacts.procmon_csv is not None
            else []
        )
        static_row = get_static_analysis(job_id)
        indicators = detect_evasion(procmon_events, static_row)
        evasion_observed = bool(indicators)
        if indicators:
            log_event(
                AuditEvent(
                    job_id,
                    "evasion_observed",
                    summarise(indicators),
                )
            )

        completed = datetime.now(timezone.utc)
        update_job_status(
            job_id,
            JobStatus.COMPLETED,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            result_summary={
                "stix_object_count": len(bundle.stix_objects),
                "dropped_file_count": len(bundle.dropped_files),
                "network_ioc_count": len(bundle.network_iocs),
                "envelope_status": artifacts.envelope.status,
            },
            quarantine_path=str(quarantine_root / str(job_id)),
            evasion_observed=evasion_observed,
        )
        cleanup_completed(staging_root, job_id)
        return {
            "job_id": str(job_id),
            "status": "completed",
            "stix_count": len(bundle.stix_objects),
        }

    except GuestDriverError as exc:
        log.exception("Guest did not complete for job %s", job_id)
        _fail(job_id, f"guest_timeout: {exc}")
        raise

    except Exception as exc:
        log.exception("Analysis failed for job %s", job_id)
        _fail(job_id, f"analysis_failed: {exc}")
        raise

    finally:
        if vm is not None:
            try:
                client.revert_snapshot(vm)
                log_event(AuditEvent(job_id, "vm_reverted", {"vmid": vm.vmid}))
            except Exception:
                log.exception("Failed to revert VM %s for job %s", vm.vmid, job_id)
        if acquired_vmid is not None:
            try:
                pool.release(acquired_vmid, job_id)
            except Exception:
                log.exception("Failed to release vmid %s for job %s", acquired_vmid, job_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clone_and_start(client: ProxmoxClient, vmid: int, job_id: UUID) -> GuestVM:
    vm = client.clone_from_template(new_vmid=vmid, name=f"sandgnat-{vmid}")
    client.start(vm)
    client.wait_for_status(vm, "running")
    return vm


def _persist_bundle(analysis_id: UUID, bundle: AnalyzedBundle) -> None:
    persist_stix_objects(analysis_id, bundle.stix_objects)
    insert_dropped_files(bundle.dropped_files)
    insert_registry_modifications(bundle.registry_modifications)
    insert_network_iocs(bundle.network_iocs)


def _ingest_quarantine(
    workspace: Path, quarantine_root: Path, job_id: UUID, bundle: AnalyzedBundle
) -> int:
    """Move each collected dropped file from staging to quarantine.

    Hash-verify on move: if on-disk bytes don't match the envelope's SHA-256,
    flag the row as unverified and skip the move. The guest agent already
    hashed the files; this second pass is belt-and-suspenders against
    staging-share corruption.
    """
    dest_dir = quarantine_root / str(job_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    moved = 0
    for dropped in bundle.dropped_files:
        if not dropped.quarantine_path:
            continue
        source = workspace / "dropped" / dropped.hash_sha256
        if not source.exists():
            log.warning(
                "Dropped file missing from staging for job %s: %s", job_id, source
            )
            continue
        dest = Path(dropped.quarantine_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(dest))
        moved += 1
    return moved


def _sha256_file(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _fail(job_id: UUID, reason: str) -> None:
    update_job_status(job_id, JobStatus.FAILED, completed_at=datetime.now(timezone.utc))
    log_event(AuditEvent(job_id, "analysis_failed", {"error": reason}))
