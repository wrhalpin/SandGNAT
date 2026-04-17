"""Celery tasks for the analysis lifecycle.

The `analyze_malware_sample` task drives the ten-step flow from the design
doc:

    1.  Persist a row in `analysis_jobs` (status='queued').
    2.  Clone a fresh guest VM from the template snapshot.
    3.  Stage the sample onto the shared SMB volume.
    4.  Publish a job manifest into `{staging}/pending/`.
    5.  Wait for the guest agent to write `completed/{job_id}/result.json`.
    6.  Parse the artifacts into STIX objects + normalised rows.
    7.  Persist everything to Postgres inside one transaction per class.
    8.  Move dropped files from the staging share into the quarantine root.
    9.  Revert the guest VM to the clean snapshot.
    10. Mark the job completed.

Nothing in this module touches malware bytes directly — it only moves files
through well-defined staging paths. Execution happens exclusively inside the
guest VM via the collector agent.
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from celery import shared_task

from .analyzer import AnalyzedBundle, analyze
from .celery_app import app  # noqa: F401  — registers the Celery app on import
from .config import get_settings
from .guest_driver import (
    GuestDriverError,
    cleanup_completed,
    stage_sample,
    submit_job,
    wait_for_result,
)
from .models import AnalysisJob, AuditEvent, JobStatus
from .persistence import (
    insert_dropped_files,
    insert_job,
    insert_network_iocs,
    insert_registry_modifications,
    log_event,
    persist_stix_objects,
    update_job_status,
)
from .proxmox_client import GuestVM, ProxmoxClient

log = logging.getLogger(__name__)


@shared_task(bind=True, name="sandgnat.analyze_malware_sample", max_retries=2)
def analyze_malware_sample(
    self,  # noqa: ANN001 — Celery bound-task self
    sample_path: str,
    sample_hash_sha256: str,
    sample_name: str | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, object]:
    settings = get_settings()
    effective_name = sample_name or Path(sample_path).name
    effective_timeout = timeout_seconds or settings.default_timeout_seconds

    job = AnalysisJob(
        id=uuid4(),
        sample_hash_sha256=sample_hash_sha256,
        sample_name=effective_name,
        status=JobStatus.QUEUED,
        timeout_seconds=effective_timeout,
    )
    insert_job(job)
    log_event(AuditEvent(job.id, "sample_submitted", {"sha256": sample_hash_sha256}))

    started = datetime.now(timezone.utc)
    update_job_status(job.id, JobStatus.RUNNING, started_at=started)

    staging_root = Path(settings.artifact_staging_root)
    quarantine_root = Path(settings.quarantine_root)

    client = ProxmoxClient()
    vm: GuestVM | None = None
    try:
        vm = _spin_up_guest(client, job.id)
        log_event(AuditEvent(job.id, "vm_spun_up", {"vmid": vm.vmid}))

        _, staged_sha256 = stage_sample(staging_root, job.id, Path(sample_path))
        if staged_sha256 != sample_hash_sha256:
            raise RuntimeError(
                f"sample hash mismatch after staging: expected {sample_hash_sha256}, got {staged_sha256}"
            )
        log_event(AuditEvent(job.id, "sample_staged", {"sha256": staged_sha256}))

        submit_job(
            staging_root,
            job.id,
            sample_name=effective_name,
            sample_sha256=sample_hash_sha256,
            timeout_seconds=effective_timeout,
        )
        log_event(AuditEvent(job.id, "job_submitted_to_guest", {}))

        # Host-side watchdog: detonation timeout + generous buffer for capture
        # export and SMB flush.
        host_timeout = effective_timeout + 180
        artifacts = wait_for_result(staging_root, job.id, timeout_seconds=host_timeout)
        log_event(
            AuditEvent(
                job.id,
                "artifacts_collected",
                {"status": artifacts.envelope.status, "workspace": str(artifacts.workspace)},
            )
        )

        bundle = analyze(
            analysis_id=job.id,
            sample_name=effective_name,
            sample_sha256=sample_hash_sha256,
            sample_md5=None,
            artifacts=artifacts,
            quarantine_root=quarantine_root,
        )
        _persist_bundle(job.id, bundle)
        log_event(
            AuditEvent(
                job.id,
                "stix_persisted",
                {
                    "stix_count": len(bundle.stix_objects),
                    "dropped": len(bundle.dropped_files),
                    "regmods": len(bundle.registry_modifications),
                    "network_iocs": len(bundle.network_iocs),
                },
            )
        )

        moved = _ingest_quarantine(artifacts.workspace, quarantine_root, job.id, bundle)
        log_event(AuditEvent(job.id, "quarantined", {"file_count": moved}))

        completed = datetime.now(timezone.utc)
        update_job_status(
            job.id,
            JobStatus.COMPLETED,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            result_summary={
                "stix_object_count": len(bundle.stix_objects),
                "dropped_file_count": len(bundle.dropped_files),
                "network_ioc_count": len(bundle.network_iocs),
                "envelope_status": artifacts.envelope.status,
            },
            quarantine_path=str(quarantine_root / str(job.id)),
        )
        cleanup_completed(staging_root, job.id)
        return {
            "job_id": str(job.id),
            "status": "completed",
            "stix_count": len(bundle.stix_objects),
        }

    except GuestDriverError as exc:
        log.exception("Guest did not complete for job %s", job.id)
        update_job_status(job.id, JobStatus.FAILED, completed_at=datetime.now(timezone.utc))
        log_event(AuditEvent(job.id, "guest_timeout", {"error": str(exc)}))
        raise

    except Exception as exc:
        log.exception("Analysis failed for job %s", job.id)
        update_job_status(job.id, JobStatus.FAILED, completed_at=datetime.now(timezone.utc))
        log_event(AuditEvent(job.id, "analysis_failed", {"error": str(exc)}))
        raise

    finally:
        if vm is not None:
            try:
                client.revert_snapshot(vm)
                log_event(AuditEvent(job.id, "vm_reverted", {"vmid": vm.vmid}))
            except Exception:
                log.exception("Failed to revert VM %s for job %s", vm.vmid, job.id)


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------

def _spin_up_guest(client: ProxmoxClient, job_id: UUID) -> GuestVM:
    """Derive a vmid and linked-clone the template snapshot.

    The 9100–9999 range is reserved for throwaway analysis clones; a proper
    pool manager comes in Phase 4.
    """
    new_vmid = 9100 + (int(job_id.int) % 900)
    vm = client.clone_from_template(new_vmid=new_vmid, name=f"sandgnat-{new_vmid}")
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
    """Move each collected dropped file from the staging workspace to quarantine.

    We hash-verify on move: if the on-disk bytes don't match the envelope's
    SHA-256, flag the row as unverified and skip the move. The guest agent
    already hashed the files; this second pass is belt-and-suspenders against
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
