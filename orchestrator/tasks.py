"""Celery tasks for the analysis lifecycle.

The `analyze_malware_sample` task is the entry point invoked by the intake
service (not yet implemented — coming in Phase 4). It walks the ten-step
lifecycle documented in the design doc.

NOTE: several guest-interaction steps (`_deliver_sample`, `_detonate`,
`_collect_artifacts`) are stubs pending the Windows collector agent. They
raise NotImplementedError rather than returning fake data, because silent
"works on empty input" behaviour would mask missing infrastructure.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from celery import shared_task

from .celery_app import app  # noqa: F401  — registers the Celery app on import
from .config import get_settings
from .models import (
    AnalysisJob,
    AuditEvent,
    JobStatus,
)
from .persistence import (
    insert_job,
    log_event,
    persist_stix_objects,
    update_job_status,
)
from .proxmox_client import GuestVM, ProxmoxClient
from .stix_builder import FileHashes, build_file, build_malware

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
    job = AnalysisJob(
        id=uuid4(),
        sample_hash_sha256=sample_hash_sha256,
        sample_name=sample_name,
        status=JobStatus.QUEUED,
        timeout_seconds=timeout_seconds or settings.default_timeout_seconds,
    )
    insert_job(job)
    log_event(AuditEvent(job.id, "sample_submitted", {"sha256": sample_hash_sha256}))

    started = datetime.now(timezone.utc)
    update_job_status(job.id, JobStatus.RUNNING, started_at=started)

    client = ProxmoxClient()
    vm: GuestVM | None = None
    try:
        vm = _spin_up_guest(client, job.id)
        log_event(AuditEvent(job.id, "vm_spun_up", {"vmid": vm.vmid}))

        _deliver_sample(vm, Path(sample_path))
        log_event(AuditEvent(job.id, "sample_delivered", {}))

        _detonate(vm, job.timeout_seconds)
        log_event(AuditEvent(job.id, "execution_completed", {}))

        artifacts_dir = _collect_artifacts(vm, job.id)
        log_event(AuditEvent(job.id, "artifacts_collected", {"path": str(artifacts_dir)}))

        stix_objects = _build_stix_from_artifacts(job.id, artifacts_dir, sample_name, sample_hash_sha256)
        persist_stix_objects(job.id, stix_objects)
        log_event(AuditEvent(job.id, "stix_persisted", {"count": len(stix_objects)}))

        completed = datetime.now(timezone.utc)
        update_job_status(
            job.id,
            JobStatus.COMPLETED,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            result_summary={"stix_object_count": len(stix_objects)},
        )
        return {"job_id": str(job.id), "status": "completed", "stix_count": len(stix_objects)}

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
# Lifecycle steps — guest-side work is stubbed pending the collector agent.
# ---------------------------------------------------------------------------

def _spin_up_guest(client: ProxmoxClient, job_id: UUID) -> GuestVM:
    # Allocate a vmid from the pool. For the foundation scaffold we derive it
    # from the job UUID; production will use a dedicated pool manager.
    new_vmid = 9100 + (int(job_id.int) % 900)
    vm = client.clone_from_template(new_vmid=new_vmid, name=f"sandgnat-{new_vmid}")
    client.start(vm)
    client.wait_for_status(vm, "running")
    return vm


def _deliver_sample(vm: GuestVM, sample_path: Path) -> None:
    raise NotImplementedError(
        "Sample delivery requires the Windows collector agent (Phase 2)."
    )


def _detonate(vm: GuestVM, timeout_seconds: int) -> None:
    raise NotImplementedError(
        "Detonation requires the Windows collector agent (Phase 2)."
    )


def _collect_artifacts(vm: GuestVM, job_id: UUID) -> Path:
    raise NotImplementedError(
        "Artifact collection requires the Windows collector agent (Phase 2)."
    )


def _build_stix_from_artifacts(
    job_id: UUID,
    artifacts_dir: Path,
    sample_name: str | None,
    sample_hash_sha256: str,
) -> list[dict]:
    """Turn on-disk artifacts into STIX objects.

    Wired up in Phase 3; for now we emit the parent Malware + File objects so
    the persistence path is exercisable end-to-end during scaffold review.
    """
    sample_file = build_file(
        analysis_id=job_id,
        name=sample_name or "sample",
        hashes=FileHashes(sha256=sample_hash_sha256),
    )
    malware = build_malware(
        analysis_id=job_id,
        name=sample_name or "unnamed-sample",
        sample_hash_sha256=sample_hash_sha256,
        object_refs=[sample_file["id"]],
    )
    return [malware, sample_file]
