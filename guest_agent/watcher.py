"""Watch the staging share and process one job at a time.

The guest agent is single-threaded by design: concurrent detonations in the
same VM would contaminate each other's artifacts. Host-side parallelism is
the job of the orchestrator, which uses multiple analysis VMs.

Pickup protocol:

    1. Host writes `{staging}/pending/{job_id}.json`.
    2. Guest attempts `os.rename` -> `{staging}/in-flight/{job_id}/job.json`.
       The rename is atomic on both NTFS and POSIX; whichever guest wins the
       race owns the job. (Today there's only ever one guest per share, but
       the protocol is correct even if we scale out.)
    3. Guest runs the job into the `in-flight` workspace.
    4. Guest writes `result.json` to the workspace, then renames the whole
       directory to `{staging}/completed/{job_id}/`. Host polls for that
       directory's existence + `result.json` before reading artifacts.

A crashed guest leaves a half-processed `in-flight/{job_id}/` directory. On
startup we scan `in-flight/` and mark abandoned jobs as failed so the host
isn't left hanging. That recovery is implemented in `_reap_stale_in_flight`.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from pathlib import Path

from orchestrator.schema import (
    MANIFEST_FILENAME,
    RESULT_FILENAME,
    SCHEMA_VERSION,
    JobManifest,
    ResultEnvelope,
)

from .config import GuestConfig
from .runner import run_job

log = logging.getLogger(__name__)


def _pending_dir(cfg: GuestConfig) -> Path:
    return cfg.staging_root / "pending"


def _in_flight_dir(cfg: GuestConfig) -> Path:
    return cfg.staging_root / "in-flight"


def _completed_dir(cfg: GuestConfig) -> Path:
    return cfg.staging_root / "completed"


def _ensure_dirs(cfg: GuestConfig) -> None:
    for d in (_pending_dir(cfg), _in_flight_dir(cfg), _completed_dir(cfg)):
        d.mkdir(parents=True, exist_ok=True)


def _claim_next_job(cfg: GuestConfig) -> tuple[JobManifest, Path] | None:
    """Atomically move one pending manifest to in-flight and return it.

    Returns (manifest, workspace_path) or None if nothing is pending.
    """
    pending = _pending_dir(cfg)
    for candidate in sorted(pending.glob("*.json")):
        job_id = candidate.stem
        workspace = _in_flight_dir(cfg) / job_id
        try:
            workspace.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            # Another guest took this one, or a prior crash left debris.
            continue
        target = workspace / MANIFEST_FILENAME
        try:
            os.rename(candidate, target)
        except OSError as exc:
            log.warning("Failed to claim %s: %s", candidate, exc)
            # Best-effort cleanup of the empty workspace.
            try:
                workspace.rmdir()
            except OSError:
                pass
            continue
        try:
            manifest = JobManifest.from_json(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.error("Invalid manifest %s: %s", target, exc)
            _write_failure_result(cfg, job_id, workspace, f"invalid manifest: {exc}")
            continue
        return manifest, workspace
    return None


def _write_failure_result(
    cfg: GuestConfig, job_id: str, workspace: Path, message: str
) -> None:
    """Record a synthetic failure envelope so the host doesn't wait forever."""
    envelope = ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id=job_id,
        status="failed",
        started_at="",
        completed_at="",
        execution_duration_seconds=0.0,
        sample_pid=None,
        sample_exit_code=None,
        timed_out=False,
        errors=[message],
    )
    (workspace / RESULT_FILENAME).write_text(envelope.to_json(), encoding="utf-8")
    _promote_to_completed(cfg, job_id, workspace)


def _promote_to_completed(cfg: GuestConfig, job_id: str, workspace: Path) -> None:
    target = _completed_dir(cfg) / job_id
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    os.rename(workspace, target)


def _reap_stale_in_flight(cfg: GuestConfig) -> None:
    """On startup, fail any job left in-flight from a prior guest crash."""
    for workspace in _in_flight_dir(cfg).iterdir():
        if not workspace.is_dir():
            continue
        job_id = workspace.name
        manifest_path = workspace / MANIFEST_FILENAME
        if not manifest_path.exists():
            # Never got far enough to have a manifest; just discard.
            shutil.rmtree(workspace, ignore_errors=True)
            continue
        log.warning("Reaping stale in-flight job: %s", job_id)
        _write_failure_result(
            cfg, job_id, workspace, "agent restarted while job was in-flight"
        )


def _process_one(cfg: GuestConfig, manifest: JobManifest, workspace: Path) -> None:
    log.info("Starting job %s (%s)", manifest.job_id, manifest.sample_name)
    try:
        envelope = run_job(manifest, cfg, workspace)
    except Exception as exc:  # noqa: BLE001 — never let the watcher die
        log.exception("Runner crashed for job %s", manifest.job_id)
        envelope = ResultEnvelope(
            schema_version=SCHEMA_VERSION,
            job_id=manifest.job_id,
            status="failed",
            started_at="",
            completed_at="",
            execution_duration_seconds=0.0,
            sample_pid=None,
            sample_exit_code=None,
            timed_out=False,
            errors=[f"runner crashed: {exc}"],
        )

    # Write result envelope atomically: write-then-rename so the host never
    # sees a partial JSON file.
    tmp = workspace / (RESULT_FILENAME + ".tmp")
    tmp.write_text(envelope.to_json(), encoding="utf-8")
    os.replace(tmp, workspace / RESULT_FILENAME)
    _promote_to_completed(cfg, manifest.job_id, workspace)
    log.info("Completed job %s (status=%s)", manifest.job_id, envelope.status)


def serve(cfg: GuestConfig, *, run_once: bool = False) -> None:
    """Main loop. Set `run_once=True` in tests to process exactly one job."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    _ensure_dirs(cfg)
    _reap_stale_in_flight(cfg)

    log.info("guest agent watching %s", cfg.staging_root)
    while True:
        claim = _claim_next_job(cfg)
        if claim is not None:
            manifest, workspace = claim
            _process_one(cfg, manifest, workspace)
            if run_once:
                return
        else:
            time.sleep(cfg.poll_interval)
