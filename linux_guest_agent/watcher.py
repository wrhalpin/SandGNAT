# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Polling watcher for the Linux static-analysis guest.

Identical staging contract to `guest_agent/watcher.py`:

    {staging}/pending/{job_id}.json   -> claimed via os.rename
    {staging}/in-flight/{job_id}/     -> per-job workspace
    {staging}/completed/{job_id}/     -> result.json + tool outputs

The only behavioural difference is the mode guard: this guest refuses any
manifest whose `mode != "static_analysis"` so a misrouted detonation job
fails fast in the guest instead of producing an empty envelope.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path

from orchestrator.schema import (
    MANIFEST_FILENAME,
    MODE_STATIC_ANALYSIS,
    RESULT_FILENAME,
    SCHEMA_VERSION,
    JobManifest,
    ResultEnvelope,
)

from .config import LinuxGuestConfig
from .runner import run_static_job

log = logging.getLogger(__name__)


def _pending_dir(cfg: LinuxGuestConfig) -> Path:
    return cfg.staging_root / "pending"


def _in_flight_dir(cfg: LinuxGuestConfig) -> Path:
    return cfg.staging_root / "in-flight"


def _completed_dir(cfg: LinuxGuestConfig) -> Path:
    return cfg.staging_root / "completed"


def _ensure_dirs(cfg: LinuxGuestConfig) -> None:
    for d in (_pending_dir(cfg), _in_flight_dir(cfg), _completed_dir(cfg)):
        d.mkdir(parents=True, exist_ok=True)


def _claim_next_job(cfg: LinuxGuestConfig) -> tuple[JobManifest, Path] | None:
    pending = _pending_dir(cfg)
    for candidate in sorted(pending.glob("*.json")):
        job_id = candidate.stem
        workspace = _in_flight_dir(cfg) / job_id
        try:
            workspace.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        target = workspace / MANIFEST_FILENAME
        try:
            os.rename(candidate, target)
        except OSError as exc:
            log.warning("Failed to claim %s: %s", candidate, exc)
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
        if manifest.mode != MODE_STATIC_ANALYSIS:
            log.error(
                "Refusing job %s: mode=%r, this is the static-analysis guest",
                job_id, manifest.mode,
            )
            _write_failure_result(
                cfg, job_id, workspace,
                f"mode {manifest.mode!r} not supported by static-analysis guest",
            )
            continue
        return manifest, workspace
    return None


def _write_failure_result(
    cfg: LinuxGuestConfig, job_id: str, workspace: Path, message: str
) -> None:
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
        mode=MODE_STATIC_ANALYSIS,
        errors=[message],
    )
    (workspace / RESULT_FILENAME).write_text(envelope.to_json(), encoding="utf-8")
    _promote_to_completed(cfg, job_id, workspace)


def _promote_to_completed(cfg: LinuxGuestConfig, job_id: str, workspace: Path) -> None:
    target = _completed_dir(cfg) / job_id
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    os.rename(workspace, target)


def _reap_stale_in_flight(cfg: LinuxGuestConfig) -> None:
    for workspace in _in_flight_dir(cfg).iterdir():
        if not workspace.is_dir():
            continue
        job_id = workspace.name
        manifest_path = workspace / MANIFEST_FILENAME
        if not manifest_path.exists():
            shutil.rmtree(workspace, ignore_errors=True)
            continue
        log.warning("Reaping stale in-flight job: %s", job_id)
        _write_failure_result(
            cfg, job_id, workspace, "static-analysis agent restarted while job was in-flight"
        )


def _process_one(
    cfg: LinuxGuestConfig, manifest: JobManifest, workspace: Path
) -> None:
    log.info("Starting static job %s (%s)", manifest.job_id, manifest.sample_name)
    try:
        envelope = run_static_job(manifest, cfg, workspace)
    except Exception as exc:  # noqa: BLE001 — never let the watcher die
        log.exception("Static runner crashed for job %s", manifest.job_id)
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
            mode=MODE_STATIC_ANALYSIS,
            errors=[f"runner crashed: {exc}"],
        )

    tmp = workspace / (RESULT_FILENAME + ".tmp")
    tmp.write_text(envelope.to_json(), encoding="utf-8")
    os.replace(tmp, workspace / RESULT_FILENAME)
    _promote_to_completed(cfg, manifest.job_id, workspace)
    log.info("Completed static job %s (status=%s)", manifest.job_id, envelope.status)


def serve(cfg: LinuxGuestConfig, *, run_once: bool = False) -> None:
    """Main loop. Set `run_once=True` in tests to process a single job."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    _ensure_dirs(cfg)
    _reap_stale_in_flight(cfg)

    log.info("linux static-analysis guest watching %s", cfg.staging_root)
    while True:
        claim = _claim_next_job(cfg)
        if claim is not None:
            manifest, workspace = claim
            _process_one(cfg, manifest, workspace)
            if run_once:
                return
        else:
            time.sleep(cfg.poll_interval)
