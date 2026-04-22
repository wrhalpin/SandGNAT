# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Per-job detonation pipeline.

Given a JobManifest and a working directory on the guest, run:

    1. Take RegShot baseline.
    2. Start ProcMon and tshark.
    3. Snapshot dropped-file roots.
    4. Execute the sample with timeout.
    5. Stop tshark and ProcMon.
    6. Take RegShot post-shot + diff.
    7. Collect changed/new files under the watched roots.
    8. Return a fully-populated ResultEnvelope.

The function is deliberately synchronous: one detonation, one call, one
result. The watcher loop wraps multiple invocations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from orchestrator.schema import (
    DROPPED_DIR,
    PCAP_FILE,
    PROCMON_CSV,
    REGSHOT_DIFF,
    SCHEMA_VERSION,
    SLEEP_PATCHES_JSONL,
    CaptureOutcome,
    JobManifest,
    ResultEnvelope,
)

from .activity import ActivitySimulator, load_activity_config
from .capture import (
    ProcmonCapture,
    RegshotCapture,
    TsharkCapture,
    collect_dropped_files,
    snapshot_roots,
)
from .config import GuestConfig
from .executor import execute_sample
from .stealth.injector import InjectResult, inject_dll


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _locate_sleep_patcher_dll() -> Path | None:
    """Find sleep_patcher.dll next to the frozen agent (Phase E).

    Search order: SANDGNAT_SLEEP_PATCHER_DLL env override, then
    <agent_dir>/sleep_patcher.dll. Returns None when the DLL isn't
    present — injection is best-effort.
    """
    import os
    from sys import argv, executable
    override = os.environ.get("SANDGNAT_SLEEP_PATCHER_DLL")
    if override:
        path = Path(override)
        return path if path.exists() else None
    # PyInstaller-frozen exe puts sys.executable next to the DLL;
    # a dev-mode `python -m guest_agent` falls back to the module dir.
    agent_dir = Path(executable).resolve().parent
    candidate = agent_dir / "sleep_patcher.dll"
    if candidate.exists():
        return candidate
    module_candidate = Path(argv[0]).resolve().parent / "sleep_patcher.dll"
    return module_candidate if module_candidate.exists() else None


def run_job(manifest: JobManifest, config: GuestConfig, workspace: Path) -> ResultEnvelope:
    """Execute one job and return its result envelope.

    `workspace` is the staging directory for this job's artifacts, typically
    `{staging_root}/in-flight/{job_id}/`. All capture outputs land here and are
    later moved to the `completed/` directory by the watcher.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    dropped_dir = workspace / DROPPED_DIR

    started_at = _iso_now()
    captures: list[CaptureOutcome] = []
    errors: list[str] = []

    # 1. RegShot baseline ----------------------------------------------------
    regshot = RegshotCapture(
        regshot_exe=config.regshot_exe,
        baseline_shot=workspace / "regshot_baseline.hiv",
        post_shot=workspace / "regshot_post.hiv",
        diff_output=workspace / REGSHOT_DIFF,
    )
    if manifest.capture.regshot:
        captures.append(regshot.take_baseline())

    # 2. ProcMon + tshark ----------------------------------------------------
    procmon = ProcmonCapture(
        procmon_exe=config.procmon_exe,
        backing_file=workspace / "procmon.pml",
        csv_output=workspace / PROCMON_CSV,
    )
    if manifest.capture.procmon:
        captures.append(procmon.start())

    tshark = TsharkCapture(
        tshark_exe=config.tshark_exe,
        output_pcap=workspace / PCAP_FILE,
        interface=config.capture_interface,
    )
    if manifest.capture.tshark:
        captures.append(tshark.start())

    # 3. File inventory ------------------------------------------------------
    watched_roots = [Path(p) for p in manifest.capture.dropped_file_roots]
    baseline_inventory = snapshot_roots(watched_roots)

    # 4. Spin up the user-activity simulator (Phase D). The warmup
    # window inside the simulator delays real input until a GUI-driven
    # installer has moved past its first prompt.
    simulator = ActivitySimulator(load_activity_config())
    simulator.start()

    # 5. Prepare Phase-E sleep-patch injection. The DLL lives next to
    # the frozen agent; if it's missing, we log and press on — Phase G
    # still catches the import pattern.
    sleep_patch_log = workspace / SLEEP_PATCHES_JSONL
    sleep_patch_dll = _locate_sleep_patcher_dll()
    inject_results: list[InjectResult] = []

    def _on_sample_spawned(pid: int) -> None:
        if sleep_patch_dll is None:
            return
        result = inject_dll(pid, sleep_patch_dll)
        inject_results.append(result)

    # 6. Detonate -----------------------------------------------------------
    exec_result = execute_sample(
        sample_path=Path(manifest.sample_guest_path),
        arguments=manifest.arguments,
        timeout_seconds=manifest.timeout_seconds,
        env_overrides={"SANDGNAT_SLEEP_PATCH_LOG": str(sleep_patch_log)},
        on_spawned=_on_sample_spawned,
    )
    if exec_result.error:
        errors.append(f"execution: {exec_result.error}")
    for ir in inject_results:
        if not ir.ok:
            errors.append(f"sleep_patch_inject: {ir.reason}")

    # 6. Tear down the simulator before freezing captures — any stray
    # input the loops generate after this point would pollute the
    # ProcMon tail.
    activity_summary = simulator.stop()
    if activity_summary.errors:
        for loop_name, loop_errors in activity_summary.errors.items():
            errors.append(f"activity[{loop_name}]: {'; '.join(loop_errors)}")

    # 7. Stop dynamic captures ----------------------------------------------
    if manifest.capture.tshark:
        captures.append(tshark.stop())
    if manifest.capture.procmon:
        captures.append(procmon.stop())

    # 8. RegShot post + diff -------------------------------------------------
    if manifest.capture.regshot:
        captures.append(regshot.take_post_and_diff())

    # 9. Collect dropped files ----------------------------------------------
    dropped_records = collect_dropped_files(
        roots=watched_roots,
        baseline=baseline_inventory,
        destination_dir=dropped_dir,
        max_file_bytes=manifest.capture.max_dropped_file_bytes,
    )

    # 10. Build envelope -----------------------------------------------------
    status = "completed"
    if exec_result.error:
        status = "failed"
    elif exec_result.timed_out:
        status = "timeout"

    return ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id=manifest.job_id,
        status=status,
        started_at=started_at,
        completed_at=_iso_now(),
        execution_duration_seconds=exec_result.duration_seconds,
        sample_pid=exec_result.pid,
        sample_exit_code=exec_result.exit_code,
        timed_out=exec_result.timed_out,
        captures=captures,
        dropped_files=dropped_records,
        errors=errors,
    )
