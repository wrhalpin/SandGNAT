# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Sample execution.

Runs the sample with a hard timeout. Returns (pid, exit_code, timed_out,
duration_seconds). Non-zero exits are *not* errors — malware crashes are
behaviourally interesting and the envelope just reports what happened.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ExecutionResult:
    """Outcome of one sample execution: pid, exit code, timeout flag,
    wallclock duration, plus an optional error for spawn failures."""

    pid: int | None
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    error: str | None = None


def execute_sample(
    sample_path: Path,
    arguments: list[str],
    *,
    timeout_seconds: int,
    working_dir: Path | None = None,
) -> ExecutionResult:
    """Run the sample with a hard timeout. Never raises.

    Spawn failure, timeout, and non-zero exit all resolve to a populated
    `ExecutionResult` — the analyzer treats crashes as behavioural data, not
    errors.
    """
    if not sample_path.exists():
        return ExecutionResult(
            pid=None,
            exit_code=None,
            timed_out=False,
            duration_seconds=0.0,
            error=f"sample not found: {sample_path}",
        )

    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            [str(sample_path), *arguments],
            cwd=str(working_dir) if working_dir else str(sample_path.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        return ExecutionResult(
            pid=None,
            exit_code=None,
            timed_out=False,
            duration_seconds=0.0,
            error=f"failed to spawn sample: {exc}",
        )

    try:
        exit_code = proc.wait(timeout=timeout_seconds)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            exit_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            exit_code = None
        timed_out = True

    return ExecutionResult(
        pid=proc.pid,
        exit_code=exit_code,
        timed_out=timed_out,
        duration_seconds=time.monotonic() - start,
    )
