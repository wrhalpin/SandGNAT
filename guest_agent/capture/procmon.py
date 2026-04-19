# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""ProcMon wrapper.

ProcMon is controlled via its CLI:

    Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile <pml>    # start
    Procmon.exe /Terminate                                          # stop
    Procmon.exe /OpenLog <pml> /SaveAs <csv> /SaveApplyFilter       # export

The first two calls return quickly but the capture keeps running in the
background until /Terminate. The third call blocks until the export is done.

We intentionally do *not* pass any /BackingFile-Limit or /RunTime — detonation
is short and we want the full timeline.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from orchestrator.schema import CaptureOutcome


@dataclass(slots=True)
class ProcmonCapture:
    procmon_exe: Path
    backing_file: Path  # .pml
    csv_output: Path

    _started: bool = False

    def start(self) -> CaptureOutcome:
        if not self.procmon_exe.exists():
            return CaptureOutcome(
                tool="procmon",
                started=False,
                stopped_cleanly=False,
                error=f"Procmon.exe not found at {self.procmon_exe}",
            )
        self.backing_file.parent.mkdir(parents=True, exist_ok=True)
        # /Quiet suppresses the EULA popup (already accepted by /AcceptEula).
        # /Minimized keeps the window out of the way during interactive work.
        cmd = [
            str(self.procmon_exe),
            "/AcceptEula",
            "/Quiet",
            "/Minimized",
            "/BackingFile",
            str(self.backing_file),
        ]
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            return CaptureOutcome(
                tool="procmon", started=False, stopped_cleanly=False, error=str(exc)
            )
        self._started = True
        return CaptureOutcome(tool="procmon", started=True, stopped_cleanly=False)

    def stop(self) -> CaptureOutcome:
        if not self._started:
            return CaptureOutcome(
                tool="procmon", started=False, stopped_cleanly=False, error="never started"
            )
        try:
            subprocess.run(
                [str(self.procmon_exe), "/Terminate"],
                check=False,
                timeout=30,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    str(self.procmon_exe),
                    "/OpenLog",
                    str(self.backing_file),
                    "/SaveAs",
                    str(self.csv_output),
                    "/SaveApplyFilter",
                ],
                check=False,
                timeout=300,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            return CaptureOutcome(
                tool="procmon",
                started=True,
                stopped_cleanly=False,
                output_filename=self.csv_output.name,
                error=f"timeout during stop/export: {exc}",
            )
        return CaptureOutcome(
            tool="procmon",
            started=True,
            stopped_cleanly=True,
            output_filename=self.csv_output.name,
        )
