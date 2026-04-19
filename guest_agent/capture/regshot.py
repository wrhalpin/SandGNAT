# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RegShot wrapper.

RegShot's command-line interface varies across builds, so we use the
well-documented scripted pattern:

    regshot.exe /C /S <shot1.hiv>            # take first shot (quiet)
    regshot.exe /C /S <shot2.hiv> /O <diff>  # take second shot, write diff

On newer builds the flags are `/C` (save-and-compare) / `/O` (output path).
If the target RegShot binary doesn't accept these flags, the capture will
report `stopped_cleanly=False` with stderr contents rather than crashing the
job — the orchestrator will still produce a result without a regshot diff.

The diff file written to `/O` is in the standard text format consumed by
`orchestrator.parsers.regshot.parse_regshot_diff`, so no transformation is
required on the host.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from orchestrator.schema import CaptureOutcome


@dataclass(slots=True)
class RegshotCapture:
    regshot_exe: Path
    baseline_shot: Path  # .hiv for first shot
    post_shot: Path       # .hiv for second shot
    diff_output: Path     # final text diff consumed by parse_regshot_diff

    _baseline_taken: bool = False

    def take_baseline(self) -> CaptureOutcome:
        if not self.regshot_exe.exists():
            return CaptureOutcome(
                tool="regshot",
                started=False,
                stopped_cleanly=False,
                error=f"regshot.exe not found at {self.regshot_exe}",
            )
        self.baseline_shot.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                [str(self.regshot_exe), "/C", "/S", str(self.baseline_shot)],
                check=False,
                timeout=300,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CaptureOutcome(
                tool="regshot", started=False, stopped_cleanly=False, error=str(exc)
            )
        if result.returncode != 0:
            return CaptureOutcome(
                tool="regshot",
                started=False,
                stopped_cleanly=False,
                error=result.stderr.decode(errors="replace").strip() or "baseline failed",
            )
        self._baseline_taken = True
        return CaptureOutcome(tool="regshot", started=True, stopped_cleanly=False)

    def take_post_and_diff(self) -> CaptureOutcome:
        if not self._baseline_taken:
            return CaptureOutcome(
                tool="regshot",
                started=False,
                stopped_cleanly=False,
                error="baseline not taken",
            )
        try:
            result = subprocess.run(
                [
                    str(self.regshot_exe),
                    "/C",
                    "/S",
                    str(self.post_shot),
                    "/O",
                    str(self.diff_output),
                ],
                check=False,
                timeout=600,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CaptureOutcome(
                tool="regshot",
                started=True,
                stopped_cleanly=False,
                output_filename=self.diff_output.name,
                error=str(exc),
            )
        if result.returncode != 0:
            return CaptureOutcome(
                tool="regshot",
                started=True,
                stopped_cleanly=False,
                output_filename=self.diff_output.name,
                error=result.stderr.decode(errors="replace").strip() or "diff failed",
            )
        return CaptureOutcome(
            tool="regshot",
            started=True,
            stopped_cleanly=True,
            output_filename=self.diff_output.name,
        )
