"""tshark wrapper.

We start tshark as a subprocess, capturing to a .pcap. Stop by sending the
process its standard interrupt signal — on Windows that's
`generate_console_ctrl_event(CTRL_BREAK_EVENT)`. A terminate() fallback
handles the case where signal delivery fails (e.g. tshark still in startup).
"""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from orchestrator.schema import CaptureOutcome


@dataclass(slots=True)
class TsharkCapture:
    tshark_exe: Path
    output_pcap: Path
    interface: str

    _proc: subprocess.Popen | None = None

    def start(self) -> CaptureOutcome:
        if not self.tshark_exe.exists():
            return CaptureOutcome(
                tool="tshark",
                started=False,
                stopped_cleanly=False,
                error=f"tshark.exe not found at {self.tshark_exe}",
            )
        self.output_pcap.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(self.tshark_exe),
            "-i",
            self.interface,
            "-w",
            str(self.output_pcap),
            # Drop ARP/STP noise; leave everything else.
            "-f",
            "not (arp or stp)",
        ]
        creation_flags = 0
        if sys.platform == "win32":
            # CREATE_NEW_PROCESS_GROUP lets us signal tshark without killing
            # the agent itself.
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
            )
        except OSError as exc:
            return CaptureOutcome(
                tool="tshark", started=False, stopped_cleanly=False, error=str(exc)
            )
        # Give tshark a moment to initialise its pcap writer; if it exits
        # immediately (e.g. bad interface) we want to report the stderr.
        time.sleep(1.0)
        if self._proc.poll() is not None:
            err = (self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else "")
            return CaptureOutcome(
                tool="tshark",
                started=False,
                stopped_cleanly=False,
                error=f"tshark exited early: {err.strip() or 'no stderr'}",
            )
        return CaptureOutcome(tool="tshark", started=True, stopped_cleanly=False)

    def stop(self) -> CaptureOutcome:
        if self._proc is None:
            return CaptureOutcome(
                tool="tshark", started=False, stopped_cleanly=False, error="never started"
            )
        try:
            if sys.platform == "win32":
                self._proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            else:
                self._proc.send_signal(signal.SIGINT)
            self._proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                return CaptureOutcome(
                    tool="tshark",
                    started=True,
                    stopped_cleanly=False,
                    output_filename=self.output_pcap.name,
                    error="tshark did not exit; killed",
                )
        return CaptureOutcome(
            tool="tshark",
            started=True,
            stopped_cleanly=True,
            output_filename=self.output_pcap.name,
        )
