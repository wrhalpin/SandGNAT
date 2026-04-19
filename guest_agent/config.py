# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Guest-side configuration.

All knobs come from environment variables so the service can be reconfigured
without rebuilding the frozen executable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw else default


@dataclass(frozen=True, slots=True)
class GuestConfig:
    """Env-loaded configuration for the Windows detonation guest.

    Paths reflect the FLARE-VM defaults; override via env if a template
    installs tools elsewhere.
    """

    # Path to the staging share as seen from *inside* the guest. Typically a
    # mapped drive or UNC path, e.g. r"\\192.168.100.1\analysis".
    staging_root: Path
    # Working directory on local disk where we unpack the sample before running.
    work_root: Path
    # Poll interval (seconds) for the pending/ queue.
    poll_interval: float
    # External tool binaries. Override if FLARE-VM installs them elsewhere.
    procmon_exe: Path
    tshark_exe: Path
    regshot_exe: Path
    # Network interface name that tshark captures on.
    capture_interface: str


def load_config() -> GuestConfig:
    """Build a `GuestConfig` from the process environment."""
    return GuestConfig(
        staging_root=Path(_env("SANDGNAT_STAGING_ROOT", r"\\192.168.100.1\analysis")),
        work_root=Path(_env("SANDGNAT_WORK_ROOT", r"C:\sandgnat")),
        poll_interval=_env_float("SANDGNAT_POLL_INTERVAL", 2.0),
        procmon_exe=Path(_env("SANDGNAT_PROCMON", r"C:\Tools\Procmon\Procmon.exe")),
        tshark_exe=Path(_env("SANDGNAT_TSHARK", r"C:\Program Files\Wireshark\tshark.exe")),
        regshot_exe=Path(_env("SANDGNAT_REGSHOT", r"C:\Tools\Regshot\Regshot-x64-Unicode.exe")),
        capture_interface=_env("SANDGNAT_CAPTURE_INTERFACE", "Ethernet"),
    )
