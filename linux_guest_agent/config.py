# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Env-backed configuration for the Linux static-analysis guest.

Stdlib only. Mirrors the layout of `guest_agent/config.py`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str | None = None) -> str:
    return os.environ.get(name, default or "") or ""


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw else default


@dataclass(frozen=True)
class LinuxGuestConfig:
    """Env-loaded configuration for the Linux static-analysis guest."""

    staging_root: Path
    poll_interval: float
    capa_exe: str
    yara_deep_rules_dir: str
    # Cap raw-strings retention so a 200 MiB string blob doesn't bloat the
    # envelope and the staging share.
    max_strings_bytes: int


def from_env() -> LinuxGuestConfig:
    """Construct a `LinuxGuestConfig` from the process environment."""
    return LinuxGuestConfig(
        staging_root=Path(_env("LINUX_GUEST_STAGING_ROOT", "/srv/sandgnat/staging")),
        poll_interval=_env_float("LINUX_GUEST_POLL_INTERVAL", 2.0),
        capa_exe=_env("LINUX_GUEST_CAPA_EXE", "capa"),
        yara_deep_rules_dir=_env("LINUX_GUEST_YARA_DEEP_RULES_DIR", ""),
        max_strings_bytes=_env_int("LINUX_GUEST_MAX_STRINGS_BYTES", 1024 * 1024),
    )
