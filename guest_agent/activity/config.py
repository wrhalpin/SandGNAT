# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Runtime configuration for the activity simulator.

Driven entirely by env vars so non-hardened dev VMs can opt out
(`SANDGNAT_ACTIVITY_ENABLED=0`) without a schema bump.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw else default


@dataclass(frozen=True, slots=True)
class ActivityConfig:
    """Enable flags + timing knobs for each activity sub-thread."""

    enabled: bool
    # Seconds after sample launch before any activity fires. Lets
    # GUI-driven installers get past the first interactive prompt
    # without our simulator clicking through it accidentally.
    warmup_seconds: float
    mouse_jiggle: bool
    mouse_jiggle_min_interval: float
    mouse_jiggle_max_interval: float
    cursor_tour: bool
    cursor_tour_min_interval: float
    cursor_tour_max_interval: float
    keyboard_noise: bool
    keyboard_noise_min_interval: float
    keyboard_noise_max_interval: float
    window_dance: bool
    window_dance_min_interval: float
    window_dance_max_interval: float


def load_activity_config() -> ActivityConfig:
    """Build an `ActivityConfig` from process environment."""
    return ActivityConfig(
        enabled=_env_bool("SANDGNAT_ACTIVITY_ENABLED", True),
        warmup_seconds=_env_float("SANDGNAT_ACTIVITY_WARMUP", 30.0),
        mouse_jiggle=_env_bool("SANDGNAT_ACTIVITY_MOUSE_JIGGLE", True),
        mouse_jiggle_min_interval=_env_float("SANDGNAT_MOUSE_JIGGLE_MIN", 20.0),
        mouse_jiggle_max_interval=_env_float("SANDGNAT_MOUSE_JIGGLE_MAX", 60.0),
        cursor_tour=_env_bool("SANDGNAT_ACTIVITY_CURSOR_TOUR", True),
        cursor_tour_min_interval=_env_float("SANDGNAT_CURSOR_TOUR_MIN", 180.0),
        cursor_tour_max_interval=_env_float("SANDGNAT_CURSOR_TOUR_MAX", 420.0),
        keyboard_noise=_env_bool("SANDGNAT_ACTIVITY_KEYBOARD_NOISE", True),
        keyboard_noise_min_interval=_env_float("SANDGNAT_KEYBOARD_NOISE_MIN", 240.0),
        keyboard_noise_max_interval=_env_float("SANDGNAT_KEYBOARD_NOISE_MAX", 600.0),
        window_dance=_env_bool("SANDGNAT_ACTIVITY_WINDOW_DANCE", True),
        window_dance_min_interval=_env_float("SANDGNAT_WINDOW_DANCE_MIN", 120.0),
        window_dance_max_interval=_env_float("SANDGNAT_WINDOW_DANCE_MAX", 300.0),
    )
