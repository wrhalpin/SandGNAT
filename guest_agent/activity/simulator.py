# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Lifecycle manager for the four activity loops.

Used by `guest_agent/runner.py` around `execute_sample` so activity
fires during detonation and stops before captures are finalised.

Typical flow:

    sim = ActivitySimulator(config)
    sim.start()           # kicks off the warmup timer; loops gated off
    ... execute sample ...
    sim.stop()            # joins threads, returns per-loop summary
"""

from __future__ import annotations

import logging
import random
import threading
from dataclasses import dataclass, field

from .base import ActivityLoop
from .config import ActivityConfig
from .cursor_tour import CursorTour
from .keyboard_noise import KeyboardNoise
from .mouse_jiggle import MouseJiggle
from .window_dance import WindowDance

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ActivitySummary:
    enabled: bool
    loops: dict[str, int] = field(default_factory=dict)
    errors: dict[str, list[str]] = field(default_factory=dict)


class ActivitySimulator:
    """Owns the warmup timer + the four activity loops.

    Thread-safe start/stop; calling `stop()` before `start()` is a
    no-op. All threads are daemons so a crashed runner can't strand
    them.
    """

    def __init__(
        self,
        config: ActivityConfig,
        *,
        rng: random.Random | None = None,
    ) -> None:
        self.config = config
        self.rng = rng or random.Random()
        self._ready = threading.Event()
        self._shutdown = threading.Event()
        self._warmup_timer: threading.Timer | None = None
        self._loops: list[ActivityLoop] = []
        self._started = False
        self._stopped = False

    def start(self) -> None:
        """Schedule the warmup gate and spin up each enabled loop."""
        if not self.config.enabled:
            _log.debug("activity simulator disabled via config")
            return
        if self._started:
            return
        self._started = True

        loop_rng = random.Random(self.rng.random())
        if self.config.mouse_jiggle:
            self._loops.append(
                MouseJiggle(
                    min_interval=self.config.mouse_jiggle_min_interval,
                    max_interval=self.config.mouse_jiggle_max_interval,
                    ready=self._ready,
                    shutdown=self._shutdown,
                    rng=random.Random(loop_rng.random()),
                )
            )
        if self.config.cursor_tour:
            self._loops.append(
                CursorTour(
                    min_interval=self.config.cursor_tour_min_interval,
                    max_interval=self.config.cursor_tour_max_interval,
                    ready=self._ready,
                    shutdown=self._shutdown,
                    rng=random.Random(loop_rng.random()),
                )
            )
        if self.config.keyboard_noise:
            self._loops.append(
                KeyboardNoise(
                    min_interval=self.config.keyboard_noise_min_interval,
                    max_interval=self.config.keyboard_noise_max_interval,
                    ready=self._ready,
                    shutdown=self._shutdown,
                    rng=random.Random(loop_rng.random()),
                )
            )
        if self.config.window_dance:
            self._loops.append(
                WindowDance(
                    min_interval=self.config.window_dance_min_interval,
                    max_interval=self.config.window_dance_max_interval,
                    ready=self._ready,
                    shutdown=self._shutdown,
                    rng=random.Random(loop_rng.random()),
                )
            )

        for loop in self._loops:
            loop.start()

        # Release the ready gate after the warmup window. Timer is
        # itself a daemon in the standard library so we don't leak it.
        def release_gate() -> None:
            _log.debug("activity warmup elapsed; releasing ready gate")
            self._ready.set()

        self._warmup_timer = threading.Timer(self.config.warmup_seconds, release_gate)
        self._warmup_timer.daemon = True
        self._warmup_timer.start()

    def stop(self, join_timeout: float = 5.0) -> ActivitySummary:
        """Signal shutdown, join threads, return a summary."""
        if self._stopped or not self._started:
            return ActivitySummary(enabled=self.config.enabled)
        self._stopped = True

        self._shutdown.set()
        # Ensure any loop still waiting on the warmup gate unblocks
        # and exits promptly.
        self._ready.set()
        if self._warmup_timer is not None:
            self._warmup_timer.cancel()

        for loop in self._loops:
            loop.join(timeout=join_timeout)

        loops_report = {loop.name: loop.steps_completed for loop in self._loops}
        errors_report = {
            loop.name: list(loop.errors) for loop in self._loops if loop.errors
        }
        return ActivitySummary(
            enabled=True, loops=loops_report, errors=errors_report
        )
