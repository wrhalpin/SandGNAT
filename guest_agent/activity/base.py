# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Base class for activity loops.

Every activity (mouse jiggle, cursor tour, keyboard noise, window
dance) is a daemon thread that wakes on a randomised interval, fires
its action, and goes back to sleep. Shared plumbing — the shutdown
event, the warmup gate, bounded random sleep, exception swallow —
lives here so the individual activities stay short.

None of this logic is Windows-specific; the actual SendInput calls
happen in the ctypes shim (`winapi.py`).
"""

from __future__ import annotations

import logging
import random
import threading
from abc import ABC, abstractmethod

_log = logging.getLogger(__name__)


class ActivityLoop(ABC):
    """Base daemon thread for one simulated user behaviour.

    Subclasses implement `step()` (the single action) and declare
    `min_interval` / `max_interval` via the constructor. The loop:

    1. Blocks on `ready` until the warmup gate releases it.
    2. Sleeps a uniform-random interval in [min, max].
    3. Calls `step()` with any exception swallowed (never kill the
       detonation over a failed SendInput).
    4. Goes back to step 2 until `stop()` sets the shutdown event.
    """

    name: str = "activity"

    def __init__(
        self,
        *,
        min_interval: float,
        max_interval: float,
        ready: threading.Event,
        shutdown: threading.Event,
        rng: random.Random | None = None,
    ) -> None:
        if min_interval <= 0 or max_interval < min_interval:
            raise ValueError(
                f"invalid interval: min={min_interval} max={max_interval}"
            )
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.ready = ready
        self.shutdown = shutdown
        self.rng = rng or random.Random()
        self._thread: threading.Thread | None = None
        self.steps_completed = 0
        self.errors: list[str] = []

    @abstractmethod
    def step(self) -> None:
        """Perform one iteration of the simulated behaviour."""

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name=f"activity-{self.name}", daemon=True
        )
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        # Block until the warmup gate releases. `ready.wait()` also
        # returns immediately if `shutdown` is already set (we check
        # the latter on the next line).
        self.ready.wait()
        while not self.shutdown.is_set():
            delay = self.rng.uniform(self.min_interval, self.max_interval)
            # Sleep in small slices so a shutdown during a long
            # cursor-tour interval doesn't hang the agent for 7 min.
            if self._sleep_interruptible(delay):
                break
            try:
                self.step()
                self.steps_completed += 1
            except Exception as exc:  # noqa: BLE001 - never kill the loop
                _log.debug("%s step failed: %s", self.name, exc, exc_info=True)
                self.errors.append(str(exc))

    def _sleep_interruptible(self, total: float) -> bool:
        """Sleep up to `total` seconds; return True if shutdown fired."""
        end_signalled = self.shutdown.wait(timeout=total)
        return end_signalled
