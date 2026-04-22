# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Parse sleep_patcher.dll's JSONL log.

Each line of the log (written by the DLL's logger.cpp) looks like:

    {"t":"2026-04-22T15:30:17.123Z","tid":4242,"fn":"Sleep",
     "requested_ms":600000,"patched_ms":2000}

This module loads the file, tolerates malformed lines (the DLL's
writer is careful but a torn write during unclean process teardown
can leave a partial line), and returns a list of `SleepPatchEvent`
records plus a summary.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SleepPatchEvent:
    """One truncated sleep/wait call."""

    timestamp: str
    thread_id: int
    function: str
    requested_ms: int
    patched_ms: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "t": self.timestamp,
            "tid": self.thread_id,
            "fn": self.function,
            "requested_ms": self.requested_ms,
            "patched_ms": self.patched_ms,
        }


def parse_log(path: Path) -> list[SleepPatchEvent]:
    """Read `path` as JSONL; return valid events, skip malformed lines.

    Returns empty list if the file doesn't exist — that's the normal
    state when a sample never called a long Sleep.
    """
    if not path.exists():
        return []
    events: list[SleepPatchEvent] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                _log.debug("skipping malformed sleep-patch line: %r", line[:120])
                continue
            ev = _coerce(obj)
            if ev is not None:
                events.append(ev)
    return events


def _coerce(obj: dict[str, Any]) -> SleepPatchEvent | None:
    try:
        return SleepPatchEvent(
            timestamp=str(obj["t"]),
            thread_id=int(obj["tid"]),
            function=str(obj["fn"]),
            requested_ms=int(obj["requested_ms"]),
            patched_ms=int(obj["patched_ms"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def summarise(events: list[SleepPatchEvent]) -> dict[str, Any]:
    """Aggregate per-function counts + total elapsed saved."""
    by_function: dict[str, int] = {}
    saved_ms = 0
    for ev in events:
        by_function[ev.function] = by_function.get(ev.function, 0) + 1
        saved_ms += max(0, ev.requested_ms - ev.patched_ms)
    return {
        "count": len(events),
        "by_function": by_function,
        "time_saved_ms": saved_ms,
    }
