# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""ProcMon CSV parser.

ProcMon can export filtered events to CSV (File → Save → CSV). The useful
columns for behavioural analysis are Time, Process Name, PID, Operation, Path,
Result, Detail. Column order and header names are stable across current
Sysinternals builds.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

# Operations we keep. Everything else (thread-profiling noise, irp_mj_read on
# memory-mapped loader pages, etc.) is dropped — it floods the graph without
# adding behavioural signal.
BEHAVIOURAL_OPERATIONS = frozenset(
    {
        # File I/O
        "CreateFile",
        "WriteFile",
        "SetDispositionInformationFile",  # delete
        "SetRenameInformationFile",
        # Registry
        "RegCreateKey",
        "RegSetValue",
        "RegDeleteKey",
        "RegDeleteValue",
        # Process
        "Process Create",
        "Process Start",
        "Process Exit",
        "Thread Create",
        "Load Image",
        # Network (ProcMon 4+ emits these as TCP/UDP Send / Receive)
        "TCP Connect",
        "TCP Send",
        "UDP Send",
    }
)


@dataclass(frozen=True, slots=True)
class ProcmonEvent:
    """One normalised ProcMon event: process + PID + operation + target path."""

    time: str
    process_name: str
    pid: int
    operation: str
    path: str
    result: str
    detail: str


def _to_int(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_procmon_csv(
    source: Path | Iterable[str],
    *,
    target_pids: Iterable[int] | None = None,
    operations: Iterable[str] | None = None,
) -> list[ProcmonEvent]:
    """Parse a ProcMon CSV export, filtering to behavioural operations.

    `source` may be a path or any line-iterable (useful for tests).
    `target_pids` (if set) restricts output to those PIDs plus their recorded
    child processes. `operations` overrides the default BEHAVIOURAL_OPERATIONS
    filter — pass an empty iterable to keep everything.
    """
    if isinstance(source, Path):
        with source.open("r", encoding="utf-8-sig", newline="") as fh:
            return list(_iter_events(fh, target_pids, operations))
    return list(_iter_events(iter(source), target_pids, operations))


def _iter_events(
    lines: Iterable[str],
    target_pids: Iterable[int] | None,
    operations: Iterable[str] | None,
) -> Iterator[ProcmonEvent]:
    allowed_ops = frozenset(operations) if operations is not None else BEHAVIOURAL_OPERATIONS
    allowed_pids = frozenset(target_pids) if target_pids is not None else None

    reader = csv.DictReader(lines)
    for row in reader:
        op = (row.get("Operation") or "").strip()
        if allowed_ops and op not in allowed_ops:
            continue

        pid = _to_int(row.get("PID", ""))
        if pid is None:
            continue
        if allowed_pids is not None and pid not in allowed_pids:
            continue

        yield ProcmonEvent(
            time=(row.get("Time of Day") or row.get("Time") or "").strip(),
            process_name=(row.get("Process Name") or "").strip(),
            pid=pid,
            operation=op,
            path=(row.get("Path") or "").strip(),
            result=(row.get("Result") or "").strip(),
            detail=(row.get("Detail") or "").strip(),
        )
