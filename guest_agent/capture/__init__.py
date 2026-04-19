# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Guest-side capture-tool wrappers.

Each module wraps exactly one external tool. Wrappers are designed so their
`start()` and `stop()` are safe to call in any order from the runner — they
never raise on a missing binary, instead returning a CaptureOutcome with
`started=False, error=...` so a partial capture still produces a valid
result envelope.
"""

from .dropped_files import FileInventory, collect_dropped_files, snapshot_roots
from .procmon import ProcmonCapture
from .regshot import RegshotCapture
from .tshark import TsharkCapture

__all__ = [
    "FileInventory",
    "ProcmonCapture",
    "RegshotCapture",
    "TsharkCapture",
    "collect_dropped_files",
    "snapshot_roots",
]
