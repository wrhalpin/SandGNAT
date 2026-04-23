# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Periodic window churn.

Every 2-5 minutes, launches one of a curated set of benign apps
(Calculator, Notepad, File Explorer at a realistic path) and closes
it again after a short delay. Gives the foreground-window enumerator
something to chew on beyond a single Explorer window.
"""

from __future__ import annotations

from .base import ActivityLoop
from . import winapi

_APPS = [
    ("notepad.exe", 4.0, 9.0),
    ("calc.exe", 3.0, 7.0),
    # explorer.exe with a path opens File Explorer at that folder.
    # Using a realistic-looking personal folder avoids spawning a
    # never-seen path that itself looks synthetic.
    ("explorer.exe %USERPROFILE%\\Documents", 5.0, 12.0),
    ("explorer.exe %USERPROFILE%\\Downloads", 5.0, 12.0),
    ("explorer.exe %USERPROFILE%\\Pictures", 4.0, 10.0),
]


class WindowDance(ActivityLoop):
    name = "window-dance"

    def step(self) -> None:
        cmd, min_hold, max_hold = self.rng.choice(_APPS)
        pid = winapi.open_app(cmd)
        if pid is None:
            return
        hold = self.rng.uniform(min_hold, max_hold)
        if self.shutdown.wait(timeout=hold):
            winapi.close_process(pid)
            return
        winapi.close_process(pid)
