# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Larger cursor motions to plausible UI targets.

Every few minutes (default 3-7), glides the cursor to a realistic
destination — taskbar, a window corner, a desktop icon cluster — and
occasionally clicks on an empty patch of desktop. Intended to defeat
checks that sample cursor position over time and expect it to wander
between clusters.

Path is linear with ~20-40 small steps so a timing-sensitive check
sees continuous motion rather than a teleport.
"""

from __future__ import annotations

from .base import ActivityLoop
from . import winapi

# Relative target zones — fraction of screen width/height. Gives
# sensible points regardless of actual resolution.
_TARGETS = [
    ("taskbar-start", 0.03, 0.98),
    ("taskbar-mid", 0.35, 0.98),
    ("taskbar-tray", 0.95, 0.98),
    ("window-top-right", 0.95, 0.05),
    ("window-top-left", 0.05, 0.05),
    ("desktop-icon-row", 0.05, 0.15),
    ("desktop-empty-centre", 0.60, 0.50),
]


class CursorTour(ActivityLoop):
    name = "cursor-tour"

    def step(self) -> None:
        bounds = winapi.screen_bounds()
        if bounds.width <= 0 or bounds.height <= 0:
            return
        start_x, start_y = winapi.cursor_pos()
        label, fx, fy = self.rng.choice(_TARGETS)
        tx = int(bounds.width * fx)
        ty = int(bounds.height * fy)

        steps = self.rng.randint(20, 40)
        for i in range(1, steps + 1):
            ix = start_x + (tx - start_x) * i // steps
            iy = start_y + (ty - start_y) * i // steps
            winapi.set_cursor_pos(ix, iy)
            # Interruptible micro-sleep between pixels so shutdown is
            # fast even mid-tour.
            if self.shutdown.wait(timeout=0.015):
                return

        # 1 in 4 tours ends in a left-click on the empty desktop
        # centre. Anywhere else we just park the cursor.
        if label == "desktop-empty-centre" and self.rng.random() < 0.25:
            winapi.mouse_click("left")
