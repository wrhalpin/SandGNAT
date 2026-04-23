# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Random small mouse deltas.

Fires every 20-60s by default, moving the cursor 2-20 px in a random
direction via SendInput. The tiny magnitude keeps the cursor roughly
where the (imaginary) user left it while still resetting
`GetLastInputInfo` so the idle timer never crosses the ~60s threshold
some evasive samples key off.
"""

from __future__ import annotations

from .base import ActivityLoop
from . import winapi


class MouseJiggle(ActivityLoop):
    name = "mouse-jiggle"

    def step(self) -> None:
        dx = self.rng.randint(-20, 20)
        dy = self.rng.randint(-20, 20)
        # Skip zero-delta moves — SendInput still resets idle but it's
        # visually stranger than letting the next interval fire.
        if dx == 0 and dy == 0:
            dx = self.rng.choice([-3, 3])
        winapi.mouse_move(dx, dy)
