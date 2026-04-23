# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Periodic keyboard activity.

Opens a hidden Notepad window, types 20-80 plausible characters, then
closes Notepad without saving. Runs on a slow schedule (default 4-10
minutes) because typing constantly is itself a tell.
"""

from __future__ import annotations

from .base import ActivityLoop
from . import winapi

_WORDS = [
    "meeting", "notes", "draft", "followup", "thanks",
    "please review", "attached", "deadline", "update", "status",
    "next steps", "tomorrow", "confirmed", "budget", "invoice",
    "agenda", "team sync", "project", "revision", "approved",
]


class KeyboardNoise(ActivityLoop):
    name = "keyboard-noise"

    def step(self) -> None:
        pid = winapi.open_app("notepad.exe")
        if pid is None:
            return
        # Give the window a moment to gain focus before typing. The
        # sleep is interruptible so a shutdown fires promptly.
        if self.shutdown.wait(timeout=1.5):
            winapi.close_process(pid)
            return

        chunks = self.rng.randint(3, 8)
        phrase = " ".join(self.rng.choice(_WORDS) for _ in range(chunks))
        # Cap to ~80 chars so we don't flood a low-power guest.
        phrase = phrase[:80] + "\n"
        winapi.send_unicode(phrase)

        # Let the "user" look at what they typed, then close. Never
        # save — we don't want detritus in the decoy profile.
        if self.shutdown.wait(timeout=self.rng.uniform(2.0, 6.0)):
            winapi.close_process(pid)
            return
        winapi.close_process(pid)
