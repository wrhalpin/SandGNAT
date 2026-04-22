# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""User-activity simulator.

Phase D of the anti-analysis mitigation plan. Runs inside the guest
agent while a sample is detonating so commodity malware's
user-interaction checks (`GetLastInputInfo`, mouse-position polling,
foreground-window enumeration) see realistic signal instead of an idle
console.

All submodules are import-safe on Linux — Windows-only ctypes calls live
behind the `winapi` shim and no-op off-Windows, so the CI test suite
can exercise the scheduler and config logic without a real desktop.
"""

from __future__ import annotations

from .config import ActivityConfig, load_activity_config
from .simulator import ActivitySimulator

__all__ = ["ActivityConfig", "ActivitySimulator", "load_activity_config"]
