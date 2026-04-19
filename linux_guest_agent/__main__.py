# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""`python -m linux_guest_agent` entry point."""

from __future__ import annotations

from .config import from_env
from .watcher import serve


def main() -> None:
    """Entry point: `python -m linux_guest_agent`."""
    serve(from_env())


if __name__ == "__main__":
    main()
