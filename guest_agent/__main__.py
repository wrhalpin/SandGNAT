# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Guest agent CLI entry point.

Usage:
    python -m guest_agent serve        # run the watcher loop
    python -m guest_agent run-once     # process a single pending job and exit
"""

from __future__ import annotations

import argparse
import sys

from .config import load_config
from .watcher import serve


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. See the module docstring for subcommands."""
    parser = argparse.ArgumentParser(prog="guest_agent")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Run the watcher loop")
    sub.add_parser("run-once", help="Process one pending job and exit")
    args = parser.parse_args(argv)

    cfg = load_config()
    serve(cfg, run_once=(args.command == "run-once"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
