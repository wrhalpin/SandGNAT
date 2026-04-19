# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Entry point for the Celery worker.

Run: `sandgnat-worker` (installed by pyproject) or
     `celery -A orchestrator.celery_app worker --loglevel=INFO --queues=analysis`.
"""

from __future__ import annotations

import sys

from .celery_app import app


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    default_args = ["worker", "--loglevel=INFO", "--queues=analysis"]
    app.worker_main(argv=argv or default_args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
