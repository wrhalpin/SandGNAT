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
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        args = ["--loglevel=INFO", "--queues=analysis"]
    # `worker_main` treats argv[0] as the subcommand, so "worker" must lead
    # regardless of whether the caller passed extra flags. The previous code
    # dropped it whenever any arg was supplied, so `sandgnat-worker --queues=x`
    # misparsed the flag as the command name.
    app.worker_main(argv=["worker", *args])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
