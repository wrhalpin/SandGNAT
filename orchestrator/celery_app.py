# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Celery application wiring."""

from __future__ import annotations

from celery import Celery

from .config import get_settings


def _make_app() -> Celery:
    settings = get_settings()
    app = Celery(
        "sandgnat",
        broker=settings.broker_url,
        backend=settings.result_backend,
        # Both task modules are imported so workers can opt into either queue
        # via `--queues=analysis` or `--queues=static`.
        include=["orchestrator.tasks", "orchestrator.tasks_static"],
    )
    app.conf.update(
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_default_queue="analysis",
        task_track_started=True,
        worker_prefetch_multiplier=1,  # one detonation per worker; do not batch
        worker_max_tasks_per_child=50,
        broker_connection_retry_on_startup=True,
        task_routes={
            "sandgnat.analyze_malware_sample": {"queue": "analysis"},
            "sandgnat.static_analyze_sample": {"queue": "static"},
        },
    )
    return app


app = _make_app()
