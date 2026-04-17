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
        include=["orchestrator.tasks"],
    )
    app.conf.update(
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_default_queue="analysis",
        task_track_started=True,
        worker_prefetch_multiplier=1,  # one detonation per worker; do not batch
        worker_max_tasks_per_child=50,
        broker_connection_retry_on_startup=True,
    )
    return app


app = _make_app()
