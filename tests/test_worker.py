# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for the Celery worker entry point argv construction."""

from __future__ import annotations

from orchestrator import worker


def test_main_prepends_worker_subcommand_when_args_given(monkeypatch) -> None:
    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(
        worker.app, "worker_main", lambda argv: captured.__setitem__("argv", argv)
    )
    worker.main(["--queues=static", "--concurrency=2"])
    # 'worker' must lead so worker_main parses it as the subcommand, not the
    # first user flag.
    assert captured["argv"][0] == "worker"
    assert "--queues=static" in captured["argv"]
    assert "--concurrency=2" in captured["argv"]


def test_main_applies_defaults_when_no_args(monkeypatch) -> None:
    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(
        worker.app, "worker_main", lambda argv: captured.__setitem__("argv", argv)
    )
    worker.main([])
    assert captured["argv"][0] == "worker"
    assert "--loglevel=INFO" in captured["argv"]
    assert "--queues=analysis" in captured["argv"]
