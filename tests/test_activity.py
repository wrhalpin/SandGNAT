# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Activity simulator tests.

The ctypes shim (`guest_agent.activity.winapi`) no-ops on Linux, so the
loops run but their actions return False. That's enough to exercise
scheduling, shutdown, warmup gating, and config plumbing without a
real desktop. For the Windows-side SendInput path, the shim is
hand-tested against a live VM; no CI coverage there.
"""

from __future__ import annotations

import random
import threading
import time

import pytest

from guest_agent.activity import (
    ActivityConfig,
    ActivitySimulator,
    load_activity_config,
)
from guest_agent.activity.base import ActivityLoop
from guest_agent.activity.cursor_tour import CursorTour
from guest_agent.activity.keyboard_noise import KeyboardNoise
from guest_agent.activity.mouse_jiggle import MouseJiggle
from guest_agent.activity.window_dance import WindowDance


def _fast_config(**overrides) -> ActivityConfig:
    """Build a config with ~0 warmup + very short intervals so
    the loops fire immediately during a test."""
    defaults = dict(
        enabled=True,
        warmup_seconds=0.0,
        mouse_jiggle=True,
        mouse_jiggle_min_interval=0.01,
        mouse_jiggle_max_interval=0.02,
        cursor_tour=False,
        cursor_tour_min_interval=0.01,
        cursor_tour_max_interval=0.02,
        keyboard_noise=False,
        keyboard_noise_min_interval=0.01,
        keyboard_noise_max_interval=0.02,
        window_dance=False,
        window_dance_min_interval=0.01,
        window_dance_max_interval=0.02,
    )
    defaults.update(overrides)
    return ActivityConfig(**defaults)


class _CountingLoop(ActivityLoop):
    name = "counting"

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self.calls = 0

    def step(self) -> None:
        self.calls += 1


# --- config ---------------------------------------------------------------


def test_load_activity_config_defaults(monkeypatch):
    # Strip any env vars the host might have set so we test pure defaults.
    for key in list(__import__("os").environ):
        if key.startswith("SANDGNAT_"):
            monkeypatch.delenv(key, raising=False)
    cfg = load_activity_config()
    assert cfg.enabled is True
    assert cfg.warmup_seconds == pytest.approx(30.0)
    assert cfg.mouse_jiggle is True
    assert cfg.mouse_jiggle_min_interval == pytest.approx(20.0)
    assert cfg.mouse_jiggle_max_interval == pytest.approx(60.0)


def test_load_activity_config_env_override(monkeypatch):
    monkeypatch.setenv("SANDGNAT_ACTIVITY_ENABLED", "0")
    monkeypatch.setenv("SANDGNAT_ACTIVITY_WARMUP", "5.5")
    monkeypatch.setenv("SANDGNAT_MOUSE_JIGGLE_MIN", "2")
    cfg = load_activity_config()
    assert cfg.enabled is False
    assert cfg.warmup_seconds == pytest.approx(5.5)
    assert cfg.mouse_jiggle_min_interval == pytest.approx(2.0)


# --- base loop ------------------------------------------------------------


def test_base_loop_rejects_invalid_intervals():
    ready = threading.Event()
    shutdown = threading.Event()
    with pytest.raises(ValueError):
        _CountingLoop(
            min_interval=0,
            max_interval=1,
            ready=ready,
            shutdown=shutdown,
        )
    with pytest.raises(ValueError):
        _CountingLoop(
            min_interval=5,
            max_interval=1,
            ready=ready,
            shutdown=shutdown,
        )


def test_base_loop_respects_warmup_gate():
    ready = threading.Event()
    shutdown = threading.Event()
    loop = _CountingLoop(
        min_interval=0.01,
        max_interval=0.02,
        ready=ready,
        shutdown=shutdown,
    )
    loop.start()
    time.sleep(0.05)
    assert loop.calls == 0, "should stay idle until ready fires"
    ready.set()
    time.sleep(0.1)
    shutdown.set()
    loop.join(timeout=1.0)
    assert loop.calls > 0


def test_base_loop_shutdown_is_prompt():
    ready = threading.Event()
    ready.set()  # no warmup
    shutdown = threading.Event()
    loop = _CountingLoop(
        min_interval=10.0,
        max_interval=10.0,
        ready=ready,
        shutdown=shutdown,
    )
    loop.start()
    t0 = time.monotonic()
    shutdown.set()
    loop.join(timeout=2.0)
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0, f"shutdown took {elapsed:.2f}s, expected <1s"


def test_base_loop_swallows_step_exceptions():
    ready = threading.Event()
    ready.set()
    shutdown = threading.Event()

    class _Boom(ActivityLoop):
        name = "boom"

        def step(self) -> None:
            raise RuntimeError("kaboom")

    loop = _Boom(
        min_interval=0.01,
        max_interval=0.02,
        ready=ready,
        shutdown=shutdown,
    )
    loop.start()
    time.sleep(0.1)
    shutdown.set()
    loop.join(timeout=1.0)
    assert loop.errors, "exception should have been captured"
    assert any("kaboom" in e for e in loop.errors)


# --- each activity's step() is callable and records progress ---------------


def _one_shot(loop_cls, rng_seed=1):
    ready = threading.Event()
    ready.set()
    shutdown = threading.Event()
    loop = loop_cls(
        min_interval=0.01,
        max_interval=0.02,
        ready=ready,
        shutdown=shutdown,
        rng=random.Random(rng_seed),
    )
    # Directly call step() so we don't depend on thread timing.
    loop.step()
    return loop


def test_mouse_jiggle_step_runs():
    _one_shot(MouseJiggle)


def test_cursor_tour_step_runs():
    # Fire shutdown first so the inner micro-sleep returns quickly.
    ready = threading.Event()
    ready.set()
    shutdown = threading.Event()
    shutdown.set()
    loop = CursorTour(
        min_interval=0.01,
        max_interval=0.02,
        ready=ready,
        shutdown=shutdown,
        rng=random.Random(2),
    )
    loop.step()


def test_keyboard_noise_step_exits_without_notepad():
    loop = _one_shot(KeyboardNoise, rng_seed=3)
    # open_app stub returns None on Linux, so step() exits before any sleep.
    assert loop.errors == []


def test_window_dance_step_exits_without_apps():
    loop = _one_shot(WindowDance, rng_seed=4)
    assert loop.errors == []


# --- simulator ------------------------------------------------------------


def test_simulator_disabled_is_noop():
    cfg = _fast_config(enabled=False)
    sim = ActivitySimulator(cfg)
    sim.start()
    summary = sim.stop()
    assert summary.enabled is False
    assert summary.loops == {}


def test_simulator_starts_enabled_loops_and_reports():
    cfg = _fast_config(mouse_jiggle=True)
    sim = ActivitySimulator(cfg, rng=random.Random(7))
    sim.start()
    time.sleep(0.15)  # let a few mouse-jiggle intervals fire
    summary = sim.stop(join_timeout=2.0)
    assert summary.enabled is True
    assert "mouse-jiggle" in summary.loops
    assert summary.loops["mouse-jiggle"] >= 1


def test_simulator_warmup_gates_start():
    cfg = _fast_config(
        mouse_jiggle=True,
        warmup_seconds=0.2,
    )
    sim = ActivitySimulator(cfg, rng=random.Random(8))
    sim.start()
    time.sleep(0.05)
    # Too early — warmup hasn't released. Stop should report ~0 iterations.
    early_summary = sim.stop(join_timeout=1.0)
    assert early_summary.loops.get("mouse-jiggle", 0) == 0


def test_simulator_stop_without_start_is_safe():
    sim = ActivitySimulator(_fast_config(enabled=True))
    summary = sim.stop()
    assert summary.enabled is True
    assert summary.loops == {}


def test_simulator_spawns_each_configured_loop():
    cfg = _fast_config(
        mouse_jiggle=True,
        cursor_tour=True,
        keyboard_noise=True,
        window_dance=True,
    )
    sim = ActivitySimulator(cfg, rng=random.Random(9))
    sim.start()
    summary = sim.stop(join_timeout=2.0)
    # Every requested loop should appear in the summary map.
    for name in ("mouse-jiggle", "cursor-tour", "keyboard-noise", "window-dance"):
        assert name in summary.loops
