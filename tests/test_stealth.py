# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for `guest_agent.stealth`.

The actual Win32 injection path is only exercised on Windows; on
Linux we test the control flow around it (graceful fallback when
the DLL is missing, correct propagation of errors, off-platform
refusal) plus the log parser.
"""

from __future__ import annotations

from pathlib import Path

from guest_agent.stealth.injector import InjectResult, inject_dll
from guest_agent.stealth.log_parser import (
    SleepPatchEvent,
    parse_log,
    summarise,
)


# --- injector -----------------------------------------------------------


def test_inject_dll_refuses_on_non_windows(tmp_path: Path):
    dll = tmp_path / "sleep_patcher.dll"
    dll.write_bytes(b"placeholder")
    # On Linux CI SANDGNAT_FAKE_WIN32 is unset, so this returns
    # ok=False with reason="not_windows".
    result = inject_dll(1234, dll)
    assert isinstance(result, InjectResult)
    assert result.ok is False
    assert result.reason == "not_windows"
    assert result.pid == 1234


def test_inject_dll_missing_dll_is_logged(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SANDGNAT_FAKE_WIN32", "1")
    missing = tmp_path / "does-not-exist.dll"
    result = inject_dll(4242, missing)
    assert result.ok is False
    assert result.reason.startswith("dll_not_found")
    assert result.pid == 4242


# --- log parser ---------------------------------------------------------


def test_parse_log_missing_file_returns_empty(tmp_path: Path):
    assert parse_log(tmp_path / "not-there.jsonl") == []


def test_parse_log_skips_blank_and_malformed(tmp_path: Path):
    path = tmp_path / "log.jsonl"
    path.write_text(
        "\n"
        "not-json-at-all\n"
        '{"t":"2026-04-22T15:30:17.123Z","tid":10,"fn":"Sleep",'
        '"requested_ms":60000,"patched_ms":2000}\n'
        '{"missing":"fields"}\n'
        '{"t":"2026-04-22T15:31:00.000Z","tid":11,"fn":"SleepEx",'
        '"requested_ms":300000,"patched_ms":2000}\n',
        encoding="utf-8",
    )
    events = parse_log(path)
    assert len(events) == 2
    assert events[0] == SleepPatchEvent(
        timestamp="2026-04-22T15:30:17.123Z",
        thread_id=10,
        function="Sleep",
        requested_ms=60000,
        patched_ms=2000,
    )
    assert events[1].function == "SleepEx"
    assert events[1].requested_ms == 300000


def test_summarise_counts_by_function_and_time_saved():
    events = [
        SleepPatchEvent("2026-04-22T15:30:17.000Z", 10, "Sleep", 60000, 2000),
        SleepPatchEvent("2026-04-22T15:30:18.000Z", 11, "Sleep", 90000, 2000),
        SleepPatchEvent("2026-04-22T15:30:19.000Z", 12, "SleepEx", 45000, 2000),
        SleepPatchEvent(
            "2026-04-22T15:30:20.000Z", 13, "NtDelayExecution", 120000, 2000
        ),
    ]
    summary = summarise(events)
    assert summary["count"] == 4
    assert summary["by_function"] == {
        "Sleep": 2,
        "SleepEx": 1,
        "NtDelayExecution": 1,
    }
    assert summary["time_saved_ms"] == (58000 + 88000 + 43000 + 118000)


def test_summarise_empty_log():
    summary = summarise([])
    assert summary == {
        "count": 0,
        "by_function": {},
        "time_saved_ms": 0,
    }


def test_event_round_trip_via_as_dict():
    ev = SleepPatchEvent("2026-04-22T15:30:17.000Z", 10, "Sleep", 60000, 2000)
    assert ev.as_dict() == {
        "t": "2026-04-22T15:30:17.000Z",
        "tid": 10,
        "fn": "Sleep",
        "requested_ms": 60000,
        "patched_ms": 2000,
    }
