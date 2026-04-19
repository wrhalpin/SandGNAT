# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for the RegShot diff parser."""

from __future__ import annotations

from orchestrator.parsers.regshot import parse_regshot_diff


REGSHOT_DIFF = """\
Keys added: 1
----------------------------
HKLM\\Software\\Evil

Values added: 2
----------------------------
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware: "C:\\\\Users\\\\User\\\\AppData\\\\Roaming\\\\m.exe"
HKCU\\Software\\Evil\\Config: "42"

Values modified: 1
----------------------------
HKLM\\Software\\Benign\\Setting: "old"
HKLM\\Software\\Benign\\Setting: "new"

Values deleted: 1
----------------------------
HKCU\\Software\\OldKey\\Value: "gone"
"""


def test_parse_regshot_extracts_sections() -> None:
    deltas = parse_regshot_diff(REGSHOT_DIFF.splitlines())
    actions = {(d.action, d.target) for d in deltas}
    assert ("added", "key") in actions
    assert ("added", "value") in actions
    assert ("deleted", "value") in actions


def test_parse_regshot_flags_persistence_keys() -> None:
    deltas = parse_regshot_diff(REGSHOT_DIFF.splitlines())
    run_key = next(
        d for d in deltas if d.value_name == "Malware"
    )
    assert run_key.persistence_indicator is True
    assert run_key.hive == "HKLM"


def test_parse_regshot_benign_keys_not_flagged() -> None:
    deltas = parse_regshot_diff(REGSHOT_DIFF.splitlines())
    benign = [d for d in deltas if d.key_path.endswith("Benign")]
    assert benign, "expected a benign delta in fixture"
    assert all(not d.persistence_indicator for d in benign)
