# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for the YARA scanner wrapper.

Most environments won't have libyara installed; when that's the case these
tests verify the scanner's no-op fallback contract rather than skipping.
When yara-python IS available, a real rule is compiled and matched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.yara_scanner import YaraScanner, _YARA_AVAILABLE


def test_scanner_disabled_when_no_rules_dir() -> None:
    scanner = YaraScanner(None)
    assert scanner.enabled is False
    assert scanner.scan_bytes(b"anything") == []


def test_scanner_disabled_when_rules_dir_empty(tmp_path: Path) -> None:
    (tmp_path / "placeholder.txt").write_text("not a rule")
    scanner = YaraScanner(tmp_path)
    # No .yar or .yara files means nothing to compile.
    assert scanner.enabled is False


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara-python not installed")
def test_scanner_matches_simple_rule(tmp_path: Path) -> None:
    rule = tmp_path / "test_rule.yar"
    rule.write_text(
        """
        rule DetectMagic : test {
            meta:
                severity = "high"
            strings:
                $magic = "SANDGNAT_MARKER"
            condition:
                $magic
        }
        """
    )
    scanner = YaraScanner(tmp_path)
    assert scanner.enabled

    matches = scanner.scan_bytes(b"prefix SANDGNAT_MARKER suffix")
    assert any(m.rule == "DetectMagic" for m in matches)

    clean = scanner.scan_bytes(b"nothing interesting here")
    assert clean == []
