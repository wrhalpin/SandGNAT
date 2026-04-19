# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Deep YARA scan against the static-analysis ruleset.

Different rule directory from the intake-time quick scan: typically slower,
larger rules that we can afford to run because we're already burning a VM
on this sample. Falls back to a no-op if `yara-python` isn't installed or
the rules dir is empty.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

try:
    import yara  # type: ignore[import-not-found]

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False

log = logging.getLogger(__name__)


def scan_deep_yara(data: bytes, rules_dir: str) -> dict[str, Any]:
    """Scan `data` against every `.yar`/`.yara` in `rules_dir`.

    Returns a dict with `matches: list[{rule, tags, meta}]` on success, or
    a `{available, skipped, reason}` marker when the library or rules are
    missing. Never raises.
    """
    if not _YARA_AVAILABLE:
        return {"available": False, "skipped": True, "reason": "yara-python not installed"}
    if not rules_dir:
        return {"available": True, "skipped": True, "reason": "no rules dir configured"}
    rules_path = Path(rules_dir)
    if not rules_path.is_dir():
        return {
            "available": True,
            "skipped": True,
            "reason": f"rules dir {rules_dir} does not exist",
        }

    filepaths: dict[str, str] = {}
    for ext in ("*.yar", "*.yara"):
        for rule_file in sorted(rules_path.rglob(ext)):
            filepaths[rule_file.stem] = str(rule_file)
    if not filepaths:
        return {"available": True, "skipped": True, "reason": "rules dir empty"}

    try:
        rules = yara.compile(filepaths=filepaths)
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "skipped": True, "reason": f"compile error: {exc}"}

    try:
        matches = rules.match(data=data)
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "skipped": True, "reason": f"scan error: {exc}"}

    return {
        "available": True,
        "skipped": False,
        "matches": [
            {
                "rule": str(m.rule),
                "tags": list(getattr(m, "tags", []) or []),
                "meta": {k: str(v) for k, v in (getattr(m, "meta", {}) or {}).items()},
            }
            for m in matches
        ],
    }
