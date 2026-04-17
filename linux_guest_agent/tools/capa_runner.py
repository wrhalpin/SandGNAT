"""Mandiant CAPA capability detection via subprocess.

CAPA is a heavy native dep — we shell out to its CLI rather than embed it.
The CLI emits structured JSON with `--json`; we parse the `rules` section
into a flattened list of capabilities (rule name + ATT&CK technique IDs).
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def run_capa(
    sample_path: Path,
    *,
    capa_exe: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    if not capa_exe:
        return {"available": False, "skipped": True, "reason": "no capa_exe configured"}

    try:
        proc = subprocess.run(
            [capa_exe, "--json", str(sample_path)],
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        return {"available": False, "skipped": True, "reason": f"capa exe {capa_exe!r} not found"}
    except subprocess.TimeoutExpired:
        return {"available": True, "skipped": True, "reason": "capa timed out"}

    if proc.returncode != 0 and not proc.stdout:
        return {
            "available": True,
            "skipped": True,
            "reason": f"capa rc={proc.returncode}: {proc.stderr.decode(errors='replace')[:512]}",
        }

    try:
        report = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"available": True, "skipped": True, "reason": f"capa json parse failed: {exc}"}

    capabilities: list[dict[str, Any]] = []
    rules = report.get("rules") or {}
    for rule_name, rule in rules.items():
        meta = rule.get("meta") or {}
        attck = meta.get("attck") or []
        capabilities.append(
            {
                "rule": rule_name,
                "namespace": meta.get("namespace"),
                "scope": meta.get("scope"),
                "attack": [
                    {
                        "tactic": (a or {}).get("tactic"),
                        "technique": (a or {}).get("technique"),
                        "id": (a or {}).get("id"),
                    }
                    for a in attck
                ],
            }
        )
    return {"available": True, "skipped": False, "capabilities": capabilities}
