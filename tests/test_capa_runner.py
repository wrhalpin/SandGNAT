# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for capa result-document parsing.

These exercise `parse_capa_report` directly with fabricated capa `--json`
documents, so no capa binary is needed. Guards the key-name fix: capa spells
the ATT&CK list `attack` (older code read the misspelled `attck`, which
silently produced empty mappings) and uses `scopes` since capa 6.
"""

from __future__ import annotations

from linux_guest_agent.tools.capa_runner import parse_capa_report


def test_maps_attack_technique_ids() -> None:
    report = {
        "rules": {
            "create process": {
                "meta": {
                    "namespace": "host-interaction/process/create",
                    "scopes": {"static": "function", "dynamic": "process"},
                    "attack": [
                        {
                            "tactic": "Execution",
                            "technique": "Command and Scripting Interpreter",
                            "id": "T1059",
                        }
                    ],
                }
            }
        }
    }
    caps = parse_capa_report(report)
    assert len(caps) == 1
    cap = caps[0]
    assert cap["rule"] == "create process"
    assert cap["namespace"] == "host-interaction/process/create"
    assert cap["scope"] == {"static": "function", "dynamic": "process"}
    assert cap["attack"] == [
        {
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter",
            "id": "T1059",
        }
    ]


def test_falls_back_to_legacy_scope_string() -> None:
    report = {"rules": {"r": {"meta": {"scope": "function"}}}}
    caps = parse_capa_report(report)
    assert caps[0]["scope"] == "function"
    assert caps[0]["attack"] == []


def test_misspelled_attck_key_is_ignored() -> None:
    # A report using the OLD misspelling should NOT populate attack — only
    # the correct capa key `attack` does. This is the exact bug that made
    # every capability ship an empty ATT&CK list.
    report = {"rules": {"r": {"meta": {"attck": [{"id": "T1055"}]}}}}
    caps = parse_capa_report(report)
    assert caps[0]["attack"] == []


def test_correct_attack_key_populates() -> None:
    report = {"rules": {"r": {"meta": {"attack": [{"id": "T1055"}]}}}}
    caps = parse_capa_report(report)
    assert caps[0]["attack"][0]["id"] == "T1055"


def test_empty_report() -> None:
    assert parse_capa_report({}) == []
    assert parse_capa_report({"rules": {}}) == []
