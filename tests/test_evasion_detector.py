# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for `orchestrator.evasion_detector`."""

from __future__ import annotations

from uuid import uuid4

from orchestrator.evasion_detector import (
    EvasionIndicator,
    detect_evasion,
    summarise,
)
from orchestrator.models import StaticAnalysisRow
from orchestrator.parsers.procmon import ProcmonEvent


def _evt(
    operation: str,
    path: str,
    *,
    detail: str = "",
    process_name: str = "sample.exe",
) -> ProcmonEvent:
    return ProcmonEvent(
        time="00:00:00.000",
        process_name=process_name,
        pid=4242,
        operation=operation,
        path=path,
        result="SUCCESS",
        detail=detail,
    )


def _static(**overrides) -> StaticAnalysisRow:
    defaults = dict(analysis_id=uuid4())
    defaults.update(overrides)
    return StaticAnalysisRow(**defaults)


# --- no-input cases -------------------------------------------------------


def test_no_inputs_returns_empty():
    assert detect_evasion() == []


def test_empty_static_row_returns_empty():
    assert detect_evasion(static=_static()) == []


# --- runtime indicators ---------------------------------------------------


def test_bios_registry_probe_detected():
    events = [
        _evt(
            "RegQueryValue",
            r"HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion",
        ),
    ]
    result = detect_evasion(events)
    assert len(result) == 1
    assert result[0].category == "bios_registry"
    assert result[0].severity == "high"
    assert result[0].source == "procmon"


def test_acpi_dsdt_probe_detected():
    events = [_evt("RegOpenKey", r"HKLM\HARDWARE\ACPI\DSDT\QEMU")]
    result = detect_evasion(events)
    assert len(result) == 1
    assert result[0].category == "bios_registry"


def test_vbox_service_registry_probe_detected():
    events = [
        _evt(
            "RegQueryValue",
            r"HKLM\SYSTEM\ControlSet001\Services\VBoxService\Start",
        )
    ]
    result = detect_evasion(events)
    assert [i.category for i in result] == ["bios_registry"]


def test_vm_artifact_file_probe_detected():
    events = [
        _evt(
            "QueryAttributes",
            r"C:\Windows\System32\drivers\VBoxMouse.sys",
        )
    ]
    result = detect_evasion(events)
    assert len(result) == 1
    assert result[0].category == "vm_artifact_file"
    assert result[0].severity == "high"


def test_vmware_tools_folder_probe_detected():
    events = [
        _evt(
            "CreateFile",
            r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
        )
    ]
    result = detect_evasion(events)
    assert any(i.category == "vm_artifact_file" for i in result)


def test_analysis_tool_enumeration_detected_via_path():
    events = [_evt("CreateFile", r"C:\Tools\Procmon\procmon.exe")]
    result = detect_evasion(events)
    assert any(i.category == "analysis_tool_enum" for i in result)


def test_analysis_tool_enumeration_detected_via_detail():
    events = [
        _evt(
            "Thread Create",
            "",
            detail="Target: wireshark.exe Command line: --help",
        )
    ]
    result = detect_evasion(events)
    assert any(i.category == "analysis_tool_enum" for i in result)


def test_deduplicates_repeated_probe_on_same_path():
    target = r"HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion"
    events = [
        _evt("RegQueryValue", target),
        _evt("RegQueryValue", target),
        _evt("RegOpenKey", target),
    ]
    result = detect_evasion(events)
    assert len(result) == 1


def test_ignores_benign_registry_reads():
    events = [
        _evt(
            "RegQueryValue",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer",
        )
    ]
    assert detect_evasion(events) == []


def test_ignores_non_query_ops():
    # Reading a benign file that happens to be in a path that
    # overlaps an artifact substring should not fire — we only trigger
    # on Create/QueryAttributes operations.
    events = [
        _evt(
            "ReadFile",
            r"C:\Windows\System32\drivers\VBoxMouse.sys",
        )
    ]
    # ReadFile isn't in the CreateFile/QueryAttributes set; so no hit.
    assert detect_evasion(events) == []


# --- static indicators ----------------------------------------------------


def test_yara_anti_vm_tag_detected():
    row = _static(deep_yara_matches=["SandGNAT_AntiVM_VMwareArtifacts"])
    result = detect_evasion(static=row)
    assert len(result) == 1
    assert result[0].category == "yara_anti_vm"
    assert result[0].source == "yara"


def test_yara_non_anti_vm_match_ignored():
    row = _static(deep_yara_matches=["Generic_Win32_Packer"])
    assert detect_evasion(static=row) == []


def test_capa_anti_analysis_capability_detected():
    row = _static(
        capa_capabilities=[
            {"namespace": "anti-analysis/anti-vm", "name": "check for vmware"},
            {"namespace": "data-manipulation", "name": "encode data"},
        ]
    )
    result = detect_evasion(static=row)
    assert len(result) == 1
    assert result[0].category == "capa_anti_analysis"
    assert "check for vmware" in result[0].evidence


def test_suspicious_import_detected_as_low():
    row = _static(imports={"kernel32.dll": ["Sleep", "CreateFileW"]})
    result = detect_evasion(static=row)
    assert len(result) == 1
    assert result[0].category == "suspicious_import"
    assert result[0].severity == "low"
    assert result[0].evidence == "Sleep"


def test_suspicious_import_flat_list_handled():
    row = _static(imports=["GetLastInputInfo", "ReadFile"])
    result = detect_evasion(static=row)
    assert [i.category for i in result] == ["suspicious_import"]


def test_suspicious_import_escalates_with_runtime_hit():
    row = _static(imports={"kernel32.dll": ["Sleep"]})
    events = [_evt("RegQueryValue", r"HKLM\HARDWARE\ACPI\DSDT\QEMU")]
    result = detect_evasion(events, static=row)
    import_hit = next(i for i in result if i.category == "suspicious_import")
    assert import_hit.severity == "medium"


def test_suspicious_import_alone_stays_low():
    row = _static(imports={"kernel32.dll": ["Sleep"]})
    result = detect_evasion(static=row)
    import_hit = next(i for i in result if i.category == "suspicious_import")
    assert import_hit.severity == "low"


# --- summariser -----------------------------------------------------------


def test_summarise_counts_by_category_and_severity():
    indicators = [
        EvasionIndicator("bios_registry", "high", "x", "procmon"),
        EvasionIndicator("bios_registry", "high", "y", "procmon"),
        EvasionIndicator("suspicious_import", "low", "Sleep", "static"),
    ]
    summary = summarise(indicators)
    assert summary["count"] == 3
    assert summary["by_category"]["bios_registry"] == 2
    assert summary["by_category"]["suspicious_import"] == 1
    assert summary["by_severity"]["high"] == 2
    assert summary["by_severity"]["low"] == 1
    assert summary["by_severity"]["medium"] == 0
    assert len(summary["indicators"]) == 3


def test_summarise_empty():
    summary = summarise([])
    assert summary == {
        "count": 0,
        "by_category": {},
        "by_severity": {"low": 0, "medium": 0, "high": 0},
        "indicators": [],
    }
