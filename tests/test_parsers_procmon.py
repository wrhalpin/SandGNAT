"""Unit tests for the ProcMon CSV parser."""

from __future__ import annotations

from orchestrator.parsers.procmon import parse_procmon_csv


PROCMON_CSV = """\
"Time of Day","Process Name","PID","Operation","Path","Result","Detail"
"10:00:00.000","sample.exe","1234","RegSetValue","HKLM\\\\Software\\\\Foo","SUCCESS","Type: REG_SZ"
"10:00:00.100","sample.exe","1234","Thread Profile","","SUCCESS","noise"
"10:00:00.200","sample.exe","1234","WriteFile","C:\\\\drop.dll","SUCCESS","Offset: 0, Length: 4096"
"10:00:00.300","explorer.exe","9999","RegSetValue","HKCU\\\\Software\\\\Other","SUCCESS","Type: REG_SZ"
"""


def test_parse_procmon_filters_to_behavioural_ops() -> None:
    events = parse_procmon_csv(PROCMON_CSV.splitlines())
    ops = {e.operation for e in events}
    assert "Thread Profile" not in ops
    assert {"RegSetValue", "WriteFile"}.issubset(ops)


def test_parse_procmon_filters_by_pid() -> None:
    events = parse_procmon_csv(PROCMON_CSV.splitlines(), target_pids=[1234])
    assert all(e.pid == 1234 for e in events)
    assert len(events) == 2  # RegSetValue + WriteFile for 1234


def test_parse_procmon_keeps_all_ops_when_operations_empty() -> None:
    events = parse_procmon_csv(PROCMON_CSV.splitlines(), operations=[])
    assert any(e.operation == "Thread Profile" for e in events)
