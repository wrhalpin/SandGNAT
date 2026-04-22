# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Post-run detection of anti-analysis / anti-VM behaviour.

Phase G of the anti-analysis mitigation plan
(`docs/explanation/anti-analysis-evasion.md`). Even when every phase
A–F mitigation worked, a sample's *attempt* to detect us is itself a
signal — one we want recorded on the analysis row and surfaced in the
audit log.

This module is **pure** — no DB, no Celery, no filesystem mutation.
Inputs: parsed ProcMon events + the StaticAnalysisRow (if static
analysis ran). Output: a list of `EvasionIndicator` records. The task
layer decides how to persist them (flip `analysis_jobs.evasion_observed`
+ append an audit event).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from .models import StaticAnalysisRow
from .parsers.procmon import ProcmonEvent

# --------------------------------------------------------------------------
# Indicator catalogue
# --------------------------------------------------------------------------

# Registry keys malware queries to detect virtualisation. Match is
# case-insensitive on the path suffix so HKLM vs HKEY_LOCAL_MACHINE and
# ControlSet001 vs CurrentControlSet both fire.
_BIOS_REGISTRY_NEEDLES: tuple[str, ...] = (
    r"hardware\acpi\dsdt",
    r"hardware\acpi\fadt",
    r"hardware\acpi\rsdt",
    r"hardware\description\system\systembiosversion",
    r"hardware\description\system\videobiosversion",
    r"hardware\description\system\biosversion",
    r"hardware\description\system\systemmanufacturer",
    r"hardware\description\system\systemproductname",
    r"software\vmware, inc.",
    r"software\oracle\virtualbox guest additions",
    r"software\microsoft\virtual machine\guest",
    r"system\controlset001\services\vboxservice",
    r"system\controlset001\services\vboxsf",
    r"system\controlset001\services\vmmouse",
    r"system\controlset001\services\vmhgfs",
)

# File / device paths that only exist inside a VM. A file-exists probe
# on any of these is unambiguous sandbox detection.
_VM_ARTIFACT_FILES: tuple[str, ...] = (
    r"system32\drivers\vboxmouse.sys",
    r"system32\drivers\vboxguest.sys",
    r"system32\drivers\vboxsf.sys",
    r"system32\drivers\vboxvideo.sys",
    r"system32\drivers\vmmouse.sys",
    r"system32\drivers\vmhgfs.sys",
    r"system32\drivers\vmusbmouse.sys",
    r"system32\drivers\vmci.sys",
    r"system32\drivers\vmx86.sys",
    r"\.\vboxminirdrdn",
    r"\.\vboxguest",
    r"\.\pipe\vboxtrayipc",
    r"\.\hgfs",
    r"program files\vmware\vmware tools",
    r"program files\oracle\virtualbox guest additions",
)

# Process / window names an enumerator would string-compare against.
_ANALYSIS_TOOL_TOKENS: tuple[str, ...] = (
    "procmon.exe",
    "procmon64.exe",
    "systemaudit.exe",         # our renamed Procmon — flag if enumerated by name
    "wireshark.exe",
    "tshark.exe",
    "tcpdump.exe",
    "fiddler.exe",
    "ollydbg.exe",
    "idaq.exe",
    "idaq64.exe",
    "ida64.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "windbg.exe",
    "autoruns.exe",
    "regshot.exe",
    "vmtoolsd.exe",
    "vboxservice.exe",
    "vboxtray.exe",
    "vmsrvc.exe",
    "vmusrvc.exe",
)

# Imports a sample uses for time-based or user-interaction evasion.
# Presence alone is low-severity — plenty of benign programs sleep.
# But paired with ANY runtime indicator the severity escalates.
_SUSPICIOUS_IMPORTS: tuple[str, ...] = (
    "sleep",
    "sleepex",
    "ntdelayexecution",
    "getlastinputinfo",
    "getcursorpos",
    "getsystemtime",
    "getticks",
    "gettickcount",
    "gettickcount64",
    "queryperformancecounter",
    "rdtsc",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "outputdebugstring",
)


@dataclass(frozen=True, slots=True)
class EvasionIndicator:
    """One finding from the evasion detector.

    `evidence` is a human-readable blob (path, module!function name,
    YARA rule id) that makes the hit traceable back to its source
    artifact. `source` is always one of {"procmon", "static", "yara"}.
    """

    category: str
    severity: str
    evidence: str
    source: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Top-level API
# --------------------------------------------------------------------------


def detect_evasion(
    procmon_events: Iterable[ProcmonEvent] = (),
    static: StaticAnalysisRow | None = None,
) -> list[EvasionIndicator]:
    """Run every detector over the provided inputs.

    Either argument may be empty/None — the detector simply skips any
    check that has no data. The returned list is de-duplicated on
    `(category, evidence)` so repeated ProcMon reads of the same key
    only produce one indicator.
    """
    seen: set[tuple[str, str]] = set()
    out: list[EvasionIndicator] = []

    def _add(indicator: EvasionIndicator) -> None:
        key = (indicator.category, indicator.evidence)
        if key in seen:
            return
        seen.add(key)
        out.append(indicator)

    for indicator in _runtime_indicators(procmon_events):
        _add(indicator)
    for indicator in _static_indicators(static):
        _add(indicator)

    # Severity escalation: if a sample has a suspicious import AND
    # any runtime indicator, upgrade the import indicator from "low"
    # to "medium" in place.
    if any(i.source == "procmon" for i in out):
        for i, ind in enumerate(out):
            if ind.source == "static" and ind.category == "suspicious_import":
                out[i] = EvasionIndicator(
                    category=ind.category,
                    severity="medium",
                    evidence=ind.evidence,
                    source=ind.source,
                )

    return out


# --------------------------------------------------------------------------
# Runtime indicators (ProcMon-derived)
# --------------------------------------------------------------------------


def _runtime_indicators(events: Iterable[ProcmonEvent]) -> Iterable[EvasionIndicator]:
    for ev in events:
        op = ev.operation or ""
        path_lower = (ev.path or "").lower()
        detail_lower = (ev.detail or "").lower()

        if op.startswith("RegQueryValue") or op.startswith("RegOpenKey"):
            for needle in _BIOS_REGISTRY_NEEDLES:
                if needle in path_lower:
                    yield EvasionIndicator(
                        category="bios_registry",
                        severity="high",
                        evidence=ev.path,
                        source="procmon",
                    )
                    break

        if op.startswith("CreateFile") or op.startswith("QueryAttributes"):
            for needle in _VM_ARTIFACT_FILES:
                if needle in path_lower:
                    yield EvasionIndicator(
                        category="vm_artifact_file",
                        severity="high",
                        evidence=ev.path,
                        source="procmon",
                    )
                    break

        # Analysis-tool enumeration: a sample opening its own reflection
        # of procmon.exe / wireshark.exe is doing Process32First-style
        # name comparison. We match against both `path` (the file the
        # sample touched) and `detail` (which often carries the
        # enumerated-process name for Thread Create events).
        haystack = f"{path_lower} {detail_lower}"
        for token in _ANALYSIS_TOOL_TOKENS:
            if token in haystack:
                yield EvasionIndicator(
                    category="analysis_tool_enum",
                    severity="high",
                    evidence=f"{ev.operation}: {ev.path or ev.detail}",
                    source="procmon",
                )
                break


# --------------------------------------------------------------------------
# Static indicators (StaticAnalysisRow-derived)
# --------------------------------------------------------------------------


def _static_indicators(
    static: StaticAnalysisRow | None,
) -> Iterable[EvasionIndicator]:
    if static is None:
        return

    # Deep YARA matches tagged anti_vm / anti_analysis are the cheapest
    # and most definitive static signal.
    _yara_needles = ("anti_vm", "antivm", "anti_analysis", "antianalysis", "anti_debug", "antidebug")
    for rule in static.deep_yara_matches:
        rule_lower = rule.lower()
        if any(needle in rule_lower for needle in _yara_needles):
            yield EvasionIndicator(
                category="yara_anti_vm",
                severity="high",
                evidence=rule,
                source="yara",
            )

    # capa's capability catalogue uses the "anti-analysis" namespace for
    # these. Any capability under that namespace is a direct hit.
    for capa in static.capa_capabilities:
        namespace = str(capa.get("namespace", "")).lower()
        name = str(capa.get("name", ""))
        if namespace.startswith("anti-analysis"):
            yield EvasionIndicator(
                category="capa_anti_analysis",
                severity="high",
                evidence=f"{namespace}::{name}" if name else namespace,
                source="static",
            )

    # Suspicious imports — low severity on their own; escalated to
    # medium by the top-level escalation pass when paired with a
    # runtime hit.
    if static.imports:
        # Imports are stored as {dll: [symbol, ...]} or as a flat list,
        # depending on what the linux guest produced. Handle both.
        candidates: list[str] = []
        if isinstance(static.imports, dict):
            for syms in static.imports.values():
                if isinstance(syms, list):
                    candidates.extend(str(s) for s in syms)
        elif isinstance(static.imports, list):
            candidates.extend(str(s) for s in static.imports)

        for sym in candidates:
            sym_lower = sym.lower()
            for token in _SUSPICIOUS_IMPORTS:
                if token == sym_lower or sym_lower.endswith(f"!{token}"):
                    yield EvasionIndicator(
                        category="suspicious_import",
                        severity="low",
                        evidence=sym,
                        source="static",
                    )
                    break


# --------------------------------------------------------------------------
# Convenience: flatten to the audit-log shape the task layer persists.
# --------------------------------------------------------------------------


def summarise(indicators: Iterable[EvasionIndicator]) -> dict[str, Any]:
    """Return a dict suitable for the `analysis_audit_log.details` column."""
    indicators = list(indicators)
    by_category: dict[str, int] = {}
    severities: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    for ind in indicators:
        by_category[ind.category] = by_category.get(ind.category, 0) + 1
        if ind.severity in severities:
            severities[ind.severity] += 1
    return {
        "count": len(indicators),
        "by_category": by_category,
        "by_severity": severities,
        "indicators": [ind.as_dict() for ind in indicators],
    }
