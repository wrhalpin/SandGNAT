# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Parse the Linux static-analysis guest's envelope into a normalised bundle.

The guest writes `static_analysis.json` (per-tool sections, see
`linux_guest_agent.runner`) plus binary MinHash files
(`trigrams_byte.bin`, `trigrams_opcode.bin`) into
`completed/{job_id}/`. This module turns those files into a
`StaticAnalysisBundle` that the Celery static task can hand straight to
the persistence layer and the similarity engine.

This module is **pure** — no DB, no Celery, no filesystem mutation beyond
reading the artifacts. Mirrors the role of `analyzer.py` for detonation.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from .models import StaticAnalysisRow
from .schema import (
    STATIC_ANALYSIS_JSON,
    TRIGRAMS_BYTE_BIN,
    TRIGRAMS_OPCODE_BIN,
)
from .trigrams import MinHashSignature, NUM_PERMUTATIONS

log = logging.getLogger(__name__)


@dataclass(slots=True)
class StaticAnalysisBundle:
    """Everything the host needs after a static-analysis run."""

    row: StaticAnalysisRow
    imphash: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None
    byte_signature: MinHashSignature | None = None
    byte_trigram_count: int = 0
    opcode_signature: MinHashSignature | None = None
    opcode_trigram_count: int = 0
    deep_yara_matches: list[str] = field(default_factory=list)
    capa_capabilities: list[dict[str, Any]] = field(default_factory=list)


def parse_static_workspace(
    *, analysis_id: UUID, workspace: Path
) -> StaticAnalysisBundle:
    """Read the guest's static-analysis artifacts and produce a bundle.

    Missing per-tool sections are tolerated — the guest reports per-tool
    outcomes in `tools` and we just propagate whatever it managed to compute.
    Missing trigram files leave the corresponding signature as None (the
    short-circuit logic just falls back to whichever flavour is present).
    """
    envelope_path = workspace / STATIC_ANALYSIS_JSON
    if not envelope_path.exists():
        raise FileNotFoundError(f"static_analysis.json missing in {workspace}")
    envelope: dict[str, Any] = json.loads(envelope_path.read_text(encoding="utf-8"))

    pe_elf = envelope.get("pe_elf") or {}
    fuzzy = envelope.get("fuzzy") or {}
    strings = envelope.get("strings_summary") or {}
    yara = envelope.get("yara_matches") or []
    capa = envelope.get("capa_capabilities") or []

    sections = pe_elf.get("sections") or []
    overall_entropy = _compute_overall_entropy(sections, fallback=pe_elf.get("overall_entropy"))

    row = StaticAnalysisRow(
        analysis_id=analysis_id,
        file_format=pe_elf.get("file_format"),
        architecture=pe_elf.get("architecture"),
        entry_point=pe_elf.get("entry_point"),
        is_packed_heuristic=pe_elf.get("is_packed_heuristic"),
        section_count=len(sections) if sections else None,
        overall_entropy=overall_entropy,
        imports=pe_elf.get("imports"),
        exports=pe_elf.get("exports"),
        sections=sections,
        strings_summary=strings,
        capa_capabilities=capa,
        deep_yara_matches=list(yara),
        raw_envelope=envelope,
    )

    bundle = StaticAnalysisBundle(
        row=row,
        imphash=pe_elf.get("imphash"),
        ssdeep=fuzzy.get("ssdeep"),
        tlsh=fuzzy.get("tlsh"),
        deep_yara_matches=list(yara),
        capa_capabilities=list(capa),
    )

    trigrams_meta = envelope.get("trigrams") or {}
    byte_blob_path = workspace / TRIGRAMS_BYTE_BIN
    if byte_blob_path.exists():
        bundle.byte_trigram_count = int(trigrams_meta.get("byte_count") or 0)
        try:
            bundle.byte_signature = MinHashSignature.from_bytes(
                byte_blob_path.read_bytes(),
                cardinality=bundle.byte_trigram_count,
            )
        except ValueError:
            log.warning("Byte trigram blob is malformed for %s; ignoring", analysis_id)
            bundle.byte_signature = None

    opcode_blob_path = workspace / TRIGRAMS_OPCODE_BIN
    if opcode_blob_path.exists():
        bundle.opcode_trigram_count = int(trigrams_meta.get("opcode_count") or 0)
        try:
            bundle.opcode_signature = MinHashSignature.from_bytes(
                opcode_blob_path.read_bytes(),
                cardinality=bundle.opcode_trigram_count,
            )
        except ValueError:
            log.warning("Opcode trigram blob is malformed for %s; ignoring", analysis_id)
            bundle.opcode_signature = None

    return bundle


def _compute_overall_entropy(
    sections: list[dict[str, Any]], *, fallback: float | None
) -> float | None:
    """Size-weighted average of per-section entropies, falling back to the
    guest-reported value if sections are missing or unweightable."""
    if not sections:
        return _safe_float(fallback)
    total_bytes = 0
    weighted = 0.0
    for s in sections:
        size = int(s.get("rsize") or s.get("size") or 0)
        entropy = _safe_float(s.get("entropy"))
        if size <= 0 or entropy is None:
            continue
        total_bytes += size
        weighted += entropy * size
    if total_bytes == 0:
        return _safe_float(fallback)
    return weighted / total_bytes


def _safe_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# Sanity assertion at import time so we catch a NUM_PERMUTATIONS mismatch early.
assert NUM_PERMUTATIONS > 0
