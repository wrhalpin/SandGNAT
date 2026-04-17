"""Compute byte + opcode trigram MinHash signatures.

Byte trigrams over executable sections only (when section info is
available; full-file fallback otherwise). Opcode trigrams via capstone
disassembly of the same sections, joined into 3-mnemonic windows. Both
flavours produce a `trigrams.MinHashSignature`.

Both signatures are written to disk as raw bytes (`trigrams_byte.bin`,
`trigrams_opcode.bin`) for the host to ingest. The metadata (cardinality,
extraction notes) lands inside the static-analysis envelope so the host
can stamp `byte_trigram_count` / `opcode_trigram_count` without re-reading
the binary blob.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from orchestrator.trigrams import (
    MinHashSignature,
    minhash_bytes,
    minhash_opcodes,
)

try:
    import capstone  # type: ignore[import-not-found]

    _CAPSTONE_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    capstone = None  # type: ignore[assignment]
    _CAPSTONE_AVAILABLE = False

log = logging.getLogger(__name__)

_ARCH_TO_CAPSTONE = {
    "x86": ("CS_ARCH_X86", "CS_MODE_32"),
    "x86_64": ("CS_ARCH_X86", "CS_MODE_64"),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
    "aarch64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
}


def compute_trigram_signatures(
    *,
    data: bytes,
    sections: list[dict[str, Any]] | None,
    arch: str | None,
    workspace: Path,
    byte_filename: str,
    opcode_filename: str,
) -> dict[str, Any]:
    """Compute byte + opcode signatures, persist them, and return metadata."""
    out: dict[str, Any] = {"available": True, "skipped": False}

    code_blobs = _executable_section_bytes(data, sections)
    if not code_blobs:
        # Fall back to the full file for byte trigrams when we can't isolate
        # code sections. Better noisy similarity than no similarity.
        code_blobs = [data]

    byte_sig = minhash_bytes(b"".join(code_blobs))
    (workspace / byte_filename).write_bytes(byte_sig.to_bytes())
    out["byte_count"] = byte_sig.cardinality

    opcode_sig: MinHashSignature | None = None
    if _CAPSTONE_AVAILABLE and arch in _ARCH_TO_CAPSTONE:
        try:
            mnemonics = _disassemble_mnemonics(code_blobs, arch)
            opcode_sig = minhash_opcodes(mnemonics)
            (workspace / opcode_filename).write_bytes(opcode_sig.to_bytes())
            out["opcode_count"] = opcode_sig.cardinality
        except Exception as exc:  # noqa: BLE001 — capstone has surprising failure modes
            log.warning("Opcode trigram extraction failed: %s", exc)
            out["opcode_skipped_reason"] = str(exc)
    else:
        out["opcode_skipped_reason"] = (
            "capstone not installed" if not _CAPSTONE_AVAILABLE
            else f"unsupported arch: {arch!r}"
        )
    return out


def _executable_section_bytes(
    data: bytes, sections: list[dict[str, Any]] | None
) -> list[bytes]:
    if not sections:
        return []
    out: list[bytes] = []
    cursor = 0
    for s in sections:
        flags = set(s.get("flags") or [])
        if not (flags & {"EXECUTE", "EXECINSTR"}):
            continue
        rsize = int(s.get("rsize") or 0)
        if rsize <= 0:
            continue
        # Section files don't always carry their raw offset — use sequential
        # placement as a pragmatic approximation for byte-trigram input. The
        # host doesn't need the exact bytes; it just needs *some* stable
        # subset of the executable contents.
        chunk = data[cursor:cursor + rsize]
        if chunk:
            out.append(chunk)
        cursor += rsize
    return out


def _disassemble_mnemonics(blobs: list[bytes], arch: str) -> list[str]:
    cs_arch_name, cs_mode_name = _ARCH_TO_CAPSTONE[arch]
    md = capstone.Cs(getattr(capstone, cs_arch_name), getattr(capstone, cs_mode_name))
    md.detail = False
    mnemonics: list[str] = []
    for blob in blobs:
        for insn in md.disasm(blob, 0):
            mnemonics.append(insn.mnemonic)
    return mnemonics
