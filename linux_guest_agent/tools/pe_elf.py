"""PE / ELF header parsing.

PE handled by `pefile`, ELF by `pyelftools`. Both are optional — if neither
is installed the tool returns `{"available": False, ...}` and the rest of
the pipeline carries on with raw byte data only (still gets fuzzy hashes,
strings, trigrams).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

try:
    import pefile  # type: ignore[import-not-found]

    _PEFILE_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    pefile = None  # type: ignore[assignment]
    _PEFILE_AVAILABLE = False

try:
    from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]

    _ELFTOOLS_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    ELFFile = None  # type: ignore[assignment]
    _ELFTOOLS_AVAILABLE = False

log = logging.getLogger(__name__)

_PE_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"


def detect_format(data: bytes) -> str | None:
    if data.startswith(_PE_MAGIC):
        return "pe"
    if data.startswith(_ELF_MAGIC):
        return "elf"
    return None


def analyze_pe_elf(sample_path: Path, data: bytes) -> dict[str, Any]:
    fmt = detect_format(data)
    if fmt == "pe":
        return _analyze_pe(sample_path, data)
    if fmt == "elf":
        return _analyze_elf(sample_path, data)
    return {
        "available": True,
        "skipped": True,
        "reason": "format not PE or ELF",
        "file_format": "unknown",
    }


def _analyze_pe(sample_path: Path, data: bytes) -> dict[str, Any]:
    if not _PEFILE_AVAILABLE:
        return {"available": False, "skipped": True, "reason": "pefile not installed"}
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # noqa: BLE001 — pefile raises a zoo
        return {"available": True, "skipped": True, "reason": f"pefile parse failed: {exc}"}

    is_64 = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
    file_format = "pe64" if is_64 else "pe32"
    arch = {
        0x014c: "x86",
        0x8664: "x86_64",
        0x01c0: "arm",
        0xaa64: "aarch64",
    }.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))

    sections = []
    for s in pe.sections:
        sections.append(
            {
                "name": s.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                "vsize": int(s.Misc_VirtualSize),
                "rsize": int(s.SizeOfRawData),
                "entropy": float(s.get_entropy()),
                "flags": _pe_section_flags(s.Characteristics),
            }
        )

    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            funcs: list[str] = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("ascii", errors="replace"))
                else:
                    funcs.append(f"ord_{imp.ordinal}")
            imports[dll] = funcs

    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("ascii", errors="replace"))

    imphash: str | None = None
    try:
        imphash = pe.get_imphash() or None
    except Exception:  # noqa: BLE001
        imphash = None

    return {
        "available": True,
        "skipped": False,
        "file_format": file_format,
        "architecture": arch,
        "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "imphash": imphash,
        "is_packed_heuristic": _looks_packed(sections),
        "sections": sections,
        "imports": imports,
        "exports": exports,
    }


def _analyze_elf(sample_path: Path, data: bytes) -> dict[str, Any]:
    if not _ELFTOOLS_AVAILABLE:
        return {"available": False, "skipped": True, "reason": "pyelftools not installed"}
    import io
    import math

    try:
        elf = ELFFile(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 — pyelftools raises a zoo
        return {"available": True, "skipped": True, "reason": f"elf parse failed: {exc}"}

    arch_map = {
        "EM_386": "x86",
        "EM_X86_64": "x86_64",
        "EM_ARM": "arm",
        "EM_AARCH64": "aarch64",
    }
    arch = arch_map.get(elf.header["e_machine"], elf.header["e_machine"])
    file_format = "elf64" if elf.elfclass == 64 else "elf32"

    sections = []
    for s in elf.iter_sections():
        body = s.data() or b""
        sections.append(
            {
                "name": s.name,
                "vsize": int(s["sh_size"]),
                "rsize": len(body),
                "entropy": _shannon_entropy(body),
                "flags": _elf_section_flags(int(s["sh_flags"])),
            }
        )

    imports: list[dict[str, str]] = []
    for s in elf.iter_sections():
        if s.header["sh_type"] in {"SHT_DYNSYM", "SHT_SYMTAB"}:
            try:
                for sym in s.iter_symbols():
                    if sym.entry["st_info"]["bind"] == "STB_GLOBAL" and sym.entry[
                        "st_shndx"
                    ] == "SHN_UNDEF":
                        imports.append({"name": sym.name, "section": s.name})
            except Exception:  # noqa: BLE001
                continue

    return {
        "available": True,
        "skipped": False,
        "file_format": file_format,
        "architecture": arch,
        "entry_point": int(elf.header["e_entry"]),
        "imphash": None,
        "is_packed_heuristic": _looks_packed(sections),
        "sections": sections,
        "imports": imports,
        "exports": [],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PE_SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}

_ELF_SECTION_FLAGS = {
    0x1: "WRITE",
    0x2: "ALLOC",
    0x4: "EXECINSTR",
}


def _pe_section_flags(chars: int) -> list[str]:
    return sorted(name for mask, name in _PE_SECTION_FLAGS.items() if chars & mask)


def _elf_section_flags(flags: int) -> list[str]:
    return sorted(name for mask, name in _ELF_SECTION_FLAGS.items() if flags & mask)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    h = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        h -= p * math.log2(p)
    return h


def _looks_packed(sections: list[dict[str, Any]]) -> bool:
    """Crude packer heuristic: any executable-flagged section above 7.0 entropy."""
    for s in sections:
        flags = s.get("flags", [])
        if "EXECUTE" not in flags and "EXECINSTR" not in flags:
            continue
        if float(s.get("entropy") or 0.0) >= 7.0:
            return True
    return False
