"""Embedded-string extraction + per-section entropy.

Stdlib only. We don't need GNU `strings(1)` for ASCII/UTF-16 enumeration —
a couple of regexes are enough and we can run on PyInstaller-frozen guests
with no extra binary.
"""

from __future__ import annotations

import math
import re
from typing import Any

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_URL_RE = re.compile(rb"https?://[^\s'\"<>]{4,256}")
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE = re.compile(rb"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[\w\\\.\- ]{3,200}")


def extract_strings_and_entropy(data: bytes, *, max_strings_bytes: int) -> dict[str, Any]:
    ascii_strings = [m.group(0).decode("ascii", errors="replace") for m in _ASCII_RUN.finditer(data)]
    utf16_strings = [
        m.group(0).decode("utf-16-le", errors="replace") for m in _UTF16_RUN.finditer(data)
    ]
    urls = sorted({m.group(0).decode("ascii", errors="replace") for m in _URL_RE.finditer(data)})
    ips = sorted({m.group(0).decode("ascii", errors="replace") for m in _IPV4_RE.finditer(data)})
    reg = sorted({m.group(0).decode("ascii", errors="replace") for m in _REG_RE.finditer(data)})

    # Truncate the raw lists to a configurable cap so the envelope doesn't
    # blow up on a string-heavy installer.
    ascii_kept = _truncate_strings(ascii_strings, max_strings_bytes)
    utf16_kept = _truncate_strings(utf16_strings, max_strings_bytes)

    return {
        "available": True,
        "ascii_count": len(ascii_strings),
        "utf16_count": len(utf16_strings),
        "ascii_sample": ascii_kept,
        "utf16_sample": utf16_kept,
        "urls": urls[:1024],
        "ips": ips[:1024],
        "registry_keys": reg[:1024],
        "overall_entropy": _shannon_entropy(data),
    }


def _truncate_strings(strs: list[str], max_bytes: int) -> list[str]:
    out: list[str] = []
    used = 0
    for s in strs:
        cost = len(s) + 1
        if used + cost > max_bytes:
            break
        out.append(s)
        used += cost
    return out


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
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
