"""ssdeep + TLSH fuzzy hashes."""

from __future__ import annotations

from typing import Any

try:
    import ssdeep  # type: ignore[import-not-found]

    _SSDEEP_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    ssdeep = None  # type: ignore[assignment]
    _SSDEEP_AVAILABLE = False

try:
    import tlsh  # type: ignore[import-not-found]

    _TLSH_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    tlsh = None  # type: ignore[assignment]
    _TLSH_AVAILABLE = False


def compute_fuzzy_hashes(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"available": _SSDEEP_AVAILABLE or _TLSH_AVAILABLE}
    if _SSDEEP_AVAILABLE:
        try:
            out["ssdeep"] = ssdeep.hash(data)
        except Exception as exc:  # noqa: BLE001
            out["ssdeep_error"] = str(exc)
    else:
        out["ssdeep"] = None
    if _TLSH_AVAILABLE:
        try:
            # TLSH requires a minimum input length (~50 bytes) and some entropy.
            h = tlsh.hash(data)
            out["tlsh"] = h or None
        except Exception as exc:  # noqa: BLE001
            out["tlsh_error"] = str(exc)
    else:
        out["tlsh"] = None
    return out
