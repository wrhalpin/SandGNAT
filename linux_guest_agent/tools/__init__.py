"""Tool wrappers for the Linux static-analysis guest.

Each wrapper exposes a single function that takes the sample bytes (or path
plus bytes) plus a `LinuxGuestConfig` and returns a dict of findings.
Missing third-party deps degrade to `{"available": False, "skipped": True,
"reason": "..."}` rather than raising — the guest is meant to keep running
even on partial toolchains.
"""

from .pe_elf import analyze_pe_elf
from .fuzzy import compute_fuzzy_hashes
from .strings_entropy import extract_strings_and_entropy
from .yara_deep import scan_deep_yara
from .capa_runner import run_capa
from .disasm_trigrams import compute_trigram_signatures

__all__ = [
    "analyze_pe_elf",
    "compute_fuzzy_hashes",
    "extract_strings_and_entropy",
    "scan_deep_yara",
    "run_capa",
    "compute_trigram_signatures",
]
