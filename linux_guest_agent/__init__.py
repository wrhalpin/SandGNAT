"""Linux static-analysis guest agent.

Mirror of `guest_agent/` for the dedicated Linux static-analysis VM.
Polls the staging share for `mode="static_analysis"` jobs, runs the
configured tool suite (PE/ELF parsing, fuzzy hashes, deep YARA, CAPA,
strings + entropy, byte/opcode trigrams), and writes the results back
to `completed/{job_id}/` for the host orchestrator to pick up.
"""

from .config import LinuxGuestConfig

__all__ = ["LinuxGuestConfig"]
