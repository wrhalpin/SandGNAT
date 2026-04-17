"""SandGNAT guest agent.

Runs inside the Windows analysis VM. Polls the staging share for a job
manifest, coordinates capture tools (ProcMon, tshark, RegShot), detonates
the sample, packages artifacts, and writes them back to the staging share.

Deliberately stdlib-only so PyInstaller bundling is trivial.
"""

__version__ = "0.1.0"
