"""Shared wire schema between the orchestrator and the Windows guest agent.

Both sides import this module. It must stay stdlib-only so the guest agent can
be frozen with PyInstaller without pulling in celery/psycopg/proxmoxer.

The staging volume (typically an SMB share mounted on both sides) holds:

    {staging_root}/pending/{job_id}.json        # host -> guest: job manifest
    {staging_root}/in-flight/{job_id}/           # guest: work in progress
    {staging_root}/completed/{job_id}/           # guest -> host: result + artifacts
        ├── result.json                          # this envelope, serialised
        ├── procmon.csv
        ├── capture.pcap
        ├── regshot_diff.txt
        ├── dropped_files.json
        └── dropped/<sha256>                     # collected dropped files

The guest picks up work by atomically moving `pending/{job_id}.json` into
`in-flight/{job_id}/job.json`. On completion it writes everything under
`completed/{job_id}/` and drops a sentinel file `result.json` *last* so the
host can detect completion by polling for that single filename.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

SCHEMA_VERSION = 1

# Sentinel filenames — kept as module constants so host and guest cannot drift.
MANIFEST_FILENAME = "job.json"
RESULT_FILENAME = "result.json"
DROPPED_FILES_MANIFEST = "dropped_files.json"
PROCMON_CSV = "procmon.csv"
PCAP_FILE = "capture.pcap"
REGSHOT_DIFF = "regshot_diff.txt"
DROPPED_DIR = "dropped"


# ---------------------------------------------------------------------------
# Job manifest: host -> guest
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class CaptureConfig:
    procmon: bool = True
    tshark: bool = True
    regshot: bool = True
    # Directories on the guest to scan for dropped files.
    dropped_file_roots: list[str] = field(
        default_factory=lambda: [
            r"C:\Users\Analyst\AppData\Local\Temp",
            r"C:\Users\Analyst\AppData\Roaming",
            r"C:\ProgramData",
            r"C:\Windows\Temp",
        ]
    )
    # Max bytes to copy back per dropped file. Protects the staging share from
    # pathological multi-GB writes. 32 MiB default.
    max_dropped_file_bytes: int = 32 * 1024 * 1024


@dataclass(slots=True)
class JobManifest:
    schema_version: int
    job_id: str
    sample_sha256: str
    sample_guest_path: str  # e.g. "C:\\sandgnat\\{job_id}\\sample.exe"
    sample_name: str
    arguments: list[str] = field(default_factory=list)
    timeout_seconds: int = 300
    capture: CaptureConfig = field(default_factory=CaptureConfig)

    def to_json(self) -> str:
        payload = asdict(self)
        return json.dumps(payload, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "JobManifest":
        data = json.loads(raw)
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported job manifest schema_version: {data.get('schema_version')!r}"
            )
        capture = CaptureConfig(**data.pop("capture", {}))
        return cls(capture=capture, **data)


# ---------------------------------------------------------------------------
# Result envelope: guest -> host
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class DroppedFileRecord:
    """One row per file dropped during detonation.

    `relative_path` is relative to the job's `completed/{job_id}/` directory;
    the host resolves it to an absolute path for quarantine ingestion.
    """

    sha256: str
    md5: str
    size_bytes: int
    original_path: str
    relative_path: str
    created_by_pid: int | None = None
    created_by_name: str | None = None


@dataclass(slots=True)
class CaptureOutcome:
    tool: str
    started: bool
    stopped_cleanly: bool
    output_filename: str | None = None
    error: str | None = None


@dataclass(slots=True)
class ResultEnvelope:
    schema_version: int
    job_id: str
    status: str  # 'completed' | 'failed' | 'timeout'
    started_at: str  # ISO-8601 UTC with Z suffix
    completed_at: str
    execution_duration_seconds: float
    sample_pid: int | None
    sample_exit_code: int | None
    timed_out: bool
    captures: list[CaptureOutcome] = field(default_factory=list)
    dropped_files: list[DroppedFileRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Free-form metadata: detected evasion attempts, evasion strings seen, etc.
    flags: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "ResultEnvelope":
        data = json.loads(raw)
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported result envelope schema_version: {data.get('schema_version')!r}"
            )
        captures = [CaptureOutcome(**c) for c in data.pop("captures", [])]
        dropped = [DroppedFileRecord(**d) for d in data.pop("dropped_files", [])]
        return cls(captures=captures, dropped_files=dropped, **data)


# ---------------------------------------------------------------------------
# Path helpers — parameterised on platform so host (POSIX) and guest (Windows)
# use the same module without platform sniffing.
# ---------------------------------------------------------------------------

def guest_sample_path(job_id: str, sample_name: str) -> str:
    """Deterministic in-guest path for a sample. Windows-style."""
    return str(PureWindowsPath(f"C:/sandgnat/{job_id}/{sample_name}"))


def staging_subpath(kind: str, job_id: str) -> PurePosixPath:
    """Relative path within the staging volume. Use POSIX form — SMB translates."""
    if kind not in {"pending", "in-flight", "completed"}:
        raise ValueError(f"unknown staging kind: {kind!r}")
    return PurePosixPath(kind) / job_id
