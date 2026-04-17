"""Host-side driver for the guest agent.

This module is the mirror image of `guest_agent.watcher`. It writes a job
manifest into the staging share's `pending/` directory, then polls the
`completed/{job_id}/` directory for the `result.json` sentinel. Once the
sentinel appears, it returns the path so the analyzer can consume the
artifacts.

The staging root is usually an NFS/SMB mount on the orchestrator that the
Windows guest sees over SMB. In tests it's just a local directory.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from .schema import (
    DROPPED_DIR,
    MANIFEST_FILENAME,
    MODE_DETONATION,
    PCAP_FILE,
    PROCMON_CSV,
    REGSHOT_DIFF,
    RESULT_FILENAME,
    SCHEMA_VERSION,
    CaptureConfig,
    JobManifest,
    ResultEnvelope,
    StaticAnalysisOptions,
    guest_sample_path,
    linux_guest_sample_path,
)

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ArtifactLocations:
    """Resolved absolute paths to each artifact, or None if not produced."""

    workspace: Path
    envelope: ResultEnvelope
    procmon_csv: Path | None
    pcap: Path | None
    regshot_diff: Path | None
    dropped_dir: Path | None


class GuestDriverError(RuntimeError):
    pass


def _pending_path(staging_root: Path, job_id: UUID) -> Path:
    return staging_root / "pending" / f"{job_id}.json"


def _completed_path(staging_root: Path, job_id: UUID) -> Path:
    return staging_root / "completed" / str(job_id)


def _ensure_staging(staging_root: Path) -> None:
    for sub in ("pending", "in-flight", "completed"):
        (staging_root / sub).mkdir(parents=True, exist_ok=True)


def _sha256_file(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def stage_sample(staging_root: Path, job_id: UUID, sample_source: Path) -> tuple[Path, str]:
    """Copy the sample into `staging/samples/{job_id}/{filename}` and hash it.

    Returns (path_on_staging, sha256). The guest reads from this path via its
    own SMB view; the in-guest path is derived by `guest_sample_path()`.

    On a real deployment the SMB share's `samples/` folder is exposed to the
    guest as `C:\\sandgnat\\samples\\{job_id}\\...`; path translation is a
    configuration concern, not code's.
    """
    dest_dir = staging_root / "samples" / str(job_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / sample_source.name
    shutil.copy2(sample_source, dest)
    return dest, _sha256_file(dest)


def submit_job(
    staging_root: Path,
    job_id: UUID,
    sample_name: str,
    sample_sha256: str,
    *,
    timeout_seconds: int,
    capture: CaptureConfig | None = None,
    arguments: list[str] | None = None,
    mode: str = MODE_DETONATION,
    static: StaticAnalysisOptions | None = None,
) -> None:
    """Atomically publish a job manifest to the guest.

    `mode` selects which guest class is expected to pick up the job — Windows
    detonation guests refuse `static_analysis` manifests and vice versa, so
    a mis-routed job fails fast in the guest rather than producing nonsense.
    """
    _ensure_staging(staging_root)
    sample_path_for_guest = (
        linux_guest_sample_path(str(job_id), sample_name)
        if mode != MODE_DETONATION
        else guest_sample_path(str(job_id), sample_name)
    )
    manifest = JobManifest(
        schema_version=SCHEMA_VERSION,
        job_id=str(job_id),
        sample_sha256=sample_sha256,
        sample_guest_path=sample_path_for_guest,
        sample_name=sample_name,
        arguments=arguments or [],
        timeout_seconds=timeout_seconds,
        mode=mode,
        capture=capture or CaptureConfig(),
        static=static or StaticAnalysisOptions(),
    )
    pending = _pending_path(staging_root, job_id)
    tmp = pending.with_suffix(".json.tmp")
    tmp.write_text(manifest.to_json(), encoding="utf-8")
    tmp.replace(pending)
    log.info("Published job manifest (%s): %s", mode, pending)


def wait_for_result(
    staging_root: Path,
    job_id: UUID,
    *,
    timeout_seconds: int,
    poll_interval: float = 2.0,
) -> ArtifactLocations:
    """Block until the guest writes result.json, then return artifact paths.

    `timeout_seconds` is the host-side watchdog: typically the detonation
    timeout plus a generous buffer for capture-export and SMB sync. Raises
    GuestDriverError on timeout; the caller should mark the job failed and
    reset the VM.
    """
    workspace = _completed_path(staging_root, job_id)
    result_path = workspace / RESULT_FILENAME
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if result_path.exists():
            break
        time.sleep(poll_interval)
    else:
        raise GuestDriverError(
            f"guest did not publish result for job {job_id} within {timeout_seconds}s"
        )

    envelope = ResultEnvelope.from_json(result_path.read_text(encoding="utf-8"))
    return ArtifactLocations(
        workspace=workspace,
        envelope=envelope,
        procmon_csv=_existing(workspace / PROCMON_CSV),
        pcap=_existing(workspace / PCAP_FILE),
        regshot_diff=_existing(workspace / REGSHOT_DIFF),
        dropped_dir=_existing(workspace / DROPPED_DIR),
    )


def _existing(path: Path) -> Path | None:
    return path if path.exists() else None


def cleanup_completed(staging_root: Path, job_id: UUID) -> None:
    """Remove the completed/ workspace after artifacts have been ingested.

    We keep the sample in `samples/{job_id}` until explicit quarantine
    transfer; that's a separate concern.
    """
    target = _completed_path(staging_root, job_id)
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    pending = _pending_path(staging_root, job_id)
    if pending.exists():
        pending.unlink(missing_ok=True)
