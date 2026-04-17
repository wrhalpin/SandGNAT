"""Dropped-file detection.

We take a pre-execution inventory of each watched directory (path -> mtime,
size), then after detonation walk the same roots again and flag any path
whose inventory entry is new or whose (mtime, size) has changed. For every
flagged path we hash the current contents and copy a bounded-size snapshot
into the staging share's `completed/{job_id}/dropped/` directory, named by
SHA-256 to dedupe within a single job.

Intentionally platform-neutral: no `winreg` or Windows-specific APIs. The
Windows reality (case-insensitive paths, long-path support) is handled by
using `Path.resolve()` and letting the OS do the right thing.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from orchestrator.schema import DroppedFileRecord


# Common Windows temp/cache paths we never want to collect even if they change.
# These would otherwise produce hundreds of irrelevant "dropped" records.
IGNORED_NAME_SUFFIXES = (
    ".tmp",  # some malware *does* write real droppers as .tmp — we still collect
             # non-random names. See the more-specific filter in _should_ignore.
)
IGNORED_PATH_FRAGMENTS = (
    r"\Microsoft\Windows\INetCache",
    r"\Microsoft\Windows\Temporary Internet Files",
    r"\Microsoft\Windows\WER",
    r"\Microsoft\Windows\Explorer\ThumbCacheToDelete",
)


@dataclass(slots=True)
class FileInventory:
    entries: dict[str, tuple[float, int]] = field(default_factory=dict)

    def record(self, path: str, mtime: float, size: int) -> None:
        self.entries[path] = (mtime, size)

    def is_new_or_changed(self, path: str, mtime: float, size: int) -> bool:
        prior = self.entries.get(path)
        if prior is None:
            return True
        return prior != (mtime, size)


def _should_ignore(path: Path) -> bool:
    p = str(path)
    return any(frag in p for frag in IGNORED_PATH_FRAGMENTS)


def snapshot_roots(roots: list[Path]) -> FileInventory:
    """Record (mtime, size) for every regular file under each root."""
    inventory = FileInventory()
    for root in roots:
        if not root.exists():
            continue
        for entry in root.rglob("*"):
            if not entry.is_file():
                continue
            if _should_ignore(entry):
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue
            inventory.record(str(entry), stat.st_mtime, stat.st_size)
    return inventory


def _hash_file(path: Path) -> tuple[str, str]:
    """Return (sha256, md5) computed in a single pass."""
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)  # required for STIX compat
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def collect_dropped_files(
    roots: list[Path],
    baseline: FileInventory,
    destination_dir: Path,
    *,
    max_file_bytes: int,
) -> list[DroppedFileRecord]:
    """Walk `roots`, detect changes vs. `baseline`, copy-out, return records.

    Files larger than `max_file_bytes` are skipped — their metadata is still
    recorded (with size) but `relative_path` is left empty so the host knows
    the bytes weren't shipped. This prevents a malicious sample from filling
    the staging share with gigabyte-sized droppers.
    """
    destination_dir.mkdir(parents=True, exist_ok=True)
    records: list[DroppedFileRecord] = []
    seen_hashes: set[str] = set()

    for root in roots:
        if not root.exists():
            continue
        for entry in root.rglob("*"):
            if not entry.is_file() or _should_ignore(entry):
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue
            if not baseline.is_new_or_changed(str(entry), stat.st_mtime, stat.st_size):
                continue

            if stat.st_size > max_file_bytes:
                records.append(
                    DroppedFileRecord(
                        sha256="",
                        md5="",
                        size_bytes=stat.st_size,
                        original_path=str(entry),
                        relative_path="",  # signals "not shipped"
                    )
                )
                continue

            try:
                sha256, md5 = _hash_file(entry)
            except OSError:
                continue

            if sha256 in seen_hashes:
                # Dedupe: same content in two locations — record both original
                # paths but only copy once.
                records.append(
                    DroppedFileRecord(
                        sha256=sha256,
                        md5=md5,
                        size_bytes=stat.st_size,
                        original_path=str(entry),
                        relative_path=f"dropped/{sha256}",
                    )
                )
                continue

            dest = destination_dir / sha256
            try:
                shutil.copy2(entry, dest)
            except OSError as exc:
                records.append(
                    DroppedFileRecord(
                        sha256=sha256,
                        md5=md5,
                        size_bytes=stat.st_size,
                        original_path=str(entry),
                        relative_path="",
                        created_by_name=f"copy-failed: {exc}",
                    )
                )
                continue

            seen_hashes.add(sha256)
            records.append(
                DroppedFileRecord(
                    sha256=sha256,
                    md5=md5,
                    size_bytes=stat.st_size,
                    original_path=str(entry),
                    relative_path=f"dropped/{sha256}",
                )
            )

    return records
