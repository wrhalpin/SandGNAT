"""Tests for the dropped-files inventory + collection logic.

These run on any OS — we're just doing filesystem before/after diffs.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from guest_agent.capture.dropped_files import collect_dropped_files, snapshot_roots


def test_snapshot_records_existing_files(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    (root / "a.txt").write_bytes(b"before")
    inv = snapshot_roots([root])
    assert str(root / "a.txt") in inv.entries


def test_collect_reports_only_new_or_changed(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    dropped_dir = tmp_path / "dropped"
    root.mkdir()
    existing = root / "existing.txt"
    existing.write_bytes(b"old")

    baseline = snapshot_roots([root])

    # Add a new file and modify the existing one.
    new = root / "payload.dll"
    new.write_bytes(b"malicious-bytes")
    existing.write_bytes(b"tampered")

    records = collect_dropped_files(
        roots=[root],
        baseline=baseline,
        destination_dir=dropped_dir,
        max_file_bytes=10 * 1024 * 1024,
    )

    by_path = {r.original_path: r for r in records}
    assert str(new) in by_path
    assert str(existing) in by_path

    new_record = by_path[str(new)]
    assert new_record.sha256 == hashlib.sha256(b"malicious-bytes").hexdigest()
    assert new_record.size_bytes == len(b"malicious-bytes")
    assert (dropped_dir / new_record.sha256).exists()


def test_collect_skips_oversized_but_records_metadata(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    dropped_dir = tmp_path / "dropped"
    root.mkdir()
    baseline = snapshot_roots([root])

    big = root / "huge.bin"
    big.write_bytes(b"\x00" * (1024 + 10))

    records = collect_dropped_files(
        roots=[root],
        baseline=baseline,
        destination_dir=dropped_dir,
        max_file_bytes=1024,  # anything larger is skipped
    )
    assert len(records) == 1
    rec = records[0]
    assert rec.sha256 == ""
    assert rec.relative_path == ""
    assert rec.size_bytes == 1024 + 10
    # The file was *not* copied because it was oversized.
    assert not (dropped_dir / "huge.bin").exists()


def test_collect_dedupes_identical_content(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    dropped_dir = tmp_path / "dropped"
    root.mkdir()
    baseline = snapshot_roots([root])

    (root / "one.bin").write_bytes(b"same")
    (root / "two.bin").write_bytes(b"same")

    records = collect_dropped_files(
        roots=[root],
        baseline=baseline,
        destination_dir=dropped_dir,
        max_file_bytes=1024,
    )
    assert len(records) == 2
    sha = hashlib.sha256(b"same").hexdigest()
    assert all(r.sha256 == sha for r in records)
    # Only one physical copy in the dropped directory.
    assert len(list(dropped_dir.iterdir())) == 1
