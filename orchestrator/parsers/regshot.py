"""RegShot diff parser.

RegShot emits a human-readable diff with section headers like:

    Keys added: 12
    ----------------------------
    HKLM\\Software\\Foo
    ...

    Values added: 5
    ----------------------------
    HKLM\\Software\\Foo\\Bar: "baz"
    ...

    Values modified: 2
    ----------------------------
    HKLM\\...: "old"
    HKLM\\...: "new"

We parse the canonical English-output format. Localised RegShot builds are not
supported; point the capture script at English output.

Known persistence-related key roots are flagged with `persistence_indicator=True`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

# Keys commonly abused for persistence. This list mirrors the MITRE ATT&CK
# T1547/T1060 guidance; extend as we see new families.
PERSISTENCE_KEY_PATTERNS = (
    re.compile(r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", re.IGNORECASE),
    re.compile(r"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", re.IGNORECASE),
    re.compile(r"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", re.IGNORECASE),
    re.compile(r"\\SYSTEM\\CurrentControlSet\\Services\\", re.IGNORECASE),
    re.compile(r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", re.IGNORECASE),
    re.compile(r"\\Software\\Microsoft\\Active Setup\\Installed Components", re.IGNORECASE),
    re.compile(r"\\Software\\Classes\\.*\\shell\\open\\command", re.IGNORECASE),
)

SECTION_HEADER = re.compile(
    r"^(?P<target>Keys|Values)\s+(?P<action>added|modified|deleted):\s*\d+",
    re.IGNORECASE,
)

HIVE_PREFIXES = ("HKLM", "HKCU", "HKU", "HKCR", "HKCC")


@dataclass(frozen=True, slots=True)
class RegistryDelta:
    action: str  # 'added' | 'modified' | 'deleted'
    target: str  # 'key' | 'value'
    hive: str
    key_path: str
    value_name: str | None
    value_data: str | None
    persistence_indicator: bool


def _is_persistence(key_path: str) -> bool:
    return any(pat.search(key_path) for pat in PERSISTENCE_KEY_PATTERNS)


def _split_hive(raw: str) -> tuple[str, str]:
    for prefix in HIVE_PREFIXES:
        if raw.upper().startswith(prefix + "\\"):
            return prefix, raw[len(prefix) + 1 :]
        if raw.upper() == prefix:
            return prefix, ""
    # Unknown hive — return whole thing as key_path.
    return "", raw


def _parse_value_line(line: str) -> tuple[str, str | None, str | None]:
    """Split `HKLM\\Path\\Key: "value"` into (full_path, value_name, value_data).

    RegShot's value format is `<full_path>: <data>`. The value _name_ is the
    last backslash-separated segment of the path; the data is everything after
    the colon. We preserve quoting as-is.
    """
    if ":" not in line:
        return line, None, None
    path_part, _, data_part = line.partition(":")
    path_part = path_part.strip()
    data_part = data_part.strip()
    key_path, _, value_name = path_part.rpartition("\\")
    if not key_path:
        return path_part, None, data_part or None
    return key_path, value_name or None, data_part or None


def parse_regshot_diff(source: Path | Iterable[str]) -> list[RegistryDelta]:
    if isinstance(source, Path):
        with source.open("r", encoding="utf-8", errors="replace") as fh:
            return list(_iter_deltas(fh))
    return list(_iter_deltas(iter(source)))


def _iter_deltas(lines: Iterable[str]) -> Iterator[RegistryDelta]:
    current_target: str | None = None  # 'key' | 'value'
    current_action: str | None = None  # 'added' | 'modified' | 'deleted'

    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue

        header = SECTION_HEADER.match(line)
        if header:
            current_target = header.group("target").lower().rstrip("s")  # 'key' or 'value'
            current_action = header.group("action").lower()
            continue

        if current_target is None or current_action is None:
            continue
        if line.startswith("-"):  # section underlines
            continue

        if current_target == "key":
            hive, key_path = _split_hive(line.strip())
            yield RegistryDelta(
                action=current_action,
                target="key",
                hive=hive,
                key_path=key_path,
                value_name=None,
                value_data=None,
                persistence_indicator=_is_persistence(line),
            )
        else:
            full_path, value_name, value_data = _parse_value_line(line.strip())
            hive, key_path = _split_hive(full_path)
            yield RegistryDelta(
                action=current_action,
                target="value",
                hive=hive,
                key_path=key_path,
                value_name=value_name,
                value_data=value_data,
                persistence_indicator=_is_persistence(full_path),
            )
