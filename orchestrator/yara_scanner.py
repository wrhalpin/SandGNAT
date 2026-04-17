"""YARA pre-classification for intake.

Scans submitted samples against a directory of YARA rule files before we
burn a VM detonation on them. Matches do not block intake — a high-confidence
match just bumps the job priority and annotates the row with rule names so
reviewers can triage faster.

`yara-python` is an optional dependency. If it isn't installed, `YaraScanner`
becomes a no-op that logs once and returns an empty match list. That keeps
the host deployable without libyara (e.g. for dev on macOS where it's a pain
to install) while still exercising the full intake pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

try:
    import yara  # type: ignore[import-not-found]

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class YaraMatch:
    rule: str
    tags: tuple[str, ...] = ()
    meta: dict[str, str] | None = None


class YaraScanner:
    """Compiles a directory of `.yar`/`.yara` files once, scans many samples.

    Rule compilation is eager so mistakes surface at orchestrator boot, not
    on the first sample submission.
    """

    def __init__(self, rules_dir: str | Path | None) -> None:
        self._rules_dir = Path(rules_dir) if rules_dir else None
        self._rules = None
        if not _YARA_AVAILABLE:
            if self._rules_dir:
                log.warning(
                    "YARA rules dir %s configured but yara-python is not installed; "
                    "scanner is a no-op",
                    self._rules_dir,
                )
            return
        if self._rules_dir and self._rules_dir.is_dir():
            self._rules = self._compile(self._rules_dir)

    @property
    def enabled(self) -> bool:
        return self._rules is not None

    def scan_bytes(self, data: bytes) -> list[YaraMatch]:
        if self._rules is None:
            return []
        try:
            raw = self._rules.match(data=data)
        except Exception as exc:  # noqa: BLE001 — libyara can throw many things
            log.warning("YARA scan failed: %s", exc)
            return []
        return [_match_to_record(m) for m in raw]

    def scan_path(self, path: str | Path) -> list[YaraMatch]:
        if self._rules is None:
            return []
        try:
            raw = self._rules.match(filepath=str(path))
        except Exception as exc:  # noqa: BLE001
            log.warning("YARA scan of %s failed: %s", path, exc)
            return []
        return [_match_to_record(m) for m in raw]

    def _compile(self, rules_dir: Path):  # type: ignore[no-untyped-def]
        filepaths: dict[str, str] = {}
        for ext in ("*.yar", "*.yara"):
            for rule_file in sorted(rules_dir.rglob(ext)):
                # namespace per file so two rules with the same name don't collide
                filepaths[rule_file.stem] = str(rule_file)
        if not filepaths:
            log.warning("YARA rules dir %s contains no rules", rules_dir)
            return None
        log.info("Compiling %d YARA rule files from %s", len(filepaths), rules_dir)
        return yara.compile(filepaths=filepaths)


def _match_to_record(match) -> YaraMatch:  # type: ignore[no-untyped-def]
    tags = tuple(getattr(match, "tags", ()) or ())
    meta = dict(getattr(match, "meta", {}) or {})
    return YaraMatch(rule=str(match.rule), tags=tags, meta={k: str(v) for k, v in meta.items()})
