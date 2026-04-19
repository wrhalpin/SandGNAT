# How to add a new artifact parser

Parsers turn guest-collected artifacts (a ProcMon CSV, a PCAP, a
RegShot diff, a static-analysis envelope) into plain Python
dataclasses that `analyzer.py` can then lift into STIX objects and
normalised DB rows.

The parser contract is: **pure function, file in → dataclasses out.**
No DB, no network, no mutations.

## When you'd want to add one

- New capture tool on the guest side (e.g. Sysmon EVTX, BitsAdmin
  traces).
- New static-analysis tool output (e.g. a custom entropy-heatmap
  generator).
- New artifact class entirely (e.g. Volatility memory-dump analysis).

## Steps

### 1. Decide where the parser sits

| Kind of artifact                                  | Location                                  |
|---------------------------------------------------|-------------------------------------------|
| Dynamic capture from Windows detonation guest     | `orchestrator/parsers/<name>.py`          |
| Static-analysis output from Linux guest           | Extend `orchestrator/static_analysis.py`  |
| Something fundamentally new (memory, graphs, etc.) | New module next to `analyzer.py`         |

Existing `orchestrator/parsers/`:

- `procmon.py` — Process Monitor CSV
- `regshot.py` — RegShot diff
- `pcap.py` — Wireshark PCAP (scapy-based)

### 2. Define the return dataclass

Keep it flat. No DB-specific types, no STIX — those live downstream.

```python
# orchestrator/parsers/sysmon.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class SysmonEvent:
    event_id: int
    time: str
    process_name: str
    pid: int
    command_line: str
    # ... whatever fields your analyzer needs

def parse_sysmon_evtx(path: Path) -> list[SysmonEvent]:
    """Parse an EVTX file into a list of SysmonEvent.

    Pure function; never raises on empty / well-formed-but-empty input.
    Raises ValueError on structural corruption.
    """
    ...
```

### 3. Tell the guest to produce it

Update `orchestrator/schema.py`:

- If the tool is Windows-side: add a flag to `CaptureConfig`
  (e.g. `sysmon: bool = True`) and a filename constant
  (`SYSMON_EVTX = "sysmon.evtx"`).
- Add a capture wrapper under `guest_agent/capture/`.
- Update `guest_agent/runner.py` to call the wrapper when the flag is
  set and write to the named file.
- Bump `SCHEMA_VERSION` if the flag addition breaks v1/v2 guests.

If Linux-side: same dance on `StaticAnalysisOptions` and
`linux_guest_agent/tools/`.

### 4. Wire the parser into analyzer

`orchestrator/analyzer.py` (for detonation) or
`orchestrator/static_analysis.py` (for static):

```python
from .parsers.sysmon import parse_sysmon_evtx

# Inside analyze():
if artifacts.sysmon_evtx is not None:
    events = parse_sysmon_evtx(artifacts.sysmon_evtx)
    for ev in events:
        # build STIX process / file / etc. from the event
        bundle.stix_objects.append(
            build_process(analysis_id, pid=ev.pid, name=ev.process_name, ...)
        )
```

Also extend `guest_driver.ArtifactLocations` with the new field and
`wait_for_result()` to resolve the file path.

### 5. Add a unit test with a fixture

Parser tests live in `tests/test_parsers_<name>.py`. The pattern:

```python
# tests/test_parsers_sysmon.py
import pytest
from pathlib import Path
from orchestrator.parsers.sysmon import parse_sysmon_evtx, SysmonEvent

FIXTURE_EVTX = b"..."  # small, realistic

def test_parse_sysmon_extracts_process_events(tmp_path: Path) -> None:
    f = tmp_path / "sysmon.evtx"
    f.write_bytes(FIXTURE_EVTX)
    events = parse_sysmon_evtx(f)
    assert any(ev.event_id == 1 for ev in events)  # process-create
    ...
```

The test must run offline — no Postgres, no Proxmox, no Windows. If
you can't write a pure unit test, your parser isn't pure; fix that
first.

### 6. Update the STIX builder (optional)

If the new artifact introduces a STIX object type we don't currently
emit (`attack-pattern`, `observed-data`, etc.), add a factory to
`orchestrator/stix_builder.py`. Otherwise, reuse existing factories.

### 7. Update docs

- `docs/reference/wire-protocol.md` — add the new file to the
  `completed/` listing and document the mode.
- `docs/reference/stix-output.md` — document any new STIX type or
  extension key.
- `docs/explanation/architecture.md` — if the new parser shifts
  pipeline shape (it usually doesn't).

## The "keep it pure" rule, concretely

A parser is **pure** if:

- Input is `Path` (or `bytes`), output is a dataclass list.
- No calls into `persistence`, `celery`, `proxmoxer`, `flask`.
- No env-var reads (config flows in via kwargs).
- No logging above DEBUG (INFO/WARNING logs get noisy across thousands
  of runs).
- No file writes. Ever.

When the parser breaks this rule, you can't unit-test it against
fixture files, which means you can't catch regressions, which means
the parser rots. This isn't theoretical — purity is what let us catch
the `PureWindowsPath` bug in analyzer tests before it shipped.

## Checklist

- [ ] Dataclass in `orchestrator/parsers/<name>.py` (or extension of
      `static_analysis.py`).
- [ ] Parser function returns plain dataclasses.
- [ ] Capture wrapper on the appropriate guest.
- [ ] Filename constant in `orchestrator/schema.py`.
- [ ] `guest_driver.ArtifactLocations` knows about the new file.
- [ ] `analyzer.py` / `static_analysis.py` wires it in.
- [ ] STIX factories if new types.
- [ ] Unit test with a realistic fixture.
- [ ] Docs updated: wire-protocol, stix-output, architecture.
