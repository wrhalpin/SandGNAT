# Wire protocol reference

The host orchestrator and the two guest agents (Windows detonation,
Linux static-analysis) communicate through a shared filesystem — the
**staging share** — plus a strict JSON schema.

Canonical source: `orchestrator/schema.py` (stdlib-only by contract;
both host and guest import it directly).

Schema version: **2**. Bumping `SCHEMA_VERSION` requires re-freezing
both guest binaries.

## Directory layout

On the staging share (typically an SMB mount, seen as
`/srv/sandgnat/staging` on the host, `\\host\sandgnat\` on Windows):

```
staging/
├── samples/
│   └── {analysis_id}/
│       └── {sample_name}           ← intake writes bytes here
├── pending/
│   └── {analysis_id}.json          ← host publishes manifests here
├── in-flight/
│   └── {analysis_id}/
│       └── job.json                ← guest claims by atomic rename
└── completed/
    └── {analysis_id}/
        ├── job.json                ← carried over from in-flight
        ├── result.json             ← sentinel: written last
        ├── procmon.csv             ← detonation only
        ├── capture.pcap            ← detonation only
        ├── regshot_diff.txt        ← detonation only
        ├── dropped_files.json      ← detonation only
        ├── dropped/
        │   └── {sha256}            ← detonation only
        ├── sleep_patches.jsonl     ← detonation only (optional; Phase E)
        ├── static_analysis.json    ← static only
        ├── trigrams_byte.bin       ← static only
        └── trigrams_opcode.bin     ← static only (optional)
```

## Pickup / claim protocol

1. Host writes `pending/{analysis_id}.json` atomically (write to
   `.json.tmp`, rename).
2. Guest polls `pending/` for `*.json` files, attempts to
   `os.rename()` each into `in-flight/{analysis_id}/job.json`. The
   rename is atomic on both NTFS and POSIX; whichever guest wins owns
   the job.
3. Guest runs the job. Intermediate artifacts land in
   `in-flight/{analysis_id}/`.
4. When done, guest writes all artifacts to the in-flight directory,
   then writes `result.json` as the **final** step, then atomically
   renames the whole directory to `completed/{analysis_id}/`.
5. Host polls `completed/{analysis_id}/result.json`. Once it exists,
   all other artifact files are guaranteed to be complete.

The "result.json written last" rule is critical. Don't read other
artifacts until `result.json` exists.

## Mode discriminator

`JobManifest.mode` is one of:

- `detonation` — Windows guest. Runs ProcMon/tshark/RegShot/file-inventory.
- `static_analysis` — Linux guest. Runs PE/ELF parsing, fuzzy hashes,
  YARA, CAPA, string/entropy extraction, trigram MinHashing.

**Each guest refuses manifests for the other mode** at claim time and
writes a failed `ResultEnvelope` so the host gets fast feedback on
misrouted jobs. See `guest_agent/watcher.py` and
`linux_guest_agent/watcher.py`.

## JobManifest

Host → guest. Written to `pending/{analysis_id}.json`.

```python
@dataclass(slots=True)
class JobManifest:
    schema_version: int                         # must equal SCHEMA_VERSION (2)
    job_id: str                                  # UUID as string
    sample_sha256: str                           # hex
    sample_guest_path: str                       # absolute path as the guest sees it
    sample_name: str                             # filename
    arguments: list[str]                         # command-line args for detonation
    timeout_seconds: int
    mode: str                                    # "detonation" | "static_analysis"
    capture: CaptureConfig                       # detonation tool toggles
    static: StaticAnalysisOptions                # static-stage tool toggles
```

`CaptureConfig`:

```python
@dataclass(slots=True)
class CaptureConfig:
    procmon: bool = True
    tshark: bool = True
    regshot: bool = True
    dropped_file_roots: list[str] = [
        r"C:\Users\Analyst\AppData\Local\Temp",
        r"C:\Users\Analyst\AppData\Roaming",
        r"C:\ProgramData",
        r"C:\Windows\Temp",
    ]
    max_dropped_file_bytes: int = 32 * 1024 * 1024
```

`StaticAnalysisOptions`:

```python
@dataclass(slots=True)
class StaticAnalysisOptions:
    pe_elf: bool = True
    fuzzy_hashes: bool = True
    strings_entropy: bool = True
    yara_deep: bool = True
    capa: bool = True
    trigrams_byte: bool = True
    trigrams_opcode: bool = True
    per_tool_timeout_seconds: int = 120
    max_strings_bytes: int = 1024 * 1024
```

## ResultEnvelope

Guest → host. Written to `completed/{analysis_id}/result.json`
**last**.

```python
@dataclass(slots=True)
class ResultEnvelope:
    schema_version: int                         # must equal SCHEMA_VERSION
    job_id: str
    status: str                                  # "completed" | "failed" | "timeout"
    started_at: str                              # ISO-8601 Z
    completed_at: str                            # ISO-8601 Z
    execution_duration_seconds: float
    sample_pid: int | None                       # detonation
    sample_exit_code: int | None                 # detonation
    timed_out: bool                              # detonation
    mode: str                                    # mirrors the manifest's mode
    captures: list[CaptureOutcome]               # detonation tool outcomes
    dropped_files: list[DroppedFileRecord]       # detonation
    errors: list[str]
    flags: dict[str, Any]                        # free-form guest-emitted metadata
    static_summary: dict[str, Any] | None        # static only: digest of findings
```

`CaptureOutcome`:

```python
@dataclass(slots=True)
class CaptureOutcome:
    tool: str                                    # "procmon", "tshark", "regshot", ...
    started: bool
    stopped_cleanly: bool
    output_filename: str | None
    error: str | None
```

`DroppedFileRecord`:

```python
@dataclass(slots=True)
class DroppedFileRecord:
    sha256: str
    md5: str
    size_bytes: int
    original_path: str                           # Windows path as seen by the guest
    relative_path: str                           # e.g. "dropped/<sha256>"
    created_by_pid: int | None
    created_by_name: str | None
```

## Static-mode envelope (`static_analysis.json`)

Separate from `result.json`. Schema-less in the strict sense — it's a
dict with known top-level keys that `orchestrator.static_analysis`
parses:

```json
{
  "sample_sha256": "...",
  "job_id": "...",
  "pe_elf": {
    "available": true, "skipped": false,
    "file_format": "pe64", "architecture": "x86_64",
    "entry_point": 5120, "imphash": "...", "is_packed_heuristic": false,
    "sections": [...], "imports": {...}, "exports": [...]
  },
  "fuzzy": {
    "available": true,
    "ssdeep": "96:abc:def", "tlsh": "T1ABCDE..."
  },
  "strings_summary": {
    "ascii_count": 127, "utf16_count": 23,
    "urls": [...], "ips": [...], "registry_keys": [...],
    "overall_entropy": 5.8
  },
  "yara_matches": ["RuleA", "RuleB"],
  "yara_detail": { "matches": [{"rule": ..., "tags": [], "meta": {}}] },
  "capa_capabilities": [
    {"rule": "execute payload", "namespace": "...", "attack": [...]}
  ],
  "capa_detail": { ... },
  "trigrams": { "byte_count": 5000, "opcode_count": 1500 }
}
```

Any top-level key may be missing if the corresponding tool was
skipped/unavailable — the parser tolerates absence rather than
requiring a sentinel.

## Sleep-patch log (`sleep_patches.jsonl`)

Phase E of the anti-analysis plan. Optional; absent when the sample
made no `Sleep`/`SleepEx`/`NtDelayExecution`/`NtWaitForSingleObject`
call with a timeout > 30 s, or when `sleep_patcher.dll` failed to
inject. One JSON object per line:

```json
{"t":"2026-04-22T15:30:17.123Z","tid":4242,"fn":"Sleep",
 "requested_ms":600000,"patched_ms":2000}
```

Fields:

- `t` — ISO-8601 UTC timestamp with millisecond precision.
- `tid` — Win32 thread id that made the call.
- `fn` — one of `Sleep`, `SleepEx`, `NtDelayExecution`,
  `NtWaitForSingleObject`.
- `requested_ms` — the original timeout the sample asked for.
- `patched_ms` — what we actually passed through (currently hard-coded
  to 2000).

Consumed host-side by `guest_agent.stealth.log_parser.parse_log`; each
event becomes one `sleep_stall` indicator in the evasion detector
(Phase G). Tolerant of malformed lines (torn writes survive a
mid-detonation crash).

## Trigram blobs

- `trigrams_byte.bin` — 128 × 32-bit little-endian uints = 512 bytes.
- `trigrams_opcode.bin` — same format, optional.

Serialisation/deserialisation: `orchestrator.trigrams.MinHashSignature.to_bytes`
and `.from_bytes`. Anything that doesn't round-trip is a bug; see
`test_trigrams.test_minhash_blob_roundtrip`.

## Schema versioning

`SCHEMA_VERSION = 2` at time of writing.

- `from_json` enforces exact-match. Old guests seeing a v2 manifest
  raise; new guests seeing a v1 envelope raise.
- Bumping version requires re-freezing both guests (PyInstaller for
  Windows; systemd-deployed Linux package).
- Fields may be added with a default **without** bumping the version
  as long as existing clients can parse them. Adding `mode` in v2
  required a bump because older guests would choke on the unknown
  top-level key in their dataclass constructor.

## Atomic write idiom

Both host and guest follow:

```python
tmp = target.with_suffix(target.suffix + ".tmp")
tmp.write_text(payload, encoding="utf-8")
os.replace(tmp, target)   # atomic on POSIX + NTFS
```

Never write directly to the target path. Never read from a target
without checking that it exists first.
