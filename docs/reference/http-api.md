# HTTP API reference

Served by `orchestrator/intake_api.py` (write path) and
`orchestrator/export_api.py` (read path), both Flask, both on the same
port, both gated by `X-API-Key: $INTAKE_API_KEY`.

`/healthz` is the only unauthenticated route.

## Summary

| Method | Path                              | Purpose                           |
|--------|-----------------------------------|-----------------------------------|
| GET    | `/healthz`                        | liveness probe                    |
| POST   | `/submit`                         | accept a sample                   |
| GET    | `/jobs/<uuid>`                    | poll one job (legacy name)        |
| GET    | `/analyses`                       | list + filter + paginate          |
| GET    | `/analyses/<uuid>`                | one job's metadata                |
| GET    | `/analyses/<uuid>/bundle`         | STIX 2.1 bundle                   |
| GET    | `/analyses/<uuid>/static`         | static-analysis findings          |
| GET    | `/analyses/<uuid>/similar`        | LSH + lineage neighbours          |
| POST   | `/analyses/<uuid>/investigation`  | retroactively tag with an investigation |

GNAT investigation fields: `POST /submit` accepts optional
`investigation_id`, `investigation_tenant_id`, and
`investigation_link_type` form fields that travel through to the
emitted STIX bundle. `GET /analyses` gains `investigation_id=` and
`has_investigation=true|false` query filters. Full reference:
[investigation-context](investigation-context.md).

## Authentication

All routes except `/healthz` require the header:

    X-API-Key: $INTAKE_API_KEY

Unauthenticated requests return:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": "unauthorized"}
```

Optional additional headers accepted on `POST /submit`:

- `X-Submitter: analyst@example.com` — recorded on the `submitter` column.
- `X-Intake-Source: <string>` — recorded on `intake_source`. Defaults
  to `"http"`.

## GET /healthz

```http
GET /healthz HTTP/1.1
```

```json
{"status": "ok"}
```

Always returns 200. No DB/Redis check — it's purely a "is the Flask
app up?" probe. See how-to/monitoring for deeper health checks.

## POST /submit

Multipart upload of a sample.

**Form fields:**

| Field      | Required | Purpose                                           |
|------------|----------|---------------------------------------------------|
| `file`     | ✅        | Sample bytes                                      |
| `name`     |           | Override filename (defaults to upload filename)    |
| `priority` |           | Integer 0–9, default 5. Lower = higher priority    |
| `force`    |           | `1`/`true`/`yes` to bypass SHA-256 dedupe          |
| `submitter`|           | Same as `X-Submitter` header                       |

**Example:**

```bash
curl -sS \
     -H "X-API-Key: $INTAKE_API_KEY" \
     -F "file=@/path/to/sample.exe" \
     -F "priority=3" \
     http://localhost:8080/submit
```

**Response (202 Accepted for new submissions, 200 for duplicates,
400 for rejections):**

```json
{
  "decision": "queued",
  "analysis_id": "e3f1b4a2-...-...",
  "duplicate_of": null,
  "rejection_reason": null,
  "sha256": "abc...",
  "md5": "xyz...",
  "sha1": "qwe...",
  "size_bytes": 4096,
  "mime_type": "application/x-msdownload",
  "sample_name": "sample.exe",
  "priority": 5,
  "vt": {
    "verdict": "unknown",
    "detection_count": null,
    "total_engines": null,
    "last_seen": null
  },
  "yara_matches": []
}
```

**`decision` values:**

| Value          | Meaning                                                   |
|----------------|-----------------------------------------------------------|
| `queued`       | New row inserted, Celery task dispatched                  |
| `prioritized`  | Same as `queued`, priority bumped by VT/YARA signal       |
| `duplicate`    | Hash already analysed; `duplicate_of` points at prior job |
| `rejected`     | Submission failed validation; see `rejection_reason`      |

Rejections (400) include:

- empty upload
- sample smaller than `INTAKE_MIN_SAMPLE_BYTES`
- sample larger than `INTAKE_MAX_SAMPLE_BYTES`
- invalid `priority` form field

## GET /jobs/<uuid>

Returns the full `AnalysisJob` row for one job id. Kept for backwards
compatibility with early intake consumers; new code should prefer
`/analyses/<uuid>` (same response shape).

Returns 400 on malformed UUID, 404 on unknown id.

## GET /analyses

List analyses with filters + pagination.

**Query parameters:**

| Param      | Type            | Default | Validation                                       |
|------------|-----------------|---------|--------------------------------------------------|
| `sha256`   | 64 hex chars    | none    | Lowercase hex, exactly 64 chars                   |
| `status`   | enum            | none    | `queued`/`running`/`completed`/`failed`/`quarantined` |
| `since`    | ISO-8601 string | none    | Parseable by `datetime.fromisoformat`             |
| `limit`    | integer         | 50      | 1 ≤ limit ≤ 200                                   |
| `offset`   | integer         | 0       | ≥ 0                                               |

**Response:**

```json
{
  "items": [<job_json>, <job_json>, ...],
  "limit": 50,
  "offset": 0,
  "count": 23
}
```

`count` is the length of `items`, not a full-table `COUNT(*)`. Paginate
until you see `count < limit` if you need an exhaustive walk.

## GET /analyses/<uuid>

Same shape as `/jobs/<uuid>`. A typical `AnalysisJob` JSON:

```json
{
  "id": "e3f1b4a2-...",
  "sample_hash_sha256": "abc...",
  "sample_hash_md5": "xyz...",
  "sample_hash_sha1": "qwe...",
  "sample_size_bytes": 4096,
  "sample_name": "evil.exe",
  "sample_mime_type": "application/x-msdownload",
  "status": "completed",
  "submitted_at": "2026-04-17T12:00:00.123456+00:00",
  "started_at": "2026-04-17T12:00:05.000000+00:00",
  "completed_at": "2026-04-17T12:07:30.000000+00:00",
  "duration_seconds": 445,
  "timeout_seconds": 300,
  "priority": 5,
  "submitter": "analyst@example",
  "intake_source": "http",
  "intake_decision": "queued",
  "intake_notes": null,
  "vt_verdict": "malicious",
  "vt_detection_count": 42,
  "vt_total_engines": 70,
  "vt_last_seen": "2026-04-15T10:00:00+00:00",
  "yara_matches": ["EvilCorp_Stealer"],
  "imphash": "abc123...",
  "ssdeep": "96:abc:def",
  "tlsh": "T1ABCDE...",
  "static_completed_at": "2026-04-17T12:02:30+00:00",
  "near_duplicate_of": null,
  "near_duplicate_score": null,
  "quarantine_path": "/srv/sandgnat/quarantine/e3f1b4a2-...",
  "evasion_observed": false,
  "network_isolation": true
}
```

## GET /analyses/<uuid>/bundle

Full STIX 2.1 bundle. Always Content-Type `application/json`.

- **404** — no job with that id.
- **409** — job not yet `completed`. Body includes current status.
- **200** — bundle payload.

Bundle shape:

```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "spec_version": "2.1",
  "objects": [
    {"type": "malware", "id": "malware--...", ...},
    {"type": "file", "id": "file--...", ...},
    {"type": "process", ...},
    {"type": "network-traffic", ...},
    {"type": "indicator", ...}
  ]
}
```

See [stix-output.md](stix-output.md) for per-type field coverage.

## GET /analyses/<uuid>/static

Static-analysis findings. Returns 404 if no `static_analysis` row
exists (common if `STATIC_ANALYSIS_ENABLED=0` or the job didn't finish
the static stage).

```json
{
  "analysis_id": "e3f1b4a2-...",
  "file_format": "pe64",
  "architecture": "x86_64",
  "entry_point": 5120,
  "is_packed_heuristic": true,
  "section_count": 5,
  "overall_entropy": 6.54,
  "imphash": "abc123...",
  "ssdeep": "96:abc:def",
  "tlsh": "T1ABCDE...",
  "static_completed_at": "2026-04-17T12:02:30+00:00",
  "imports": {"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
  "exports": [],
  "sections": [
    {"name": ".text", "vsize": 4096, "rsize": 4096, "entropy": 7.4, "flags": ["EXECUTE", "READ"]}
  ],
  "strings_summary": {
    "ascii_count": 127,
    "utf16_count": 23,
    "urls": ["http://..."],
    "ips": ["10.0.0.1"],
    "registry_keys": ["HKLM\\Software\\..."]
  },
  "capa_capabilities": [
    {"rule": "execute payload", "namespace": "host-interaction", ...}
  ],
  "deep_yara_matches": ["Family_EvilCorp_v3"]
}
```

The full `raw_envelope` (per-tool detail blob) is **not** returned on
this endpoint — it can be hundreds of KB. Fetch the per-tool data via
the specific tool's output if you really need it; in practice the
summary fields above are enough.

## GET /analyses/<uuid>/similar

Similar analyses ranked by estimated Jaccard similarity.

**Query parameters:**

| Param       | Type    | Default  | Validation          |
|-------------|---------|----------|---------------------|
| `threshold` | float   | `0.5`    | 0.0 ≤ t ≤ 1.0       |
| `limit`     | integer | `25`     | 1 ≤ limit ≤ 100     |
| `flavour`   | enum    | `either` | `byte`/`opcode`/`either` |

**Response:**

```json
{
  "items": [
    {
      "analysis_id": "a...",
      "sample_sha256": "abc...",
      "similarity": 0.94,
      "flavour": "byte",
      "relation": "near_duplicate"
    },
    {
      "analysis_id": "b...",
      "sample_sha256": "def...",
      "similarity": 0.71,
      "flavour": "opcode",
      "relation": "similar"
    }
  ]
}
```

`relation` values:

- `near_duplicate` — explicit short-circuit parent from
  `analysis_lineage`.
- `similar` — LSH neighbour from `sample_similarity`.

404 if the base job doesn't exist. 200 with `items: []` if it exists
but has no neighbours above threshold.

## Status codes summary

| Code | Meaning                                                  |
|------|----------------------------------------------------------|
| 200  | OK                                                       |
| 202  | Submission accepted (for POST /submit only)              |
| 400  | Bad request — invalid parameter or malformed body        |
| 401  | Missing or invalid `X-API-Key`                            |
| 404  | Resource not found                                       |
| 409  | Resource exists but not in the state required (bundle)   |

## Clients

- GNAT's `gnat.connectors.sandgnat.SandGNATClient` (not in this repo)
- `how-to/query-export-api.md` has working `curl` + `python` snippets.
