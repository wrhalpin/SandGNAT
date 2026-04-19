# How to configure the VirusTotal pre-check

SandGNAT's intake pipeline can query VirusTotal by sample hash to
enrich metadata and bump priority on known-malicious samples. Queries
are **hash-only** — we never upload sample bytes.

## Prerequisites

- A VirusTotal v3 API key. Free-tier keys work but are rate-limited
  (4 requests/min, 500/day). A paid key is appropriate for any
  production-scale sandbox.
- Network access from the orchestrator host to
  `https://www.virustotal.com/api/v3`.

## Enable it

Set two env vars on the orchestrator:

```bash
VIRUSTOTAL_API_KEY=your-key-here
# Optional:
VIRUSTOTAL_BASE_URL=https://www.virustotal.com/api/v3
VIRUSTOTAL_TIMEOUT_SECONDS=10
```

Restart the intake service after setting.

## Verify it's working

Submit a sample whose hash VT already knows (e.g. the EICAR string).
The `vt` field in the `/submit` response should be populated:

```json
{
  "decision": "prioritized",
  "priority": 2,
  "vt": {
    "verdict": "malicious",
    "detection_count": 50,
    "total_engines": 70,
    "last_seen": "2026-03-15T10:00:00+00:00"
  }
}
```

Also check `GET /analyses/<id>`:

```json
{
  "vt_verdict": "malicious",
  "vt_detection_count": 50,
  "vt_total_engines": 70,
  "vt_last_seen": "2026-03-15T10:00:00+00:00"
}
```

## Disable it

Unset `VIRUSTOTAL_API_KEY` (or set it to the empty string). Intake
will short-circuit the lookup and always record `vt_verdict="unknown"`.
Nothing else in the pipeline depends on VT output.

## How the verdict maps to priority

`intake._derive_priority` bumps priority to at most 2 when
`vt.is_known_malicious` is True (i.e. `verdict=="malicious"` AND
`detection_count > 0`). The caller-requested priority is preserved if
it was already higher.

| VT verdict     | Behaviour                              |
|----------------|----------------------------------------|
| `malicious`    | Priority clamped to ≤2, decision `prioritized` |
| `suspicious`   | Recorded but no priority bump          |
| `harmless`     | Recorded but no priority bump          |
| `undetected`   | Recorded but no priority bump          |
| `unknown`      | No-op                                  |
| `error`        | Logged, no-op                          |

## Failure handling

VT is treated as advisory. All failure modes map to
`verdict="unknown"` or `verdict="error"` — the sample is still
accepted and enqueued.

- Unreachable / DNS fail → `verdict="error"`
- HTTP 401 → `verdict="error"`, error field `"unauthorized"`
  (check your key)
- HTTP 404 → `verdict="unknown"` (VT hasn't seen this hash)
- HTTP 5xx → `verdict="error"`
- Malformed JSON → `verdict="error"`

Nothing in intake ever blocks on VT being down. That's a deliberate
reliability choice: VT being flaky should not stop sample submission.

## Security

- **Never upload.** The VT client exposes `lookup_hash(sha256)` only.
  There is no code path that POSTs `/api/v3/files` with bytes. This
  is a hard constraint of the architecture: uploading samples to VT
  would leak our corpus to third parties and defeats the purpose of
  running our own sandbox.
- The API key lives in env vars, never logged. If you're paranoid,
  rotate quarterly or use a vault.
- Egress to `www.virustotal.com` on TCP 443 is the only traffic this
  feature introduces. Firewalls should allow it from the orchestrator
  subnet only.

## Rate limiting

Intake doesn't implement client-side rate limiting — a burst of
submissions can blow through a free-tier quota in minutes. Options:

1. Use a paid VT key with a higher quota.
2. Disable VT when bulk-ingesting a backlog (unset the env var
   temporarily, re-enable after).
3. Add a leaky-bucket wrapper around the VT client (not currently
   implemented — raise an issue if you need it).

## Testing

Tests mock the VT client; no live calls are made by the suite. See
`tests/test_vt_client.py` for the mapping rules (verdict inference,
401/404 handling, malformed payload tolerance).
