# How to query the export API from a script

The export API is SandGNAT's read surface for external consumers. It's
designed for the `gnat.connectors.sandgnat` connector but anything
that can make an authenticated HTTP GET can use it — analyst
notebooks, monitoring tooling, ad-hoc scripts.

All examples use `INTAKE_API_KEY=your-key` and a service at
`http://localhost:8080`.

## Curl: one-liners

**Poll for newly completed analyses:**

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "http://localhost:8080/analyses?status=completed&since=2026-04-17T00:00:00Z&limit=50" \
     | jq '.items[] | {id, sha: .sample_hash_sha256, score: .near_duplicate_score}'
```

**Fetch one STIX bundle:**

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "http://localhost:8080/analyses/<uuid>/bundle" \
     -o bundle.json
```

**Get static-analysis findings with CAPA capabilities:**

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "http://localhost:8080/analyses/<uuid>/static" \
     | jq '.capa_capabilities'
```

**Find similar samples above 0.85 Jaccard:**

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "http://localhost:8080/analyses/<uuid>/similar?threshold=0.85&limit=10" \
     | jq '.items'
```

## Python: minimal client

Keep a single `requests.Session` for connection pooling and set the
auth header once:

```python
import os
import requests

BASE = os.environ.get("SANDGNAT_BASE_URL", "http://localhost:8080")
KEY = os.environ["SANDGNAT_API_KEY"]

s = requests.Session()
s.headers["X-API-Key"] = KEY


def list_analyses(**filters):
    r = s.get(f"{BASE}/analyses", params=filters, timeout=30)
    r.raise_for_status()
    return r.json()


def get_bundle(analysis_id: str) -> dict:
    r = s.get(f"{BASE}/analyses/{analysis_id}/bundle", timeout=30)
    if r.status_code == 409:
        raise RuntimeError(f"analysis {analysis_id} not yet completed: {r.json()}")
    r.raise_for_status()
    return r.json()


def get_static(analysis_id: str) -> dict | None:
    r = s.get(f"{BASE}/analyses/{analysis_id}/static", timeout=30)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def get_similar(analysis_id: str, *, threshold: float = 0.5) -> list[dict]:
    r = s.get(
        f"{BASE}/analyses/{analysis_id}/similar",
        params={"threshold": threshold},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["items"]
```

## Python: watermark-paginated sync

The pattern the GNAT connector uses — fetch everything completed
since the last watermark, in order:

```python
from datetime import datetime, timezone, timedelta


def sync_since(last_seen: datetime) -> list[dict]:
    """Yield every completed analysis with submitted_at >= last_seen,
    page-by-page. Returns list of (analysis, bundle) tuples."""
    results = []
    offset = 0
    limit = 100
    while True:
        page = list_analyses(
            status="completed",
            since=last_seen.isoformat(),
            limit=limit,
            offset=offset,
        )
        items = page["items"]
        if not items:
            break
        for a in items:
            try:
                bundle = get_bundle(a["id"])
            except RuntimeError:
                continue  # stale race, skip
            results.append((a, bundle))
        if page["count"] < limit:
            break
        offset += limit
    return results


# Run every 60s with a 5-minute overlap to paper over clock skew + race.
last = datetime.now(timezone.utc) - timedelta(minutes=5)
while True:
    for analysis, bundle in sync_since(last):
        print(f"{analysis['id']}: {len(bundle['objects'])} STIX objects")
    last = datetime.now(timezone.utc) - timedelta(minutes=5)
    time.sleep(60)
```

## Near-duplicate resolution

A job with `near_duplicate_of` set doesn't have its own STIX bundle —
it's linked to a parent. Handle this at the client:

```python
def resolve_bundle(analysis_id: str) -> dict:
    """Return the STIX bundle for this analysis, following the lineage
    to a parent if this is a short-circuited near-duplicate."""
    analysis = s.get(f"{BASE}/analyses/{analysis_id}", timeout=30).json()
    target = analysis.get("near_duplicate_of") or analysis_id
    return get_bundle(target)
```

Alternatively, trust that the bundle endpoint returns *something*
sensible (empty objects list) for near-duplicates and treat missing
STIX as "refer to the parent via the metadata field."

## Error handling

| Status | When                                          | What to do                            |
|--------|-----------------------------------------------|---------------------------------------|
| 200    | OK                                            | Parse response                        |
| 202    | Submission accepted (POST /submit only)       | Begin polling                         |
| 400    | Bad parameter (invalid sha256, threshold, UUID) | Fix the request; don't retry       |
| 401    | Missing or wrong `X-API-Key`                  | Fix credentials; don't retry          |
| 404    | Resource missing                              | Exists-check before treating as error |
| 409    | Bundle requested before completion            | Retry after a short backoff           |
| 5xx    | Server error                                  | Retry with exponential backoff        |

## Rate limits

The server doesn't impose any right now. Be polite — requests-per-second
from a single consumer shouldn't exceed a few hundred for the
`/analyses` list endpoint. Bundle fetches can be tens of KB each;
don't hammer them in a tight loop.

## Verifying signatures (future)

The current API does not sign bundles. If GNAT-side verification
becomes a requirement, the expected path is to add a detached
`X-SandGNAT-Signature: sha256=<hmac>` header (HMAC over the bundle
bytes using `INTAKE_API_KEY` or a separate signing key). Not
implemented yet — raise an issue if you need it.

## Local testing without Postgres

The intake/export app can run against an in-memory store via
`create_app(store=<fake>)` — exactly how the test suite exercises
it. See `tests/test_export_api.py` for a working fake. Not useful
for serving real clients, but useful for developing your own GNAT
connector offline.
