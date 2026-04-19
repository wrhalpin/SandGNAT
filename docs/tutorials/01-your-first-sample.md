# Tutorial 01 — Your first sample

By the end: you've submitted a sample, watched it go through the
pipeline, and pulled back a STIX 2.1 bundle. This is a tour of the
happy path.

This tutorial assumes a **real deployment** — orchestrator running,
Postgres/Redis live, at least one analysis VM available. If you're
doing local dev, start with [tutorial 02](02-local-dev-stack.md)
first, then come back here when you have a detonation VM attached.

Estimated time: 20 minutes (most of it waiting on the analysis VM).

## What you'll need

- `curl` and `jq`
- `INTAKE_API_KEY` and the base URL of the intake service
- One test sample. For this tutorial, the **EICAR test string** is
  perfect — it's the universally-recognised fake-malware string that
  every AV knows:

  ```bash
  echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
  ```

  EICAR is not a real threat. It's safe to work with. Its SHA-256 is
  `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`.

## Step 1 — Submit

```bash
curl -sS \
     -H "X-API-Key: $INTAKE_API_KEY" \
     -F "file=@/tmp/eicar.com" \
     -F "priority=5" \
     "$SANDGNAT_URL/submit" \
     | jq '.'
```

You should see something like:

```json
{
  "decision": "queued",
  "analysis_id": "a1b2c3d4-...",
  "duplicate_of": null,
  "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "md5": "44d88612fea8a8f36de82e1278abb02f",
  "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
  "size_bytes": 68,
  "sample_name": "eicar.com",
  "priority": 5,
  "vt": { "verdict": "unknown" },
  "yara_matches": []
}
```

Save the `analysis_id` — everything else below uses it.

**What just happened:**

1. Intake validated the upload (size, hash, no duplicate in the
   corpus yet).
2. Intake wrote the bytes to
   `{ARTIFACT_STAGING_ROOT}/samples/{analysis_id}/eicar.com`.
3. Intake inserted a `queued` row in `analysis_jobs`.
4. Intake dispatched a Celery task — either `static_analyze_sample`
   (if `STATIC_ANALYSIS_ENABLED=1`) or `analyze_malware_sample`.
5. The 202 response came back with no wait for the analysis itself.

Note `decision: "queued"` and `priority: 5`. If you submitted a
sample that VT knew was malicious, decision would be `"prioritized"`
and priority would be ≤2.

## Step 2 — Poll status

```bash
ANALYSIS_ID=<paste-here>

while true; do
    STATUS=$(curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
        "$SANDGNAT_URL/analyses/$ANALYSIS_ID" \
        | jq -r '.status')
    echo "[$(date +%H:%M:%S)] status=$STATUS"
    [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
    sleep 10
done
```

Expect the status to transition:

- `queued` — sitting in Redis waiting for a worker.
- `running` — a worker picked it up, acquired a VM pool slot, manifest
  published to the guest.
- `completed` — artifacts came back, STIX persisted. (or `failed`.)

The wait time depends on:

- How many analysis VMs are configured.
- `ANALYSIS_DEFAULT_TIMEOUT` (default 5 minutes).
- Whether the static stage ran first (adds ~30–60 s).

For EICAR specifically, expect 3–8 minutes end-to-end.

## Step 3 — Fetch the STIX bundle

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "$SANDGNAT_URL/analyses/$ANALYSIS_ID/bundle" \
     | jq '.'
```

You'll see a STIX 2.1 bundle with:

- One `malware` SDO wrapping the analysis.
- One `file` SCO for the sample itself.
- At least one `process` SCO.
- Possibly `indicator`s (EICAR doesn't modify registry, so probably none
  for this sample; a real sample would have persistence indicators).

A tiny slice:

```json
{
  "type": "bundle",
  "id": "bundle--...",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "malware",
      "id": "malware--...",
      "name": "eicar.com",
      "labels": ["malware"],
      "is_family": false,
      "object_refs": ["file--...", "process--..."],
      "x_analysis_metadata": {
        "analysis_id": "...",
        "tools_used": ["procmon", "regshot", "tshark"],
        "network_isolation": true,
        "sample_hash_sha256": "275a021bb...",
        "analyst_confidence_level": 75
      }
    },
    {
      "type": "file",
      "id": "file--...",
      "hashes": {
        "SHA-256": "275a021bb...",
        "MD5": "44d88612fe..."
      },
      "name": "eicar.com",
      "size": 68,
      ...
    }
  ]
}
```

## Step 4 — Explore the other endpoints

**Job metadata in detail:**

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "$SANDGNAT_URL/analyses/$ANALYSIS_ID" | jq '{
        status, priority, submitter,
        vt: {verdict: .vt_verdict, count: .vt_detection_count},
        fingerprint: {imphash, ssdeep, tlsh},
        near_duplicate_of, near_duplicate_score,
        submitted_at, completed_at, duration_seconds
     }'
```

**Static-analysis findings** (if static stage ran):

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "$SANDGNAT_URL/analyses/$ANALYSIS_ID/static" | jq '{
        file_format, architecture, is_packed_heuristic,
        section_count, overall_entropy,
        imports, capa_capabilities, deep_yara_matches
     }'
```

If the static stage didn't run, this returns 404. That's normal for
first deployments — enable with `STATIC_ANALYSIS_ENABLED=1` and
rebuild the Linux guest.

**Similar samples:**

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "$SANDGNAT_URL/analyses/$ANALYSIS_ID/similar?threshold=0.5" | jq '.items'
```

For your first sample, this is empty (no corpus to compare to). After
you've submitted 2–3 variants of the same family, you'll see
neighbours here.

## Step 5 — Submit again (see dedupe)

```bash
curl -sS \
     -H "X-API-Key: $INTAKE_API_KEY" \
     -F "file=@/tmp/eicar.com" \
     "$SANDGNAT_URL/submit" \
     | jq '.'
```

Response:

```json
{
  "decision": "duplicate",
  "analysis_id": "<same-id-as-before>",
  "duplicate_of": "<same-id>",
  ...
}
```

No new detonation. The SHA-256 matched an existing completed job, so
intake returned the prior id. Skip this with `-F force=true` if you
want to force a reanalysis — see [tutorial 03](03-force-reanalysis.md).

## What you've accomplished

- Submitted a sample to SandGNAT's intake API.
- Watched it traverse the pipeline.
- Pulled back a STIX 2.1 bundle.
- Seen the dedupe behaviour.
- Used the `/analyses/<id>` / `/static` / `/similar` endpoints.

## Next

- [03 — Force a reanalysis and see a near-duplicate](03-force-reanalysis.md)
- [how-to/query-export-api.md](../how-to/query-export-api.md) — scripting
  the export API
- [explanation/architecture.md](../explanation/architecture.md) — the
  full pipeline diagrams

## Troubleshooting

- **401 Unauthorized on submit** — `X-API-Key` header missing or
  doesn't match `INTAKE_API_KEY` on the server.
- **413 Request Entity Too Large** — your sample is larger than
  `INTAKE_MAX_SAMPLE_BYTES` (default 128 MiB).
- **Status stays `queued` forever** — no Celery worker is consuming
  the `analysis` queue. Check worker logs.
- **Status stays `running` forever** — the guest agent isn't picking
  up the manifest, or the watchdog hasn't fired yet. Check the staging
  share (`ls {ARTIFACT_STAGING_ROOT}/pending/`, `ls in-flight/`,
  `ls completed/`). See [how-to/build-windows-guest.md](../how-to/build-windows-guest.md#troubleshooting).
- **409 on bundle fetch** — job isn't completed yet. Poll status
  first; only fetch bundle once status is `completed`.
