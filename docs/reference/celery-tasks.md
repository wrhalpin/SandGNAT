# Celery tasks reference

Two tasks, two queues. Workers opt into either queue with
`--queues=analysis` (Windows detonation) or `--queues=static` (Linux
static).

## sandgnat.analyze_malware_sample

**Module:** `orchestrator.tasks`
**Queue:** `analysis`
**Max retries:** 2
**Acks late:** yes

### Signature

```python
analyze_malware_sample(
    analysis_id: str,
    sample_hash_sha256: str,
    sample_name: str,
    timeout_seconds: int | None = None,
) -> dict[str, object]
```

### Preconditions

- An `analysis_jobs` row exists with `id = analysis_id`
  (intake is the only row-creator).
- The sample is staged at
  `{ARTIFACT_STAGING_ROOT}/samples/{analysis_id}/{sample_name}` with
  a SHA-256 matching `sample_hash_sha256`.

### What it does

1. Log `detonation_started`, mark status `running`.
2. Verify staged-sample hash matches the arg. Fail fast on mismatch.
3. Acquire a Windows vmid from the VM pool. Retry with `countdown=30`
   if the pool is exhausted.
4. Clone the Windows template, start the VM, wait for `running`.
5. Publish a `mode=detonation` manifest to `pending/`.
6. Poll `completed/{id}/result.json` with a timeout of
   `timeout_seconds + 180`.
7. Run `analyzer.analyze()` over the result workspace.
8. Persist STIX, dropped files, registry modifications, network IOCs.
9. Move dropped files from staging to quarantine.
10. Update `analysis_jobs.status = completed` with `result_summary`.
11. Revert the VM to clean snapshot, release the pool lease (in
    `finally`).

### Return value

```json
{
  "job_id": "e3f1b4a2-...",
  "status": "completed",
  "stix_count": 42
}
```

### Failure modes

- `FileNotFoundError` — staged sample missing.
- `RuntimeError("staged sample hash mismatch")` — hash drift between
  intake and detonation time.
- `GuestDriverError` — guest didn't publish `result.json` within the
  watchdog.
- `PoolExhausted` → retried by Celery, not a permanent failure.

All failures set `status = failed` and write an `analysis_failed`
audit row.

### Dispatched by

- `intake.ingest_submission` via `tasks.enqueue_analysis` when
  `STATIC_ANALYSIS_ENABLED=0`.
- `tasks_static.static_analyze_sample` when the static stage does
  **not** short-circuit (chain).

## sandgnat.static_analyze_sample

**Module:** `orchestrator.tasks_static`
**Queue:** `static`
**Max retries:** 2
**Acks late:** yes

### Signature

```python
static_analyze_sample(
    analysis_id: str,
    sample_hash_sha256: str,
    sample_name: str,
    timeout_seconds: int | None = None,
    priority: int = 5,
) -> dict[str, object]
```

### Preconditions

Same as `analyze_malware_sample`.

### What it does

1. Log `static_analysis_started`, mark status `running`.
2. Acquire a **Linux** vmid from the Linux pool. Retry with
   `countdown=15` on exhaustion.
3. Clone the Linux template, start, wait for `running`.
4. Publish a `mode=static_analysis` manifest.
5. Poll `completed/{id}/result.json`.
6. Parse `static_analysis.json` + `trigrams_*.bin` via
   `static_analysis.parse_static_workspace()`.
7. Persist `static_analysis`, `sample_trigrams`, `sample_minhash_bands`.
8. Stamp `analysis_jobs.imphash / ssdeep / tlsh / static_completed_at`.
9. LSH candidate fetch + exact Jaccard.
10. Short-circuit decision:
    - **Above threshold** → mark `near_duplicate_of`, insert lineage,
      status `completed`, no chain. Return.
    - **Below threshold** → `analyze_malware_sample.apply_async(...)`,
      status stays `running`.
11. Revert Linux VM, release lease (in `finally`).

### Return value

Near-duplicate path:
```json
{
  "job_id": "...",
  "status": "near_duplicate",
  "parent": "<parent_id>",
  "score": 0.94
}
```

Chain path:
```json
{
  "job_id": "...",
  "status": "chained_to_detonation"
}
```

### Dispatched by

- `intake.ingest_submission` via `tasks.enqueue_analysis` when
  `STATIC_ANALYSIS_ENABLED=1`.

## Routing

`orchestrator/celery_app.py`:

```python
task_routes = {
    "sandgnat.analyze_malware_sample": {"queue": "analysis"},
    "sandgnat.static_analyze_sample":  {"queue": "static"},
}
```

## Worker entry points

**Windows detonation worker:**
```bash
celery -A orchestrator.celery_app worker --loglevel=INFO --queues=analysis
# or:
sandgnat-worker
```

The installed `sandgnat-worker` console script defaults to `--queues=analysis`.

**Linux static-stage worker:**
```bash
celery -A orchestrator.celery_app worker --loglevel=INFO --queues=static
```

Typical sizing: one worker process per VM pool slot
(`MAX_CONCURRENT_ANALYSES=4` implies 4 detonation workers + 4 static
workers).

## Scheduling

- `worker_prefetch_multiplier = 1` — one detonation per worker at a
  time. Never batch; a VM isn't shared.
- `worker_max_tasks_per_child = 50` — recycle worker processes every
  50 tasks to mitigate slow memory leaks in upstream libraries
  (pefile, capstone, et al.).
- `task_acks_late = True` + `task_reject_on_worker_lost = True` — a
  worker crash re-queues the task rather than silently dropping it.
  Combined with the VM pool's lease reaper, a crashed worker doesn't
  permanently burn a vmid.

## Priorities

Celery priorities are inverted (0 = highest). Intake's
`ingest_submission` clamps the caller-requested priority to 0–9 and
bumps to ≤2 for known-malicious samples. Workers honor priority
natively via the Redis broker.

| Priority | Meaning                                     |
|----------|---------------------------------------------|
| 0–2      | High — VT/YARA flagged                      |
| 3–5      | Normal (default 5)                          |
| 6–9      | Background / low urgency                    |

## Testing

Neither task is directly exercised by the test suite (they need real
Celery, Postgres, Redis, Proxmox). Branching logic is covered by
`tests/test_static_pipeline.py`:

- `_persist_and_find_similar` — the core short-circuit decision.
- `enqueue_analysis` branching on `settings.static.enabled`.

Full end-to-end is covered by the manual runbook in
[how-to/run-under-gunicorn.md](../how-to/run-under-gunicorn.md).
