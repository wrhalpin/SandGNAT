# How to tune the VM pools

SandGNAT uses two DB-backed VM pools: a Windows pool for detonation
(default vmid 9100–9199) and a Linux pool for the static-analysis
pre-stage (9200–9299). This page covers sizing, pool-exhaustion
handling, and stale-lease reclamation.

## What a "pool slot" is

One slot = one vmid in the configured range. Each slot maps to one
concurrent in-flight analysis for that pool. The pool manager
(`orchestrator/vm_pool.py`) holds a DB row in `vm_pool_leases` for
the lifetime of the job; the Celery task releases it in a
`finally` block.

A slot is **not** a live VM. The VM exists only while the task is
running, cloned from the template and destroyed (via snapshot revert)
on release.

## Sizing

Default: 100 slots per pool. That's way more than any single-node
deployment actually uses. The realistic upper bound is driven by:

- **RAM reservation on the Proxmox host.** Windows VMs reserve 4–8 GiB
  each. Linux static VMs reserve 2–4 GiB each. Concurrency × per-VM
  RAM can't exceed the host's RAM minus orchestrator + Postgres +
  Redis + OPNsense.
- **Disk I/O.** Linked clones are cheap but every concurrent VM is
  doing 60–80 GiB of disk-delta writes. SSD is strongly recommended.
- **Celery worker count.** A pool slot without a worker to drive it
  is waste. Match them:

    # 4 concurrent detonations:
    celery -A orchestrator.celery_app worker --concurrency=4 --queues=analysis
    # 4 concurrent static runs:
    celery -A orchestrator.celery_app worker --concurrency=4 --queues=static

## Set the range

Env vars (orchestrator-side):

```bash
VM_POOL_VMID_MIN=9100
VM_POOL_VMID_MAX=9107         # 8 Windows slots
VM_POOL_STALE_LEASE_SECONDS=1800

LINUX_VM_POOL_VMID_MIN=9200
LINUX_VM_POOL_VMID_MAX=9207   # 8 Linux slots
LINUX_VM_POOL_STALE_LEASE_SECONDS=600
```

Restart Celery workers after changing the range. The next
`pool.acquire()` will pick from the new range.

**Don't overlap the ranges.** Nothing in the code enforces this — two
pools pointed at overlapping vmids will fight over `vm_pool_leases`
rows. Keep them disjoint.

## How acquisition works

1. `pool.acquire(analysis_id)` calls `reap_stale()` first to sweep
   abandoned leases.
2. Then iterates `vmid_min..vmid_max`, attempting an atomic UPSERT
   for each:

       INSERT INTO vm_pool_leases (vmid, ..., status='leased')
       ON CONFLICT (vmid) DO UPDATE
         SET ... WHERE status IN ('released','orphaned')
                  OR heartbeat_at < now() - INTERVAL '... seconds'
       RETURNING vmid

3. Exactly one INSERT per vmid returns a row; the rest return empty.
   Race-free across workers without advisory locks.
4. The first successful UPSERT wins; we return that vmid.
5. If every slot is held by a live lease, raise `PoolExhausted`.

## Handling exhaustion

Both tasks catch `PoolExhausted` and re-queue with `self.retry(...)`:

- `analyze_malware_sample`: `countdown=30`
- `static_analyze_sample`: `countdown=15`

A burst that temporarily exhausts the pool just adds retry latency,
not failures.

Signals you're under-sized:

```sql
-- Current pool saturation:
SELECT guest_type,
       count(*) FILTER (WHERE status='leased') AS active,
       count(*) AS total
FROM vm_pool_leases
GROUP BY guest_type;

-- Jobs currently queued but not yet leased:
SELECT status, count(*)
FROM analysis_jobs
WHERE status IN ('queued', 'running')
GROUP BY status;
```

If `active / total` is routinely >80% **and** queued jobs pile up,
add slots (and matching workers).

## Stale lease reclamation

A crashed Celery worker leaves a lease in place. The pool manager's
sweeper treats any `status='leased'` row with
`heartbeat_at < now() - STALE_LEASE_SECONDS` as orphaned and frees
its slot.

Tune `VM_POOL_STALE_LEASE_SECONDS`:

- Too low (e.g. 60) — a slow detonation exceeds the window; the
  sweeper reclaims a slot that's still running, and a second job
  clones on top. Bad.
- Too high (e.g. 86400) — a crashed worker's lease lingers for a
  day, blocking new jobs unnecessarily.

Defaults (1800 for Windows, 600 for Linux) are tuned for the typical
detonation / static durations with generous headroom.

The tasks don't currently *bump* heartbeats mid-job — a detonation
runs for its full timeout with the same `heartbeat_at` it had at
acquire time. That's why the stale window is large. If you run very
long detonations, either bump the stale window or implement a
heartbeat tick (one-liner: `pool.heartbeat(vmid, analysis_id)` from a
periodic thread).

## Manual pool inspection

```sql
-- Who's holding what right now:
SELECT vmid, analysis_id, guest_type, acquired_at, heartbeat_at
FROM vm_pool_leases
WHERE status = 'leased'
ORDER BY acquired_at;

-- Orphan history:
SELECT count(*) FROM vm_pool_leases WHERE status = 'orphaned';
```

## Manual recovery

If a pool is wedged (every slot leased, no actual jobs running —
probably a post-incident state), you can hand-release:

```sql
-- Check first which leases are wedged. Never do this while real jobs run.
UPDATE vm_pool_leases
   SET status = 'released', released_at = now()
 WHERE status = 'leased' AND guest_type = 'windows';
```

Then reconcile Proxmox: any `sandgnat-<vmid>` VM that's still around
should be stopped and destroyed.

## Mixing guest types

A single job **can** hold one Windows lease and one Linux lease
simultaneously (different `guest_type`) — that's exactly what happens
during the static→detonation chain. The partial unique index
`uq_pool_active_analysis` only enforces one lease per analysis_id per
guest_type. No additional config needed.

## Template vmids

- `PROXMOX_TEMPLATE_VMID` (default 9000) — Windows template.
- `LINUX_TEMPLATE_VMID` (default 9001) — Linux template.

The pool ranges must **not** overlap these. 9100+ / 9200+ for pools,
single-digit 90xx for templates is the convention.

## Related

- [build-windows-guest.md](build-windows-guest.md) / [build-linux-guest.md](build-linux-guest.md)
  — preparing the template VMs the pools clone from.
- [reference/celery-tasks.md](../reference/celery-tasks.md) — how
  tasks acquire and release.
- [reference/database-schema.md](../reference/database-schema.md#vm_pool_leases-migration-002--003)
  — exact `vm_pool_leases` columns.
