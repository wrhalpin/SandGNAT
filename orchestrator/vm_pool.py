"""DB-backed VM pool manager.

Replaces the placeholder `9100 + (job.int % 900)` vmid derivation from the
Phase 2 scaffold. Every running Celery worker that needs a fresh guest VM
calls `VmPool.acquire(analysis_id)`; the pool hands back a free vmid from
the configured range and records a lease in `vm_pool_leases`.

Leases are the durable source of truth for "which vmids are currently in
use." A crashed worker leaves its lease behind, but the lease carries a
heartbeat timestamp — a periodic sweep reclaims any lease whose heartbeat
has aged past `stale_lease_seconds`.

Allocation strategy
-------------------

The acquire path issues a single UPSERT per candidate vmid:

    INSERT INTO vm_pool_leases (vmid, node, analysis_id, status)
    VALUES (%s, %s, %s, 'leased')
    ON CONFLICT (vmid) DO UPDATE SET ...
    WHERE vm_pool_leases.status IN ('released','orphaned')
       OR vm_pool_leases.heartbeat_at < now() - interval '%d seconds'
    RETURNING vmid

The partial update guard means two workers racing for the same vmid never
both succeed: exactly one INSERT returns a row, the other returns zero and
moves on to the next candidate. No advisory locks, no explicit transactions.

The module is import-safe on hosts without Postgres: the `Store` protocol is
injected, so tests use an in-memory fake.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import UUID

from .models import VmLease

log = logging.getLogger(__name__)


class PoolExhausted(RuntimeError):
    """Raised when every vmid in the configured range is currently leased."""


class PoolStore(Protocol):
    """Subset of persistence needed by the pool. Implemented in `persistence.py`."""

    def try_acquire_lease(
        self,
        vmid: int,
        node: str,
        analysis_id: UUID,
        stale_after_seconds: int,
    ) -> bool:
        """Atomically claim `vmid` for `analysis_id`. Return True on success."""

    def heartbeat_lease(self, vmid: int, analysis_id: UUID) -> bool:
        """Bump heartbeat_at for an active lease. Return True if matched."""

    def release_lease(self, vmid: int, analysis_id: UUID) -> None: ...

    def mark_orphaned(self, vmid: int) -> None: ...

    def active_leases(self) -> list[VmLease]: ...

    def reap_stale(self, stale_after_seconds: int) -> list[int]:
        """Mark any stale leased rows as orphaned; return reclaimed vmids."""


class VmPool:
    def __init__(
        self,
        store: PoolStore,
        *,
        vmid_min: int,
        vmid_max: int,
        node: str,
        stale_lease_seconds: int = 1800,
    ) -> None:
        if vmid_min > vmid_max:
            raise ValueError(f"vmid_min {vmid_min} > vmid_max {vmid_max}")
        self._store = store
        self._min = vmid_min
        self._max = vmid_max
        self._node = node
        self._stale_after = stale_lease_seconds

    @property
    def capacity(self) -> int:
        return self._max - self._min + 1

    def acquire(self, analysis_id: UUID) -> int:
        """Claim a free vmid from the pool. Raises PoolExhausted on full pool.

        We sweep stale leases first so a crashed worker doesn't permanently
        burn a slot. Candidate vmids are tried in order; `try_acquire_lease`
        is responsible for the atomic SQL, so if two workers hit the same
        vmid at once exactly one wins.
        """
        self._store.reap_stale(self._stale_after)
        for vmid in range(self._min, self._max + 1):
            if self._store.try_acquire_lease(
                vmid, self._node, analysis_id, self._stale_after
            ):
                log.info("Acquired vmid=%d for analysis %s", vmid, analysis_id)
                return vmid
        raise PoolExhausted(
            f"no free vmids in [{self._min}, {self._max}] for analysis {analysis_id}"
        )

    def heartbeat(self, vmid: int, analysis_id: UUID) -> None:
        if not self._store.heartbeat_lease(vmid, analysis_id):
            log.warning(
                "Heartbeat for vmid=%d analysis=%s did not match any active lease",
                vmid,
                analysis_id,
            )

    def release(self, vmid: int, analysis_id: UUID) -> None:
        self._store.release_lease(vmid, analysis_id)
        log.info("Released vmid=%d for analysis %s", vmid, analysis_id)

    def mark_orphaned(self, vmid: int) -> None:
        self._store.mark_orphaned(vmid)

    def active_count(self) -> int:
        return sum(1 for lease in self._store.active_leases() if lease.status == "leased")

    def snapshot(self) -> list[VmLease]:
        return self._store.active_leases()

    def reap_stale(self) -> list[int]:
        return self._store.reap_stale(self._stale_after)


# ---------------------------------------------------------------------------
# In-memory store, used by tests and by small single-node deployments that
# don't want the Postgres dependency. Not process-safe.
# ---------------------------------------------------------------------------

class InMemoryPoolStore:
    """Thread-unsafe, process-local pool store. Testing / dev only."""

    def __init__(self) -> None:
        self._leases: dict[int, VmLease] = {}

    def try_acquire_lease(
        self,
        vmid: int,
        node: str,
        analysis_id: UUID,
        stale_after_seconds: int,
    ) -> bool:
        lease = self._leases.get(vmid)
        now = datetime.now(timezone.utc)
        is_free = (
            lease is None
            or lease.status in {"released", "orphaned"}
            or (
                lease.heartbeat_at is not None
                and lease.heartbeat_at < now - timedelta(seconds=stale_after_seconds)
            )
        )
        if not is_free:
            return False
        for existing in self._leases.values():
            if existing.status == "leased" and existing.analysis_id == analysis_id:
                # one lease per job at a time
                return False
        self._leases[vmid] = VmLease(
            vmid=vmid,
            node=node,
            analysis_id=analysis_id,
            status="leased",
            acquired_at=now,
            heartbeat_at=now,
        )
        return True

    def heartbeat_lease(self, vmid: int, analysis_id: UUID) -> bool:
        lease = self._leases.get(vmid)
        if not lease or lease.status != "leased" or lease.analysis_id != analysis_id:
            return False
        lease.heartbeat_at = datetime.now(timezone.utc)
        return True

    def release_lease(self, vmid: int, analysis_id: UUID) -> None:
        lease = self._leases.get(vmid)
        if lease and lease.analysis_id == analysis_id:
            lease.status = "released"
            lease.released_at = datetime.now(timezone.utc)

    def mark_orphaned(self, vmid: int) -> None:
        lease = self._leases.get(vmid)
        if lease:
            lease.status = "orphaned"

    def active_leases(self) -> list[VmLease]:
        return [lease for lease in self._leases.values() if lease.status == "leased"]

    def reap_stale(self, stale_after_seconds: int) -> list[int]:
        threshold = datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)
        reclaimed: list[int] = []
        for vmid, lease in self._leases.items():
            if (
                lease.status == "leased"
                and lease.heartbeat_at is not None
                and lease.heartbeat_at < threshold
            ):
                lease.status = "orphaned"
                reclaimed.append(vmid)
        return reclaimed
