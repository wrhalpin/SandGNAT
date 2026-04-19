# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for the VM pool manager.

Uses the in-memory `InMemoryPoolStore` to exercise the allocation, release,
heartbeat, and stale-reap paths without Postgres. The stale-lease path is
tested by manually aging heartbeat timestamps rather than sleeping.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from orchestrator.vm_pool import InMemoryPoolStore, PoolExhausted, VmPool


def _make_pool(**overrides):  # type: ignore[no-untyped-def]
    store = InMemoryPoolStore()
    kwargs = dict(
        vmid_min=9100,
        vmid_max=9103,
        node="pve1",
        stale_lease_seconds=1800,
    )
    kwargs.update(overrides)
    return VmPool(store, **kwargs), store


def test_acquire_returns_first_free_vmid() -> None:
    pool, _ = _make_pool()
    vmid = pool.acquire(uuid4())
    assert vmid == 9100
    vmid2 = pool.acquire(uuid4())
    assert vmid2 == 9101


def test_release_frees_vmid_for_reuse() -> None:
    pool, _ = _make_pool()
    a = uuid4()
    vmid = pool.acquire(a)
    pool.release(vmid, a)
    # Next acquire for a new job should be the earliest again (since that slot
    # is now 'released', the UPSERT guard lets it win).
    vmid2 = pool.acquire(uuid4())
    assert vmid2 == 9100


def test_pool_exhaustion_raises() -> None:
    pool, _ = _make_pool()
    for _ in range(pool.capacity):
        pool.acquire(uuid4())
    with pytest.raises(PoolExhausted):
        pool.acquire(uuid4())


def test_stale_lease_is_reaped_and_reclaimed() -> None:
    pool, store = _make_pool(stale_lease_seconds=60)
    a = uuid4()
    vmid = pool.acquire(a)

    # Age the lease by 10 minutes.
    store._leases[vmid].heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=10)

    reclaimed = pool.reap_stale()
    assert vmid in reclaimed
    assert store._leases[vmid].status == "orphaned"

    # A fresh acquire can now take the reclaimed slot.
    vmid_next = pool.acquire(uuid4())
    assert vmid_next == vmid


def test_heartbeat_keeps_lease_alive() -> None:
    pool, store = _make_pool(stale_lease_seconds=60)
    a = uuid4()
    vmid = pool.acquire(a)

    store._leases[vmid].heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    pool.heartbeat(vmid, a)
    # After heartbeat the lease is fresh again, so reap finds nothing.
    assert pool.reap_stale() == []


def test_same_analysis_cannot_hold_two_leases() -> None:
    pool, _ = _make_pool()
    a = uuid4()
    pool.acquire(a)
    with pytest.raises(PoolExhausted):
        # All other slots are empty, but the unique-analysis constraint keeps
        # us from grabbing a second one for the same job.
        pool.acquire(a)


def test_acquire_skips_slot_held_by_live_peer() -> None:
    pool, store = _make_pool()
    a = uuid4()
    b = uuid4()
    pool.acquire(a)  # takes 9100
    vmid_b = pool.acquire(b)  # must skip 9100
    assert vmid_b == 9101
    assert store._leases[9100].analysis_id == a
    assert store._leases[9101].analysis_id == b


def test_invalid_range_raises() -> None:
    with pytest.raises(ValueError):
        VmPool(InMemoryPoolStore(), vmid_min=100, vmid_max=50, node="pve1")


def test_active_count_tracks_leased_only() -> None:
    pool, _ = _make_pool()
    a = uuid4()
    b = uuid4()
    pool.acquire(a)
    pool.acquire(b)
    assert pool.active_count() == 2
    pool.release(9100, a)
    assert pool.active_count() == 1


def test_two_pools_with_disjoint_ranges_share_one_store() -> None:
    """Windows + Linux pool instances on a single store don't trample each
    other: each picks vmids only from its configured range and tags leases
    with its guest_type."""
    store = InMemoryPoolStore()
    win_pool = VmPool(
        store, vmid_min=9100, vmid_max=9101, node="pve1", guest_type="windows"
    )
    lin_pool = VmPool(
        store, vmid_min=9200, vmid_max=9201, node="pve1", guest_type="linux"
    )
    job = uuid4()

    win_vmid = win_pool.acquire(job)
    lin_vmid = lin_pool.acquire(job)  # same job_id, different guest_type — allowed
    assert 9100 <= win_vmid <= 9101
    assert 9200 <= lin_vmid <= 9201
    assert store._leases[win_vmid].guest_type == "windows"
    assert store._leases[lin_vmid].guest_type == "linux"

    # Each pool's active_count counts only its own slots indirectly via vmid range.
    assert win_pool.active_count() == 2  # active_count counts all leased rows
    assert lin_pool.active_count() == 2


def test_pool_rejects_unknown_guest_type() -> None:
    with pytest.raises(ValueError):
        VmPool(InMemoryPoolStore(), vmid_min=1, vmid_max=2, node="x", guest_type="freebsd")
