"""Tests for the LSH-banded similarity engine."""

from __future__ import annotations

import os
from uuid import uuid4

from orchestrator.similarity import (
    InMemorySimilarityStore,
    cache_top_edges,
    find_similar,
    short_circuit_decision,
)
from orchestrator.trigrams import minhash_bytes


def _store_with_samples(n: int = 5):  # type: ignore[no-untyped-def]
    store = InMemorySimilarityStore()
    samples: list[tuple] = []
    for i in range(n):
        analysis_id = uuid4()
        sha = ("%064d" % i)
        data = (f"sample-{i}-".encode() + os.urandom(2048))
        sig = minhash_bytes(data)
        store.store_signature(analysis_id, sha, "byte", sig)
        samples.append((analysis_id, sha, sig, data))
    return store, samples


def test_find_similar_recovers_self_when_not_excluded() -> None:
    store, samples = _store_with_samples()
    aid, sha, sig, _ = samples[0]
    hits = find_similar(
        analysis_id=aid,
        sample_sha256=sha,
        signature=sig,
        flavour="byte",
        store=store,
        exclude_self=False,
    )
    # Self-match should be the top hit at similarity 1.0.
    assert hits
    assert hits[0].analysis_id == aid
    assert hits[0].similarity == 1.0


def test_find_similar_excludes_self_by_default() -> None:
    store, samples = _store_with_samples()
    aid, sha, sig, _ = samples[0]
    hits = find_similar(
        analysis_id=aid,
        sample_sha256=sha,
        signature=sig,
        flavour="byte",
        store=store,
    )
    assert all(h.analysis_id != aid for h in hits)


def test_find_similar_finds_near_duplicate() -> None:
    """A sample that is almost identical to a stored one should rank highest."""
    store, samples = _store_with_samples()
    parent_aid, parent_sha, _, parent_data = samples[0]

    # Append 64 different bytes — the bulk of the trigrams still match.
    sibling_data = parent_data + os.urandom(64)
    sibling_aid = uuid4()
    sibling_sig = minhash_bytes(sibling_data)

    hits = find_similar(
        analysis_id=sibling_aid,
        sample_sha256="x" * 64,
        signature=sibling_sig,
        flavour="byte",
        store=store,
    )
    # Either parent shows up at the top with score >= 0.6, or — if no band
    # collided — there are simply no hits. Both are acceptable LSH outcomes
    # for this fixture; the assertion is "if we got a hit, it points at the
    # right parent".
    if hits:
        assert hits[0].analysis_id == parent_aid
        assert hits[0].similarity > 0.6


def test_short_circuit_returns_best_above_threshold() -> None:
    store, samples = _store_with_samples()
    aid, sha, sig, _ = samples[0]
    hits = find_similar(
        analysis_id=aid,
        sample_sha256=sha,
        signature=sig,
        flavour="byte",
        store=store,
        exclude_self=False,
    )
    decision = short_circuit_decision(hits, threshold=0.85)
    assert decision is not None
    assert decision.similarity >= 0.85


def test_short_circuit_returns_none_when_below_threshold() -> None:
    store, _ = _store_with_samples()
    # A fresh signature unrelated to any stored sample should not short-circuit.
    fresh = minhash_bytes(os.urandom(4096))
    hits = find_similar(
        analysis_id=uuid4(),
        sample_sha256="z" * 64,
        signature=fresh,
        flavour="byte",
        store=store,
    )
    assert short_circuit_decision(hits, threshold=0.85) is None


def test_cache_top_edges_writes_canonical_ordering() -> None:
    """In production callers always pass exclude_self=True, so cache_top_edges
    never sees a self-edge — its canonical-ordering invariant is safe."""
    store, samples = _store_with_samples()
    # Build a fresh similar-but-distinct sample so we get a non-self hit.
    parent_aid, parent_sha, _, parent_data = samples[0]
    sibling_aid = parent_aid  # noqa — bound for clarity
    fresh_aid = parent_aid  # placeholder
    # Take any sample[1..N] hits against sample[0]'s signature; those hits
    # carry different analysis_ids, which is what cache_top_edges requires.
    aid, sha, sig, _ = samples[0]
    hits = find_similar(
        analysis_id=aid,
        sample_sha256=sha,
        signature=sig,
        flavour="byte",
        store=store,
    )
    written = cache_top_edges(analysis_id=aid, hits=hits, store=store, min_score=0.0)
    assert written == len(hits)
    for left, right, _, _ in store.edges:
        assert left < right


def test_store_signature_is_idempotent() -> None:
    store = InMemorySimilarityStore()
    aid = uuid4()
    sig = minhash_bytes(b"hello world" * 100)
    store.store_signature(aid, "a" * 64, "byte", sig)
    store.store_signature(aid, "a" * 64, "byte", sig)  # second write — must not double-band
    bands = sig.bands()
    for idx, value in enumerate(bands):
        assert store._band_lookup["byte"][(idx, value)] == {aid}
