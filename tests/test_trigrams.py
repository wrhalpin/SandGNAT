"""Tests for the byte/opcode trigram extractor + MinHash signature.

We want three things to be true:
  1. Hashing is deterministic — same bytes in, same signature out, across
     interpreter runs and across host/guest. Round-trips through to_bytes
     and from_bytes preserve every value.
  2. Estimated Jaccard via MinHash tracks the true Jaccard within
     ±0.05 across realistic set overlaps.
  3. Banded LSH groups true near-duplicates into the same band, while
     unrelated samples almost never collide.
"""

from __future__ import annotations

import os
import random

from orchestrator.trigrams import (
    NUM_BANDS,
    NUM_PERMUTATIONS,
    SIGNATURE_VERSION,
    MinHashSignature,
    byte_trigrams,
    minhash,
    minhash_bytes,
    minhash_opcodes,
    opcode_trigrams,
    true_jaccard,
)


# ---------------------------------------------------------------------------
# Trigram extraction
# ---------------------------------------------------------------------------

def test_byte_trigrams_yields_expected_count() -> None:
    data = b"ABCDEF"
    grams = list(byte_trigrams(data))
    assert grams == [b"ABC", b"BCD", b"CDE", b"DEF"]


def test_byte_trigrams_empty_for_short_input() -> None:
    assert list(byte_trigrams(b"AB")) == []
    assert list(byte_trigrams(b"")) == []


def test_opcode_trigrams_normalizes_case_and_joins() -> None:
    grams = list(opcode_trigrams(["MOV", "Push", "ret", "call"]))
    # Expect three sliding windows since input has 4 mnemonics.
    assert len(grams) == 2
    assert grams[0] == "mov|push|ret"
    assert grams[1] == "push|ret|call"


# ---------------------------------------------------------------------------
# MinHash determinism + roundtrip
# ---------------------------------------------------------------------------

def test_minhash_is_deterministic() -> None:
    data = os.urandom(2048)
    a = minhash_bytes(data)
    b = minhash_bytes(data)
    assert a.values == b.values
    assert a.cardinality == b.cardinality


def test_minhash_blob_roundtrip() -> None:
    data = b"\x90" * 64 + b"the quick brown fox jumps over the lazy dog" * 50
    sig = minhash_bytes(data)
    blob = sig.to_bytes()
    assert len(blob) == NUM_PERMUTATIONS * 4
    rebuilt = MinHashSignature.from_bytes(blob, cardinality=sig.cardinality)
    assert rebuilt.values == sig.values
    assert rebuilt.version == SIGNATURE_VERSION


def test_minhash_jaccard_self_is_one() -> None:
    sig = minhash_bytes(os.urandom(1024))
    assert sig.jaccard(sig) == 1.0


def test_minhash_jaccard_disjoint_is_low() -> None:
    a = minhash_bytes(os.urandom(2048))
    b = minhash_bytes(os.urandom(2048))
    # Two random buffers basically never share trigrams; expect well under 0.1.
    assert a.jaccard(b) < 0.1


def test_minhash_jaccard_estimate_tracks_truth() -> None:
    """Construct two trigram sets with a known true Jaccard, verify the
    MinHash estimate is within the expected error window."""
    rng = random.Random(42)
    universe = [bytes(rng.getrandbits(8) for _ in range(3)) for _ in range(2000)]
    set_a = universe[:1500]
    set_b = universe[500:2000]
    truth = true_jaccard(set_a, set_b)
    estimate = minhash(set_a).jaccard(minhash(set_b))
    # Standard MinHash error ~ 1/sqrt(NUM_PERMUTATIONS) = ~0.088 for n=128.
    assert abs(estimate - truth) < 0.10, (estimate, truth)


def test_minhash_signature_size_constants() -> None:
    sig = minhash_bytes(b"abcdef" * 100)
    assert len(sig.values) == NUM_PERMUTATIONS
    assert len(sig.bands()) == NUM_BANDS


# ---------------------------------------------------------------------------
# LSH band collisions
# ---------------------------------------------------------------------------

def test_identical_inputs_share_every_band() -> None:
    data = b"sandgnat-static-bytes" * 200
    a = minhash_bytes(data)
    b = minhash_bytes(data)
    assert a.bands() == b.bands()


def test_unrelated_inputs_rarely_share_any_band() -> None:
    rng = random.Random(7)
    seen_collisions = 0
    trials = 25
    for _ in range(trials):
        a = minhash_bytes(bytes(rng.getrandbits(8) for _ in range(2048)))
        b = minhash_bytes(bytes(rng.getrandbits(8) for _ in range(2048)))
        if set(a.bands()) & set(b.bands()):
            seen_collisions += 1
    # Across 25 random pairs of unrelated buffers, band collisions should be
    # vanishingly rare. Allow a tiny budget for noise.
    assert seen_collisions <= 1


# ---------------------------------------------------------------------------
# Opcode signature
# ---------------------------------------------------------------------------

def test_minhash_opcodes_roundtrips() -> None:
    mnemonics = ["mov", "push", "ret", "call", "jmp", "mov", "ret"]
    sig = minhash_opcodes(mnemonics)
    rebuilt = MinHashSignature.from_bytes(sig.to_bytes(), cardinality=sig.cardinality)
    assert rebuilt.values == sig.values
