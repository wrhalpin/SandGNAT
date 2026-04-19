# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Byte + opcode trigram extraction and MinHash signatures.

Stdlib only — both the Linux static-analysis guest and the host orchestrator
import this module. Adding third-party deps here breaks PyInstaller-frozen
guest builds.

Why MinHash?
------------

A "raw" trigram set for a real-world binary contains 10^4–10^6 distinct
3-grams. Storing and comparing those sets directly doesn't scale: every
similarity query becomes O(N * k) intersections. MinHash collapses each set
into a fixed-length signature (here: 128 unsigned 32-bit hashes) such that

    P(matching position) ≈ Jaccard(A, B)

so estimating the Jaccard overlap of two samples becomes O(signature_size)
regardless of their original set sizes.

Banded LSH
----------

To skip the O(N) signature comparison too, we split each signature into
`num_bands` contiguous bands (here: 16 × 8 hashes). Two samples are
*candidates* if they share at least one band. The candidate-fetch step is
O(matches) against an indexed table; only candidates get the full Jaccard
estimate. Tuning B and R trades recall for precision — the default 16x8
fires for pairs above ≈ 0.6 Jaccard.

Determinism
-----------

The hash family is `(a_i * x + b_i) mod prime`, with `a_i, b_i` derived
from `hashlib.sha256(seed | i)` for a fixed `seed=0`. This makes signatures
reproducible across hosts and across re-runs, which matters because the
on-wire signature blob ends up in `sample_trigrams.byte_minhash`.

Bumping `SIGNATURE_VERSION` invalidates all stored signatures — only do
that when a hash family change is unavoidable.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Iterable, Iterator

SIGNATURE_VERSION = 1
NUM_PERMUTATIONS = 128
NUM_BANDS = 16
ROWS_PER_BAND = NUM_PERMUTATIONS // NUM_BANDS  # = 8
_PRIME = (1 << 61) - 1   # Mersenne prime; used as the modulus
_HASH_MAX = (1 << 32) - 1
_BYTES_PER_HASH = 4
_SIGNATURE_BYTES = NUM_PERMUTATIONS * _BYTES_PER_HASH


@dataclass(frozen=True, slots=True)
class MinHashSignature:
    """Fixed-size MinHash signature for one set of trigrams."""

    values: tuple[int, ...]   # length == NUM_PERMUTATIONS
    cardinality: int          # number of distinct trigrams the signature was built from
    version: int = SIGNATURE_VERSION

    def __post_init__(self) -> None:
        if len(self.values) != NUM_PERMUTATIONS:
            raise ValueError(
                f"MinHashSignature requires {NUM_PERMUTATIONS} values, got {len(self.values)}"
            )

    def to_bytes(self) -> bytes:
        """Pack the signature into its on-wire form (little-endian uint32 array)."""
        return struct.pack(f"<{NUM_PERMUTATIONS}I", *self.values)

    @classmethod
    def from_bytes(cls, blob: bytes, *, cardinality: int, version: int = SIGNATURE_VERSION) -> "MinHashSignature":
        """Inverse of `to_bytes`. `cardinality` must come from an external
        source (it's not derivable from the signature alone)."""
        if len(blob) != _SIGNATURE_BYTES:
            raise ValueError(
                f"MinHash blob must be exactly {_SIGNATURE_BYTES} bytes, got {len(blob)}"
            )
        values = struct.unpack(f"<{NUM_PERMUTATIONS}I", blob)
        return cls(values=values, cardinality=cardinality, version=version)

    def jaccard(self, other: "MinHashSignature") -> float:
        """Estimate Jaccard similarity from two signatures."""
        if self.version != other.version:
            raise ValueError(
                f"Cannot compare signatures across versions {self.version} vs {other.version}"
            )
        if not self.values or not other.values:
            return 0.0
        matches = sum(1 for a, b in zip(self.values, other.values) if a == b)
        return matches / NUM_PERMUTATIONS

    def bands(self) -> list[bytes]:
        """Split the signature into NUM_BANDS hashed bands suitable for LSH lookup.

        Each band is the SHA-1 of its slice of the signature truncated to 8
        bytes — enough entropy to make collisions across unrelated samples
        vanishingly rare without bloating the index.
        """
        out: list[bytes] = []
        for band_idx in range(NUM_BANDS):
            start = band_idx * ROWS_PER_BAND
            end = start + ROWS_PER_BAND
            slab = struct.pack(f"<{ROWS_PER_BAND}I", *self.values[start:end])
            out.append(hashlib.sha1(slab).digest()[:8])
        return out


# ---------------------------------------------------------------------------
# Hash family. Pre-computed once at import time.
# ---------------------------------------------------------------------------

def _generate_hash_coeffs(seed: int = 0) -> tuple[tuple[int, int], ...]:
    coeffs: list[tuple[int, int]] = []
    for i in range(NUM_PERMUTATIONS):
        digest = hashlib.sha256(f"sandgnat-minhash-{seed}-{i}".encode()).digest()
        a = int.from_bytes(digest[:8], "little") | 1   # ensure odd / nonzero
        b = int.from_bytes(digest[8:16], "little")
        coeffs.append((a, b))
    return tuple(coeffs)


_COEFFS = _generate_hash_coeffs()


def _trigram_universe_hash(trigram: bytes | str) -> int:
    """Hash a single trigram into a 64-bit integer in the universe.

    For byte trigrams we hash the raw 3 bytes; for opcode trigrams we hash
    the concatenated mnemonic string. Either way we use SHA-1 truncated to
    64 bits, which is more than enough collision resistance for the modular
    permutations applied on top.
    """
    if isinstance(trigram, str):
        data = trigram.encode("ascii", errors="replace")
    else:
        data = trigram
    return int.from_bytes(hashlib.sha1(data).digest()[:8], "little") % _PRIME


# ---------------------------------------------------------------------------
# Trigram extraction
# ---------------------------------------------------------------------------

def byte_trigrams(data: bytes) -> Iterator[bytes]:
    """Yield every 3-byte sliding window in `data`. Empty if len(data) < 3."""
    if len(data) < 3:
        return
    mv = memoryview(data)
    for i in range(len(data) - 2):
        yield bytes(mv[i:i + 3])


def opcode_trigrams(mnemonics: Iterable[str]) -> Iterator[str]:
    """Yield every 3-mnemonic sliding window joined by '|'."""
    buf: list[str] = []
    for m in mnemonics:
        buf.append(m.lower())
        if len(buf) >= 3:
            yield "|".join(buf[-3:])


# ---------------------------------------------------------------------------
# MinHash
# ---------------------------------------------------------------------------

def minhash(trigrams: Iterable[bytes | str]) -> MinHashSignature:
    """Compute the MinHash signature of an iterable of trigrams.

    A trigram set with fewer than NUM_PERMUTATIONS distinct elements still
    produces a valid signature — the `_HASH_MAX` sentinel just sits in the
    unused slots, which is fine for Jaccard estimation (the same sentinel
    in two signatures means both sides genuinely had no element shorter
    than that permutation).
    """
    sig = [_HASH_MAX] * NUM_PERMUTATIONS
    seen: set[int] = set()
    for tg in trigrams:
        h = _trigram_universe_hash(tg)
        if h in seen:
            continue
        seen.add(h)
        for i, (a, b) in enumerate(_COEFFS):
            v = ((a * h + b) % _PRIME) & _HASH_MAX
            if v < sig[i]:
                sig[i] = v
    return MinHashSignature(values=tuple(sig), cardinality=len(seen))


def minhash_bytes(data: bytes) -> MinHashSignature:
    """Convenience: byte-trigram MinHash of `data`."""
    return minhash(byte_trigrams(data))


def minhash_opcodes(mnemonics: Iterable[str]) -> MinHashSignature:
    """Convenience: opcode-trigram MinHash of a sequence of mnemonics."""
    return minhash(opcode_trigrams(mnemonics))


# ---------------------------------------------------------------------------
# True Jaccard (used in tests + small-corpus debugging)
# ---------------------------------------------------------------------------

def true_jaccard(a: Iterable, b: Iterable) -> float:
    """Exact Jaccard similarity of two iterables. Used by tests to verify
    that MinHash-estimated similarity tracks the real value."""
    set_a = set(a)
    set_b = set(b)
    if not set_a and not set_b:
        return 1.0
    return len(set_a & set_b) / len(set_a | set_b)
