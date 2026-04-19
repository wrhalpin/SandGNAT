# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Banded-LSH similarity lookup over MinHash signatures.

Companion to `trigrams.py`. Given a fresh sample's MinHash signature, we
need to answer "what stored samples are most similar?" in O(candidates),
not O(corpus). The strategy is:

    1. Split the new signature into NUM_BANDS bands (see trigrams.bands()).
    2. For each band, look up every stored sample sharing that exact band
       hash. Union those analysis_ids — that's the candidate set.
    3. For each candidate, fetch its full signature and compute
       MinHash.jaccard(). Sort, take top-N.

Step 2 is the cheap part: the `sample_minhash_bands` table has a composite
index on `(flavour, band_index, band_value)` so the lookup is essentially
O(1) per band. Step 3 only touches signatures we already know are likely
to score well.

Short-circuit
-------------

`short_circuit_decision()` is the only knob the static-analysis Celery
task uses to decide "this is close enough to a prior analysis that we can
skip the Windows detonation and just lineage-link." It returns the highest
hit if it crosses the configured threshold, else None.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Protocol
from uuid import UUID

from .trigrams import NUM_BANDS, MinHashSignature

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SimilarityHit:
    """One ranked neighbour returned by `find_similar`."""

    analysis_id: UUID
    sample_sha256: str
    flavour: str  # 'byte' | 'opcode'
    similarity: float


class SimilarityStore(Protocol):
    """Read+write surface for the similarity engine.

    The Postgres implementation lives in `persistence.py`; tests use the
    in-memory `InMemorySimilarityStore` below.
    """

    def candidate_ids(self, flavour: str, bands: list[bytes]) -> set[UUID]:
        """Return analysis_ids that share at least one band with the query."""

    def load_signature(
        self, analysis_id: UUID, flavour: str
    ) -> tuple[str, MinHashSignature] | None:
        """Return (sample_sha256, signature) or None if not stored."""

    def store_signature(
        self,
        analysis_id: UUID,
        sample_sha256: str,
        flavour: str,
        signature: MinHashSignature,
    ) -> None:
        """Persist signature + its bands. Idempotent on (analysis_id, flavour)."""

    def store_similarity_edge(
        self,
        left: UUID,
        right: UUID,
        flavour: str,
        similarity: float,
    ) -> None:
        """Cache a pairwise similarity score (canonical ordering: left < right)."""


def find_similar(
    *,
    analysis_id: UUID,
    sample_sha256: str,
    signature: MinHashSignature,
    flavour: str,
    store: SimilarityStore,
    top_n: int = 10,
    exclude_self: bool = True,
) -> list[SimilarityHit]:
    """LSH-banded similarity search; returns hits sorted high → low."""
    bands = signature.bands()
    candidates = store.candidate_ids(flavour, bands)
    if exclude_self:
        candidates.discard(analysis_id)
    if not candidates:
        return []

    hits: list[SimilarityHit] = []
    for cand_id in candidates:
        loaded = store.load_signature(cand_id, flavour)
        if loaded is None:
            continue
        cand_sha, cand_sig = loaded
        try:
            score = signature.jaccard(cand_sig)
        except ValueError as exc:
            # Different signature_version — skip rather than crash the task.
            log.warning("Skipping %s in similarity scan: %s", cand_id, exc)
            continue
        hits.append(
            SimilarityHit(
                analysis_id=cand_id,
                sample_sha256=cand_sha,
                flavour=flavour,
                similarity=score,
            )
        )

    hits.sort(key=lambda h: h.similarity, reverse=True)
    return hits[:top_n]


def short_circuit_decision(
    hits: list[SimilarityHit], threshold: float
) -> SimilarityHit | None:
    """Return the best hit if it meets `threshold`, else None.

    Caller uses the return value to decide whether to mark the new analysis
    as a near-duplicate of the hit and skip Windows detonation. Hits must
    already be sorted descending by similarity (as `find_similar` returns).
    """
    if not hits:
        return None
    best = hits[0]
    return best if best.similarity >= threshold else None


def cache_top_edges(
    *,
    analysis_id: UUID,
    hits: list[SimilarityHit],
    store: SimilarityStore,
    min_score: float = 0.5,
) -> int:
    """Persist edges for hits at or above `min_score`. Returns count stored.

    Edges below 0.5 are noise — storing every pairwise comparison would
    quickly outgrow the table.
    """
    written = 0
    for hit in hits:
        if hit.similarity < min_score:
            continue
        # Canonical ordering enforced by the table CHECK constraint.
        left, right = sorted((analysis_id, hit.analysis_id))
        store.store_similarity_edge(left, right, hit.flavour, hit.similarity)
        written += 1
    return written


# ---------------------------------------------------------------------------
# In-memory store (tests + small dev deployments).
# ---------------------------------------------------------------------------

class InMemorySimilarityStore:
    """Thread-unsafe, process-local. Mirrors the Postgres-backed semantics."""

    def __init__(self) -> None:
        self._signatures: dict[tuple[UUID, str], tuple[str, MinHashSignature]] = {}
        # band_lookup[flavour][(band_index, band_value)] -> set of analysis_ids
        self._band_lookup: dict[str, dict[tuple[int, bytes], set[UUID]]] = {}
        self.edges: list[tuple[UUID, UUID, str, float]] = []

    def candidate_ids(self, flavour: str, bands: list[bytes]) -> set[UUID]:
        out: set[UUID] = set()
        per_flavour = self._band_lookup.get(flavour, {})
        for idx, band_value in enumerate(bands):
            out |= per_flavour.get((idx, band_value), set())
        return out

    def load_signature(
        self, analysis_id: UUID, flavour: str
    ) -> tuple[str, MinHashSignature] | None:
        return self._signatures.get((analysis_id, flavour))

    def store_signature(
        self,
        analysis_id: UUID,
        sample_sha256: str,
        flavour: str,
        signature: MinHashSignature,
    ) -> None:
        self._signatures[(analysis_id, flavour)] = (sample_sha256, signature)
        bands = signature.bands()
        if len(bands) != NUM_BANDS:
            raise ValueError(f"signature produced {len(bands)} bands, expected {NUM_BANDS}")
        per_flavour = self._band_lookup.setdefault(flavour, {})
        for idx, value in enumerate(bands):
            per_flavour.setdefault((idx, value), set()).add(analysis_id)

    def store_similarity_edge(
        self,
        left: UUID,
        right: UUID,
        flavour: str,
        similarity: float,
    ) -> None:
        if left >= right:
            raise ValueError(f"non-canonical edge {left} >= {right}")
        self.edges.append((left, right, flavour, similarity))
