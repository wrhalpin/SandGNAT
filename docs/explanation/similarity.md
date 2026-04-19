# Trigram similarity and LSH

SandGNAT's Linux static-analysis stage computes a similarity signature
for every sample and uses it to cluster submissions. Two questions this
page answers:

1. **What's a trigram MinHash signature and how does it estimate
   similarity?**
2. **Why banded LSH instead of just comparing signatures pairwise?**

If you just want to use similarity, see
[how-to/query-export-api.md](../how-to/query-export-api.md). The short
version: `GET /analyses/<id>/similar` returns a JSON list of peer
analyses sorted by estimated Jaccard similarity.

## The problem

Malware is heavily reused. Two submissions that look byte-identical
aren't interesting (the sha256 deduplicator catches those). Two
submissions that are 95% the same — a repacked variant, a new config
baked in, a minor string change — are what we want to catch, and
sha256 gives zero signal there.

We want a function that, given a new sample's bytes, can answer "have
we seen anything like this before?" in O(corpus_size) *at worst* and
sub-linear for most samples. Full byte-level comparison is O(N²) and
doesn't scale past a few thousand samples.

## Trigrams

A **trigram** is a 3-element window over a sequence.

- Byte trigram: 3 consecutive bytes of a sample's executable sections.
- Opcode trigram: 3 consecutive mnemonics from a capstone disassembly.

The intuition: two programs with similar control flow produce similar
opcode trigram *sets*, and the set-theoretic overlap (Jaccard) is a
decent proxy for "how related are these?"

**Jaccard similarity** of two sets A and B:

    J(A, B) = |A ∩ B| / |A ∪ B|

Perfect overlap = 1.0. Zero overlap = 0.0. Repacked malware typically
scores 0.3–0.6 on byte trigrams (resource sections and data drift, but
code is preserved); 0.7–0.95 on opcode trigrams after unpacking.

Computing Jaccard directly requires storing every trigram set and
intersecting them — too much memory and too slow for a million-sample
corpus.

## MinHash

MinHash is a probabilistic datastructure that collapses a set of any
size into a fixed-length signature such that

    Pr(signatures match at position i) ≈ J(A, B)

for independent hash functions `h_1..h_k`. SandGNAT uses k=128
permutations, so each sample's signature is 128 × 32-bit ints =
512 bytes.

The algorithm:

1. Pick k independent hash functions `h_1..h_k`. SandGNAT derives them
   deterministically from a fixed seed, so signatures are reproducible
   across hosts and runs. (See `orchestrator.trigrams._generate_hash_coeffs`.)
2. For a set S, the i-th signature entry is `min(h_i(x) for x in S)`.
3. To estimate J(A, B), count positions where signature(A) and
   signature(B) agree, divide by k.

Error decays as `O(1/sqrt(k))`. With k=128 the 1-sigma error is about
0.088 — comfortable for a 0.85 short-circuit threshold.

Code: `orchestrator.trigrams.minhash()` produces a `MinHashSignature`.
Determinism is covered by `test_trigrams.test_minhash_is_deterministic`.

## Banded LSH

Comparing a new signature against every prior signature is
O(N × k) — 128 int-compares times N corpus samples. Still linear,
still too slow at scale.

**Locality-sensitive hashing** solves this with a clever subdivision:

- Split each signature into `b` bands of `r` rows each (`b × r = k`).
  SandGNAT uses b=16, r=8.
- For each band, hash its slice of the signature to a short band-value.
  Two samples share a band iff their band-values at the same index are
  equal.
- Store `(analysis_id, band_index, band_value)` rows in an indexed
  table (`sample_minhash_bands` in Postgres).
- **Query**: for a new signature, look up rows matching each of its 16
  band-values. That's 16 O(1) index probes. The union of matching
  analysis_ids is the **candidate set** — samples that might be similar.
- Compute exact Jaccard only against candidates.

The probability that two samples with true Jaccard J share at least
one band is `1 - (1 - J^r)^b`. For b=16, r=8:

| True Jaccard | P(share a band) |
|--------------|-----------------|
| 0.5          | 6.2%            |
| 0.7          | 64%             |
| 0.8          | 94%             |
| 0.85         | 98.8%           |
| 0.9          | 99.9%+          |

So at the default short-circuit threshold of 0.85, we miss fewer than
1.2% of true near-duplicates. Below 0.7 we mostly don't see them — which
is fine because we don't want to short-circuit on those anyway.

Tuning `b` and `r` trades recall for precision. More bands = higher
recall but more false-positive candidates to exact-compare. The
defaults are the standard "S-curve at ~0.7" values; tune if your
threshold changes significantly.

## Two flavours: byte vs opcode

Byte trigrams are cheap (no disassembly) and language/architecture
agnostic — they work on packed PEs, ELFs, Mach-Os, shellcode
fragments. Weakness: byte-level rewrites (packers, string encoding)
kill the signal.

Opcode trigrams require successful disassembly but are robust to
byte-level obfuscation — an xor-encoded code region looks totally
different byte-wise but disassembles to the same mnemonic stream once
unpacked (assuming the sample unpacks itself; we disassemble the
on-disk form).

SandGNAT stores **both** flavours and computes similarity on each
independently. The `flavour` config (`STATIC_SHORT_CIRCUIT_FLAVOUR=
byte|opcode|either`) picks which flavour's hit triggers the
short-circuit. Default: `either` — accept whichever scores higher.

See the `sample_trigrams` and `sample_minhash_bands` tables in the
[database reference](../reference/database-schema.md) for how the
signatures are persisted.

## When it goes wrong

- **Highly packed samples with code-level entropy near 8.0** — every
  byte looks random, byte trigrams are useless. Opcode trigrams only
  help if the packer exposes a small stub we can disassemble. For
  these cases SandGNAT falls through to detonation (which is what
  we'd want anyway — you can't statically understand a packer).
- **Tiny samples (<1 KiB)** — both the byte trigram set and the
  disassembly window are too small for stable Jaccard estimates.
  Signatures are still emitted, but similarity scores should be
  treated as noisy.
- **Signature-version bump** — changing the hash family in
  `orchestrator.trigrams` invalidates every stored signature. The
  `signature_version` column lets us coexist with old signatures
  during a migration, but until a background re-hash job ships,
  bumping the version means losing similarity data.

## References

- Broder (1997): "On the resemblance and containment of documents" —
  the original MinHash paper.
- Rajaraman & Ullman, *Mining of Massive Datasets*, Chapter 3 — best
  tutorial explanation of banded LSH.
- `orchestrator/trigrams.py` — stdlib-only implementation (~150 LoC).
- `orchestrator/similarity.py` — candidate fetch + ranking + short-circuit
  decision.
