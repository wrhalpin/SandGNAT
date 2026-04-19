# Tutorial 03 — Force a reanalysis and see a near-duplicate

By the end: you've submitted one sample, submitted a **slightly
modified** copy of it, and watched SandGNAT correctly identify the
second as a near-duplicate of the first via trigram similarity —
skipping Windows detonation entirely and lineage-linking back to the
parent.

This tutorial requires `STATIC_ANALYSIS_ENABLED=1` and at least one
Linux static-analysis VM. If you don't have that set up, see
[how-to/build-linux-guest.md](../how-to/build-linux-guest.md).

Estimated time: 15 minutes.

## Prerequisites

- You've completed [tutorial 01](01-your-first-sample.md).
- `STATIC_ANALYSIS_ENABLED=1`, `STATIC_SHORT_CIRCUIT_THRESHOLD=0.85`
  (the default), Linux static-analysis guest running.
- `curl` and `jq` on your path.
- Two test files — we'll generate them in a moment.

## Step 1 — Build two closely-related samples

We need two binaries that share most of their code but aren't
byte-identical (otherwise the sha256 dedupe catches the duplicate
before trigrams get involved).

```bash
mkdir -p /tmp/sandgnat-tut3
cd /tmp/sandgnat-tut3

# Sample A: a tiny benign payload-echoer.
cat > payload.c <<'EOF'
#include <stdio.h>
int main(int argc, char **argv) {
    printf("sandgnat-tutorial-payload version %s\n", argv[0]);
    return 0;
}
EOF

gcc -O2 -o sample-A payload.c

# Sample B: same source, rebuilt with a different string literal.
# Because the code is otherwise identical, the code-section trigrams
# will be near-duplicates but the sha256s will differ.
sed -i 's/version/v2/' payload.c
gcc -O2 -o sample-B payload.c

# Confirm they have different SHA-256s:
sha256sum sample-A sample-B
```

You should see two distinct hashes.

## Step 2 — Submit sample A

```bash
export KEY=$INTAKE_API_KEY
export URL=$SANDGNAT_URL   # e.g. http://localhost:8080

A=$(curl -sS \
    -H "X-API-Key: $KEY" \
    -F "file=@sample-A" \
    "$URL/submit" | jq -r '.analysis_id')
echo "sample-A analysis_id: $A"
```

Wait for it to complete (this invokes both the static stage and
detonation for a fresh sample):

```bash
while true; do
    STATUS=$(curl -sS -H "X-API-Key: $KEY" \
        "$URL/analyses/$A" | jq -r '.status')
    echo "[$(date +%H:%M:%S)] sample-A status=$STATUS"
    [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
    sleep 15
done
```

Once completed, confirm it went through the full pipeline (not a
short-circuit — it's the first of its kind):

```bash
curl -sS -H "X-API-Key: $KEY" "$URL/analyses/$A" | \
    jq '{status, near_duplicate_of, near_duplicate_score}'
```

Expect `near_duplicate_of: null`. Sample A is now the "parent" in the
corpus.

## Step 3 — Submit sample B

```bash
B=$(curl -sS \
    -H "X-API-Key: $KEY" \
    -F "file=@sample-B" \
    "$URL/submit" | jq -r '.analysis_id')
echo "sample-B analysis_id: $B"
```

Wait again:

```bash
while true; do
    STATUS=$(curl -sS -H "X-API-Key: $KEY" \
        "$URL/analyses/$B" | jq -r '.status')
    echo "[$(date +%H:%M:%S)] sample-B status=$STATUS"
    [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
    sleep 10
done
```

**This should complete faster than sample A.** The static stage runs
(30–60 s) but Windows detonation doesn't.

## Step 4 — Check the short-circuit

```bash
curl -sS -H "X-API-Key: $KEY" "$URL/analyses/$B" | \
    jq '{status, intake_decision, near_duplicate_of, near_duplicate_score, duration_seconds}'
```

Expect something like:

```json
{
  "status": "completed",
  "intake_decision": "near_duplicate",
  "near_duplicate_of": "<sample-A's id>",
  "near_duplicate_score": 0.92,
  "duration_seconds": 45
}
```

`near_duplicate_of` points at sample A. `near_duplicate_score` is the
Jaccard estimate between B's trigrams and A's trigrams — anything
≥ 0.85 (the default threshold) triggered the short-circuit.

Duration dropped dramatically because detonation didn't fire.

## Step 5 — Inspect the similarity neighbour

From sample B's perspective:

```bash
curl -sS -H "X-API-Key: $KEY" \
    "$URL/analyses/$B/similar?threshold=0.5" | jq '.items'
```

Expect:

```json
[
  {
    "analysis_id": "<sample-A's id>",
    "sample_sha256": "<sample-A's sha>",
    "similarity": 0.92,
    "flavour": "byte",
    "relation": "near_duplicate"
  }
]
```

`relation: near_duplicate` marks it as a short-circuit parent (from
`analysis_lineage`), not just an LSH neighbour.

And from sample A's perspective, B shows up as a peer:

```bash
curl -sS -H "X-API-Key: $KEY" \
    "$URL/analyses/$A/similar?threshold=0.5" | jq '.items'
```

The similarity table is symmetric — both samples see each other.

## Step 6 — Get the STIX bundle for the near-duplicate

Fetch B's bundle:

```bash
curl -sS -H "X-API-Key: $KEY" "$URL/analyses/$B/bundle" | jq '.objects | length'
```

You'll likely see `0` — B's analysis_id has no STIX objects because
no detonation ran. The bundle lives on A; clients are expected to
follow the lineage:

```bash
PARENT=$(curl -sS -H "X-API-Key: $KEY" "$URL/analyses/$B" | \
    jq -r '.near_duplicate_of')
curl -sS -H "X-API-Key: $KEY" "$URL/analyses/$PARENT/bundle" | \
    jq '.objects | length'
```

Now you see A's actual object count.

This pattern is what the GNAT connector does — follow
`near_duplicate_of` when the bundle is empty. See
[explanation/near-duplicate-short-circuit.md](../explanation/near-duplicate-short-circuit.md).

## Step 7 — Force a full reanalysis

Say you want to **force** B to be detonated anyway (maybe your rules
updated, maybe you're debugging). Use `force=true` to bypass intake
dedupe:

```bash
B2=$(curl -sS \
    -H "X-API-Key: $KEY" \
    -F "file=@sample-B" \
    -F "force=true" \
    "$URL/submit" | jq -r '.analysis_id')
echo "B-forced analysis_id: $B2"
```

Note `force=true` bypasses the **sha256 dedupe** at intake. It does
**not** bypass the trigram short-circuit at static. If you want a
forced detonation regardless of similarity, you'd need to set
`STATIC_SHORT_CIRCUIT_THRESHOLD=1.01` globally (nothing short-circuits)
or `STATIC_ANALYSIS_ENABLED=0` (skip the static stage entirely) for
the duration of your experiment.

## Step 8 — Check the audit log

```bash
psql "$DATABASE_URL" -c "
SELECT event_type, details
  FROM analysis_audit_log
 WHERE analysis_id = '$B'
 ORDER BY occurred_at
"
```

You should see a `near_duplicate_short_circuit` event with the
parent id and score embedded.

## What you've accomplished

- Submitted a first sample and observed the full (static →
  detonation) pipeline.
- Submitted a near-duplicate and watched SandGNAT skip detonation
  entirely.
- Verified via the `/similar` and `/analyses` endpoints that the
  similarity + lineage linkage is correct.
- Learned how to follow a `near_duplicate_of` pointer to the real
  STIX bundle.
- Seen how `force=true` affects dedupe (but not the short-circuit).

## Next

- [explanation/similarity.md](../explanation/similarity.md) — the
  MinHash + LSH theory behind what just happened.
- [explanation/near-duplicate-short-circuit.md](../explanation/near-duplicate-short-circuit.md)
  — why skipping detonation is the right default.
- [how-to/query-export-api.md](../how-to/query-export-api.md) — write
  a client that handles the lineage pattern automatically.

## Troubleshooting

- **Sample B ran the full pipeline anyway** — the trigram similarity
  didn't cross the threshold. Two things to check:
  - `curl ... /analyses/$B/similar?threshold=0` shows the actual
    similarity score. If it's below 0.85, either lower your threshold
    or make B more similar to A.
  - If similarity is empty, the static stage may not have run
    (`STATIC_ANALYSIS_ENABLED=0`?), or the Linux guest couldn't
    disassemble the binary (check `/analyses/$B/static` for an error).
- **Both samples got `decision: "duplicate"` instead of `"queued"`** —
  you accidentally made them byte-identical. Run `sha256sum` and
  verify they differ.
- **"near_duplicate_score: null" even though `near_duplicate_of` is
  set** — mismatched migration state. Confirm migration 003 is
  applied (`\d analysis_jobs` shows the `near_duplicate_score`
  column).
