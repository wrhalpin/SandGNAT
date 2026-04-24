<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
---
layout: default
title: Submit a sample under a GNAT investigation
description: Attach a GNAT investigation_id to a SandGNAT submission so the analysis bundle routes into the right evidence graph.
---
-->

# Submit a sample under a GNAT investigation

Tag a submission with a GNAT investigation so every STIX object the
analysis produces can be routed into that investigation's evidence
graph when [GNAT](https://github.com/wrhalpin/GNAT) pulls the bundle.
The tag travels the whole pipeline — intake → detonation → STIX
export — with zero heuristic matching on the GNAT side.

Reference: [investigation-context](../reference/investigation-context.md).

## When to do this

When the analyst **already knows** the investigation the sample
belongs to at submission time. For retroactive linking after a
correlator finds a connection, use the
[tagging endpoint](#retroactive-tagging-phase-5) instead.

## Submitting

`POST /submit` accepts three optional form fields:

| Field                      | Required | Notes                                        |
|----------------------------|---------:|----------------------------------------------|
| `investigation_id`         | optional | GNAT investigation primary key               |
| `investigation_tenant_id`  | optional | Multi-tenant correlation tag                 |
| `investigation_link_type`  | optional | `confirmed` (default), `inferred`, `suggested` |

Both IDs must match `^[A-Za-z0-9_.:\-]+$` and are capped at 128 chars.
If `investigation_id` is absent, the other two are ignored (SandGNAT
has no standalone use for a tenant tag without an investigation).

```bash
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     -F "file=@/path/to/suspicious.exe" \
     -F "investigation_id=IC-2026-0042" \
     -F "investigation_tenant_id=acme-co" \
     http://localhost:8080/submit
```

The response echoes the three fields back so a caller can confirm the
tag stuck before Celery picks up the job:

```json
{
  "decision": "queued",
  "analysis_id": "e3f1b4a2-...",
  "sha256": "...",
  "investigation_id": "IC-2026-0042",
  "investigation_link_type": "confirmed",
  "investigation_tenant_id": "acme-co"
}
```

## What ends up in the STIX bundle

When the detonation completes, `GET /analyses/<uuid>/bundle` returns a
bundle whose `objects[]` starts with a STIX `Grouping`:

```json
{
  "type": "grouping",
  "id": "grouping--...",
  "context": "malware-analysis",
  "name": "SandGNAT analysis e3f1b4a2-...",
  "object_refs": ["malware--...", "file--...", "process--...", ...],
  "x_gnat_investigation_id": "IC-2026-0042",
  "x_gnat_investigation_origin": "sandgnat",
  "x_gnat_investigation_link_type": "confirmed"
}
```

Every object referenced by `object_refs` also carries the three
`x_gnat_investigation_*` properties, so a consumer that reads one
object in isolation still gets the full context block.

## Retroactive tagging (Phase 5)

If a link surfaces after the analysis has already completed (e.g. a
correlator hit weeks later), an authorised client can tag the job
without re-running the analysis:

```bash
curl -sS -X POST -H "X-API-Key: $INTAKE_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"investigation_id":"IC-2026-0100","link_type":"inferred","tenant_id":"acme-co"}' \
     http://localhost:8080/analyses/e3f1b4a2-.../investigation
```

`link_type` defaults to `inferred` on this endpoint — the retroactive
linkage is by definition not operator-asserted. The persisted STIX
bundle is **not** regenerated; the row-level tag is what changes. If
an analyst needs stamped objects reflecting the retroactive link,
GNAT re-stamps on its side with `link_type="inferred"` when it pulls
the bundle.

Re-tagging an already-tagged job returns `409 Conflict`. Pass
`?force=true` to overwrite.

## Filtering the export API by investigation

```bash
# Everything tagged to a specific investigation:
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "http://localhost:8080/analyses?investigation_id=IC-2026-0042"

# Every tagged analysis (any investigation):
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "http://localhost:8080/analyses?has_investigation=true"

# Every untagged analysis:
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     "http://localhost:8080/analyses?has_investigation=false"
```

## Untagged analyses are unaffected

A submission without `investigation_id` produces the exact same
bundle bytes as before the investigation-context work shipped — no
stamping, no Grouping. The feature is strictly additive.
