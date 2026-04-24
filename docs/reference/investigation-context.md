<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
---
layout: default
title: Investigation context reference
description: Exact property names, values, persistence, and wire shapes for the cross-tool investigation context on SandGNAT.
---
-->

# Investigation context reference

Exact property names, values, persistence, and wire shapes for
SandGNAT's side of the GNAT-o-sphere cross-tool investigation
context. How-to walkthrough:
[submit-under-investigation](../how-to/submit-under-investigation.md).

The canonical cross-tool contract lives in the
[wrhalpin/GNAT repo](https://github.com/wrhalpin/GNAT) at
`docs/reference/investigation-context-schema.md`. Differences between
that spec and this page are bugs — file against the SandGNAT repo.

## Identifier format

| Rule                  | Value                                                   |
|-----------------------|---------------------------------------------------------|
| Character class       | `^[A-Za-z0-9_.:\-]+$`                                   |
| Maximum length        | 128 characters                                          |
| Validation module     | `orchestrator.intake.validate_investigation_fields`     |

Validation happens at the intake edge and on `POST
/analyses/<id>/investigation`. SandGNAT never calls out to GNAT to
verify that an ID exists — it's treated as an opaque tag. Validation
of the referenced investigation happens on the GNAT side when the
bundle is ingested.

## Link types

| Value        | Meaning                                                                 |
|--------------|-------------------------------------------------------------------------|
| `confirmed`  | Operator-asserted at intake. The submitter is claiming the link.        |
| `inferred`   | Added retroactively by a correlator. Default on Phase-5 tagging.        |
| `suggested`  | Machine-proposed link; not yet reviewed.                                |

## STIX custom properties

Applied to every object emitted from a tagged analysis *and* to the
wrapping `Grouping`:

| Property                            | Value                                     |
|-------------------------------------|-------------------------------------------|
| `x_gnat_investigation_id`           | The validated ID string                   |
| `x_gnat_investigation_origin`       | Always `"sandgnat"` in SandGNAT output    |
| `x_gnat_investigation_link_type`    | One of `confirmed` / `inferred` / `suggested` |

Helper: `orchestrator.stix_builder.apply_investigation_context`. The
analyzer calls it once per object at bundle-assembly time.

## The wrapping `Grouping`

| Property          | Value                                           |
|-------------------|-------------------------------------------------|
| `type`            | `grouping`                                      |
| `spec_version`    | `2.1`                                           |
| `id`              | `grouping--<uuidv5(analysis_id, "investigation:<id>")>` |
| `name`            | `SandGNAT analysis <analysis_id>`               |
| `context`         | `malware-analysis`                              |
| `object_refs`     | Every STIX object produced by the run           |
| `x_analysis_metadata` | Standard SandGNAT `{analysis_id, …}` block  |
| `x_gnat_investigation_*` | The three custom properties (same values as on the per-object stamps) |

Factory: `orchestrator.stix_builder.build_investigation_grouping`.

`export_bundle` lifts the Grouping to `objects[0]` so a consumer that
reads the first object always gets the full context.

## Database shape (`analysis_jobs`)

Migration 004 adds three nullable columns:

| Column                    | Type                                      | Notes                                    |
|---------------------------|-------------------------------------------|------------------------------------------|
| `investigation_id`        | `TEXT`                                    | Primary tag. NULL for untagged analyses. |
| `investigation_link_type` | `TEXT` (check: confirmed/inferred/suggested) | Defaults to `confirmed`                |
| `investigation_tenant_id` | `TEXT`                                    | Optional multi-tenant correlation tag    |

Plus a partial index:

```sql
CREATE INDEX idx_analysis_jobs_investigation_id
    ON analysis_jobs (investigation_id)
    WHERE investigation_id IS NOT NULL;
```

## HTTP surface summary

| Method | Path                                       | Purpose                                        |
|--------|--------------------------------------------|------------------------------------------------|
| POST   | `/submit`                                  | Accepts the three form fields at intake time   |
| GET    | `/analyses`                                | New filters: `investigation_id=`, `has_investigation=` |
| GET    | `/analyses/<id>`                           | Response includes the three investigation fields |
| GET    | `/analyses/<id>/bundle`                    | Grouping at `objects[0]`; objects all stamped  |
| POST   | `/analyses/<id>/investigation`             | Retroactive tagging (Phase 5)                  |

Full wire examples:
[submit-under-investigation](../how-to/submit-under-investigation.md).

## What SandGNAT deliberately does not do

- **Validate `investigation_id` against GNAT.** SandGNAT is a
  standalone service; GNAT validates on ingest.
- **Push bundles to GNAT.** Pull remains the integration direction.
- **Regenerate a persisted bundle on retroactive tagging.** The
  bundle is content-addressed and may already have been consumed.
  Row-level tag changes; bundle bytes do not. GNAT re-stamps on its
  side using `link_type="inferred"` when a retroactive pull arrives.

## Backwards compatibility

Submissions without `investigation_id` produce byte-identical STIX
bundles to the pre-investigation output — no Grouping, no `x_gnat_*`
custom properties. This is enforced by
`tests/test_analyzer.py::test_analyze_without_investigation_id_produces_no_grouping`.
