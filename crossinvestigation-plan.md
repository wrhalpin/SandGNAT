# SandGNAT — Cross-Tool Investigation Context Plan

**Scope:** SandGNAT’s side of the GNAT-o-sphere investigation-context work. The shared contract lives in the GNAT repo at `docs/reference/investigation-context-schema.md` and `docs/architecture/adrs/ADR-00XX-gnat-investigation-context.md`. **Read those first.**

**Intended audience:** Claude Code working in the `wrhalpin/SandGNAT` repo.

-----

## Context that must not be re-derived

SandGNAT is **not** structured as a `sandgnat/` package. Its layout is:

- `orchestrator/` — Python Celery orchestrator.
  - `intake.py`, `intake_api.py`, `intake_server.py` — HTTP `POST /submit` entry point.
  - `export_api.py` — read-only Flask blueprint consumed by `gnat.connectors.sandgnat`. Endpoints: `/analyses`, `/analyses/<uuid>`, `/analyses/<uuid>/bundle`, `/analyses/<uuid>/static`, `/analyses/<uuid>/similar`.
  - `stix_builder.py` — STIX 2.1 object factories + bundle export.
  - `analyzer.py` — turns guest artifacts into STIX + normalised rows.
  - `persistence.py` — writes STIX + metadata + signatures to Postgres.
  - `models.py` — dataclasses for job/artifact rows.
  - `tasks.py` — Celery `analyze_malware_sample`.
- `guest_agent/`, `linux_guest_agent/` — guest-side collectors.
- `migrations/` — Postgres schema, versioned SQL (`001_initial_schema.sql`, `002_intake_and_vm_pool.sql`, `003_static_analysis.sql`).

Integration with GNAT is **pull-based today**: GNAT’s SandGNAT connector hits SandGNAT’s export API. SandGNAT does not push to GNAT. That stays the same.

The authentication model is a shared `X-API-Key` header (`INTAKE_API_KEY`). The gateway and export API use the same scheme.

If any of the above has changed, confirm the current state in-conversation before proceeding.

-----

## Goal

Let a GNAT investigation_id travel with a SandGNAT sample through intake → detonation → STIX bundle → export, so that when GNAT pulls the bundle, every object can be routed into the right investigation’s evidence graph without any heuristic matching.

-----

## The shared contract (quick reference — full version in GNAT repo)

Three custom STIX properties stamped on emitted objects:

- `x_gnat_investigation_id` — string, GNAT investigation primary key.
- `x_gnat_investigation_origin` — always `"sandgnat"` for SandGNAT output.
- `x_gnat_investigation_link_type` — `"confirmed"` when the sample was submitted under a specific investigation_id; `"inferred"` when correlation logic attached it post-hoc; `"suggested"` for unverified matches.

Every run must also emit a STIX `Grouping` wrapping all objects from that run, carrying the same three properties on the Grouping itself.

-----

## Phase 0 — Schema migration

Path: `migrations/004_investigation_context.sql`.

Add nullable columns to `analysis_jobs`:

```sql
ALTER TABLE analysis_jobs
    ADD COLUMN investigation_id TEXT,
    ADD COLUMN investigation_link_type TEXT
        CHECK (investigation_link_type IN ('confirmed', 'inferred', 'suggested'))
        DEFAULT 'confirmed',
    ADD COLUMN investigation_tenant_id TEXT;

CREATE INDEX idx_analysis_jobs_investigation_id
    ON analysis_jobs (investigation_id)
    WHERE investigation_id IS NOT NULL;
```

Rationale:

- `investigation_id` is the GNAT-assigned string. No FK — SandGNAT does not know GNAT’s schema. Validation happens on the GNAT side when the bundle is ingested.
- `investigation_link_type` defaults to `"confirmed"` because if a caller passed an ID at intake time, the caller is asserting the link is known-good. Post-hoc tagging (Phase 5) uses `"inferred"` or `"suggested"`.
- `investigation_tenant_id` lets operators correlate the sample to a tenant without needing GNAT’s API. Useful for audit and multi-tenant deployments.

-----

## Phase 1 — Intake

### 1.1 Accept investigation_id on submission

In `orchestrator/intake_api.py`, extend `POST /submit` to accept optional form fields:

- `investigation_id` — string, max 128 chars, validated against a simple regex `^[A-Za-z0-9_.:-]+$`.
- `investigation_tenant_id` — string, same regex.
- `investigation_link_type` — one of `confirmed`, `inferred`, `suggested`. Defaults to `confirmed`.

Behaviour:

- All three are optional. If `investigation_id` is absent, the other two are ignored.
- The intake endpoint does **not** validate the ID against GNAT. SandGNAT is not a GNAT client; the ID is treated as an opaque tag. Validation happens when GNAT ingests the bundle.
- The fields are persisted on the new `analysis_jobs` columns.

### 1.2 Update the models

In `orchestrator/models.py`, add the three fields to the `AnalysisJob` dataclass. Plumb through `intake.py` and `persistence.py`.

### 1.3 Response surface

The `POST /submit` response already returns `{"decision": "queued", "analysis_id": "...", ...}`. Extend it to echo back the investigation_id if one was provided. This gives the caller an immediate confirmation.

-----

## Phase 2 — STIX stamping

In `orchestrator/stix_builder.py`:

### 2.1 Add a helper

```python
def apply_investigation_context(
    stix_obj: dict,
    investigation_id: str | None,
    link_type: str = "confirmed",
) -> dict:
    """Stamp x_gnat_investigation_* properties if investigation_id is set."""
```

### 2.2 Route all factory outputs through it

Every factory function in `stix_builder.py` that produces a STIX object must call this helper before returning. The context (investigation_id, link_type) is threaded through from the job row.

### 2.3 Grouping envelope

Add a new factory: `build_investigation_grouping(objects, investigation_id, link_type) -> dict`.

It produces a STIX `Grouping` with:

- `name`: `"SandGNAT analysis <analysis_id>"`
- `context`: `"malware-analysis"`
- `object_refs`: every object emitted by the run
- `x_gnat_investigation_id`, `x_gnat_investigation_origin="sandgnat"`, `x_gnat_investigation_link_type`.

The analyzer’s bundle-output step calls this and includes the Grouping at the front of the bundle.

### 2.4 Analyzer update

In `orchestrator/analyzer.py`, read the investigation context from the job row and pass it through the factory calls. No new logic — just threading.

**Important:** objects emitted from analyses with no investigation_id must look exactly like they do today. No stamping, no Grouping. The stamping path is additive.

-----

## Phase 3 — Export API

In `orchestrator/export_api.py`:

### 3.1 Filter support on `/analyses`

Add query params:

- `investigation_id` — return only jobs tagged with this investigation.
- `has_investigation` — boolean, return only jobs that have *any* investigation_id set.

### 3.2 Surface on job responses

`GET /analyses/<uuid>` and `GET /analyses` rows gain:

```json
{
  "investigation_id": "...",
  "investigation_link_type": "confirmed",
  "investigation_tenant_id": "..."
}
```

The GNAT connector uses these fields to decide which investigation to post evidence to. (Note: the connector on the GNAT side hits `POST /api/investigations/{id}/evidence` — this is GNAT work, not SandGNAT work. SandGNAT just has to make the investigation_id visible.)

### 3.3 Bundle endpoint

`GET /analyses/<uuid>/bundle` must now always include the Grouping at the top of the bundle when the job has an investigation_id. The individual objects inside keep their own stamped custom properties.

-----

## Phase 4 — Static and similarity flows

The static analysis flow (`orchestrator/tasks_static.py`, `linux_guest_agent/`) produces its own STIX findings via `static_analysis.py`. These must also be stamped. Same helper, same thread-through.

Similarity lookups (`orchestrator/similarity.py`) don’t emit STIX themselves but contribute to the bundle. No change needed.

-----

## Phase 5 — Post-hoc tagging (optional, recommended)

Sometimes GNAT’s correlator links a completed analysis to an investigation after the fact (e.g., a hash match surfaces in a later investigation). SandGNAT should allow an authorised client to tag an existing job:

Endpoint (add to `orchestrator/export_api.py` but **auth-gated separately** — this is a write endpoint, not read-only):

```
POST /analyses/<uuid>/investigation
Body: {"investigation_id": "...", "link_type": "inferred", "tenant_id": "..."}
```

Behaviour:

- If the job already has an investigation_id, return `409 Conflict` unless `?force=true`.
- On success, update the row and return the updated record. The bundle is **not** regenerated; the custom properties on individual objects stay as they were at analysis time. Only the row-level tag changes.

Rationale for not regenerating: the STIX bundle is persisted and may already have been consumed. Tagging is metadata, not re-analysis. If an analyst wants stamped objects for a retroactive link, they can re-pull and GNAT can re-stamp on its side using the `"inferred"` link_type.

**Skip Phase 5 if schedule is tight.** The intake path (Phase 1) covers the common case.

-----

## Phase 6 — Tests

### Unit

- `tests/test_intake_investigation.py` — submission with and without investigation_id, validation of bad formats, persistence to the row.
- `tests/test_stix_stamping.py` — apply_investigation_context stamps the three properties correctly; objects without a set ID come out unchanged.
- `tests/test_grouping_envelope.py` — Grouping includes every emitted object_ref, has the three custom properties, `context = "malware-analysis"`.
- `tests/test_export_filters.py` — `?investigation_id=...` filters correctly; response rows include the new fields.

### Integration

One end-to-end: submit a sample with an investigation_id, wait for completion in a test harness (mocked Proxmox), pull the bundle, assert the Grouping is present and every object in the bundle carries the three custom properties.

-----

## Phase 7 — Docs

- Update `README.md`’s “Submitting a sample” and “Querying results” sections with the new fields.
- Add `docs/how-to/submit-under-investigation.md` — short how-to.
- Add `docs/reference/investigation-context.md` — exact property names and values; link back to the canonical spec in the GNAT repo.

-----

## Out of scope

- Any SandGNAT-side validation of investigation IDs against GNAT. SandGNAT remains a standalone service with an opaque string tag.
- A push path to GNAT. Pull remains the integration direction.
- Changes to guest agents. Investigation context lives on the host side only.

-----

## Acceptance criteria

1. A sample can be submitted with `investigation_id` via `POST /submit`.
1. The completed STIX bundle from `GET /analyses/<uuid>/bundle` contains a wrapping `Grouping` and every object carries `x_gnat_investigation_id`, `x_gnat_investigation_origin="sandgnat"`, and `x_gnat_investigation_link_type`.
1. `GET /analyses?investigation_id=IC-2026-0001` returns only jobs tagged with that investigation.
1. Submissions without investigation_id work exactly as before — no stamping, no Grouping, bundle byte-compatible with the pre-change output.
1. Migration applies cleanly on an existing database with live data.

-----

## Risks

|Risk                                                                          |Mitigation                                                                                                                                    |
|------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
|Bundle format regression for untagged analyses.                               |Test 4 above. Do not change the bundle builder’s code path when investigation_id is absent.                                                   |
|Large investigation_id values blow up Postgres indices.                       |128-char cap, regex-validated.                                                                                                                |
|Retroactive tag via Phase 5 confuses consumers.                               |Document clearly that Phase 5 only updates the row-level tag; bundle contents don’t change. Keep it off by default behind a flag if uncertain.|
|Celery task picks up an old job with no investigation context after migration.|Migration adds nullable columns — existing in-flight jobs keep working unchanged.                                                             |

-----

## Handoff checklist

- [ ] GNAT’s ADR and schema reference doc are finalised before starting SandGNAT coding.
- [ ] Confirmed in-conversation that `orchestrator/` is still the top-level package name and that `migrations/001`–`003` are still the current schema baseline.
- [ ] Decide whether Phase 5 is in scope for this cut or deferred.