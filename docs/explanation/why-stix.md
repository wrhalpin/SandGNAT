# Why STIX 2.1 as the output format

Every persisted behavioural finding passes through
`orchestrator.stix_builder` and ends up as a STIX 2.1 object in
Postgres. This page explains that choice and its consequences.

## What STIX is

STIX (Structured Threat Information eXpression) is an
OASIS-standardised schema for sharing threat intelligence. Version 2.1
defines 19 "domain objects" (SDOs: `malware`, `indicator`,
`attack-pattern`, etc.), 14 "cyber observable objects" (SCOs: `file`,
`process`, `network-traffic`, `domain-name`, etc.), and a set of
relationship types.

Objects are JSON with a deterministic `id` field (`{type}--{UUID}`), a
`type`, a `spec_version`, timestamps, and type-specific fields. Every
SDO/SCO we emit includes an `x_analysis_metadata` extension that ties
it back to an `analysis_id`.

## Why STIX

**Because consumers expect it.** The downstream target is GNAT — a
threat-intel platform that speaks STIX natively, has a STIX ORM, and
mostly exchanges STIX with other platforms. Any custom format we
invented would be a translation layer GNAT would have to own.

**Because it survives schema churn.** SandGNAT's Postgres tables (see
[database-schema.md](../reference/database-schema.md)) will evolve —
Phase 3 added intake columns, Phase 4 added similarity, Phase 5 added
static fingerprint fields. STIX objects don't see any of that: an
external consumer cares about "what did the malware do" and STIX
answers that question at a stable abstraction level.

**Because relationships are a first-class concept.** Every STIX object
carries `object_refs` and can be linked via explicit `relationship`
SDOs. That lets SandGNAT express "this `file` was dropped by this
`process`" or "this `indicator` points to this `network-traffic`"
without reinventing the graph shape every integration.

**Because IDs are deterministic.** SandGNAT uses UUIDv5 derived from
`(analysis_id, type, natural_key)` so re-ingesting the same artifacts
produces the same STIX IDs. That makes the writes idempotent: a
re-run of the analyzer on the same `completed/` workspace is a no-op
at the DB layer thanks to `ON CONFLICT DO NOTHING`.

## What STIX is not

STIX isn't a storage-efficient format. A bundle with hundreds of
process-registry-write observables is tens of KB of JSON. We accept
the bloat because:

1. Postgres JSONB is compressed on disk (TOAST).
2. We extract hot columns (hashes, `analysis_id`, `type`) into
   relational indices, so queries don't scan JSON.
3. The read path through the export API serves whole bundles rarely —
   most analyst queries hit `/analyses`, `/static`, `/similar`, which
   don't return STIX.

STIX also isn't a great match for clustering metadata. Trigram
signatures, LSH bands, similarity edges, and lineage relations **are
not STIX objects** — they live in normalised Postgres tables and
never leak into the bundle. The boundary is: anything an external
threat analyst would want to know about the sample goes through STIX;
anything SandGNAT needs for its own clustering stays in native tables.

## What we actually emit

For a typical completed detonation:

| STIX type          | Count        | Source                             |
|--------------------|--------------|------------------------------------|
| `malware`          | 1            | wraps the entire analysis          |
| `file`             | 1 + per drop | sample itself + every dropped file |
| `process`          | per PID      | ProcMon events grouped by PID      |
| `network-traffic`  | per flow     | PCAP flows                         |
| `indicator`        | per persistence key + per confirmed IOC | RegShot + PCAP     |
| `domain-name`, `ipv4-addr` | per DNS/flow | PCAP                         |

Full per-type field coverage is in [reference/stix-output.md](../reference/stix-output.md).

## The bundle

`persistence.export_bundle(analysis_id)` assembles everything STIX
objects with that `x_analysis_metadata.analysis_id` into a single
STIX 2.1 Bundle. `id` is derived from the bundle's contents so two
identical bundles get the same id.

That's what `GET /analyses/<id>/bundle` returns.

## Custom extensions we use

STIX allows `x_`-prefixed keys on any object. We use a handful:

- `x_analysis_metadata` on every object — links to `analysis_id`, VM
  UUID, tool provenance, analyst confidence.
- `x_quarantine_path` on `file` objects for dropped files.
- `x_artifact_disposition` (`"quarantined"`) on file objects.
- `x_created_by_process_ref` linking a dropped `file` to its creating
  `process`.
- `x_registry_modifications` on `process` objects — summaries of
  RegSetValue events captured in ProcMon.
- `x_http_headers` on `network-traffic` when the PCAP parser extracts
  them.
- `x_imphash` key inside the standard `hashes` dict on `file` objects
  (imphash isn't in the STIX `hash-algorithm-ov` vocabulary).

All extensions are documented in [reference/stix-output.md](../reference/stix-output.md).

## What we don't do

- **We don't emit Relationship SDOs.** The `object_refs` field on
  `malware` is enough for our graph shape; explicit `relationship`
  SDOs are more ceremony than value.
- **We don't emit CourseOfAction, CampaignReport, IntrusionSet.**
  Those are analyst-curated; SandGNAT only emits machine-observed
  facts.
- **We don't emit CAPA capabilities as `attack-pattern` SDOs.** CAPA
  findings live in `static_analysis.capa_capabilities` as normalised
  JSONB. Promoting them to attack-pattern STIX is additive and could
  ship in a later phase.

## STIX vs our own tables: who owns what

For a given sample:

| Question                                      | Where it lives            |
|-----------------------------------------------|---------------------------|
| What was the SHA-256?                         | `analysis_jobs` + STIX file |
| What files did it drop?                       | `dropped_files` (normalised) + STIX file(s) |
| What registry keys did it modify?             | `registry_modifications` + STIX indicator |
| What domains/IPs did it contact?              | `network_iocs` + STIX network-traffic |
| Is this a near-duplicate of prior analysis X? | `analysis_jobs.near_duplicate_of` (*not* STIX) |
| What's its CAPA capability fingerprint?       | `static_analysis.capa_capabilities` (not STIX) |
| What's its byte-trigram MinHash signature?    | `sample_trigrams` (definitely not STIX) |

The rule: **STIX for analyst-facing facts; native tables for SandGNAT's
operational bookkeeping.** Blurring that line causes pain for both
external consumers (who see SandGNAT-specific fields in STIX they
don't understand) and operators (who can't answer "why didn't we
detonate?" from a STIX bundle).
