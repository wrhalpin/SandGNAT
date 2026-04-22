# CLAUDE.md — session orientation

## What this repo is

SandGNAT is an automated malware runtime-analysis sandbox. It detonates samples
in isolated Windows VMs on Proxmox, captures registry/file/network/process
artifacts, and emits STIX 2.1 into PostgreSQL.

Canonical design: `docs/MALWARE_ANALYSIS_SYSTEM_DESIGN.md`. Read it before
making architectural changes.

## Layout at a glance

- `orchestrator/` — host-side Python package. Celery tasks, Proxmox API,
  Postgres persistence, STIX construction.
- `orchestrator/schema.py` — shared host<->guest wire schema. **Stdlib only**;
  both sides import it. Don't add third-party deps here.
- `orchestrator/stix_builder.py` — STIX 2.1 factories. All persisted
  behavioural findings flow through here.
- `orchestrator/parsers/` — One parser per capture tool (ProcMon CSV, RegShot
  diff, Wireshark PCAP). Parsers return plain dicts; `stix_builder` converts
  them to STIX. Keep that separation.
- `orchestrator/guest_driver.py` — host side of the detonation protocol:
  stages samples, publishes job manifests to `staging/pending/`, waits for the
  guest to write `completed/{job_id}/result.json`.
- `orchestrator/analyzer.py` — turns a guest's completed artifacts into a
  (STIX objects + normalised rows) bundle. Pure — no DB writes.
- `orchestrator/persistence.py` — the only module that writes to Postgres. Use
  it from tasks and tests; don't scatter SQL elsewhere.
- `orchestrator/intake.py` — sample intake pipeline (validate → hash → dedupe
  → VT hash lookup → YARA scan → stage bytes → insert row → enqueue). Takes
  injectable `JobStore` + `Enqueuer` so tests run offline.
- `orchestrator/intake_api.py` + `intake_server.py` — Flask HTTP front-end.
  Intake endpoints (`POST /submit`, `GET /jobs/<uuid>`, `GET /healthz`) live
  here directly; read-only export endpoints are a blueprint from
  `export_api.py` registered onto the same app. Requires `INTAKE_API_KEY`;
  factory refuses to start without it.
- `orchestrator/export_api.py` — read-only Flask blueprint consumed by the
  `gnat.connectors.sandgnat` connector (in the separate `wrhalpin/GNAT`
  repo). Routes: `GET /analyses`, `GET /analyses/<uuid>`,
  `GET /analyses/<uuid>/bundle`, `GET /analyses/<uuid>/static`,
  `GET /analyses/<uuid>/similar`. All SQL goes through `persistence.py`;
  the blueprint only calls `ExportStore` protocol methods, so tests use an
  in-memory fake.
- `orchestrator/vt_client.py` — VirusTotal v3 **hash-only** lookup. Never
  upload sample bytes to VT — that leaks the corpus.
- `orchestrator/yara_scanner.py` — optional YARA pre-classification
  (`yara-python` extras). High-severity matches bump job priority.
- `orchestrator/vm_pool.py` — DB-backed vmid pool (`vm_pool_leases` table).
  `try_acquire_lease` is a conditional UPSERT; the WHERE guard is the lock.
  Stale leases get reaped by heartbeat age, so a crashed worker doesn't
  permanently burn a slot. Two pool instances share the table — Windows
  (vmid 9100–9199, `guest_type='windows'`) and Linux (9200–9299,
  `guest_type='linux'`).
- `orchestrator/trigrams.py` — stdlib-only MinHash + LSH band derivation.
  Imported by both the host orchestrator and the Linux static-analysis
  guest. Bumping `SIGNATURE_VERSION` invalidates every stored signature.
- `orchestrator/similarity.py` — banded LSH lookup over
  `sample_minhash_bands` + Jaccard ranking + `short_circuit_decision`.
- `orchestrator/static_analysis.py` — pure parser turning the Linux
  guest's `static_analysis.json` + trigram blobs into a
  `StaticAnalysisBundle`. Mirrors `analyzer.py`'s role for detonation.
- `orchestrator/evasion_detector.py` — pure post-run analyzer that
  inspects ProcMon events + the StaticAnalysisRow for anti-VM /
  anti-analysis behaviour (BIOS-registry probes, VM-artifact file
  lookups, analysis-tool enumeration, suspicious imports, YARA
  anti_vm hits). Task layer flips `analysis_jobs.evasion_observed`
  and logs an `evasion_observed` audit event on any hit. YARA
  companion rules live in `infra/yara/anti_vm.yar`.
- `orchestrator/tasks_static.py` — Celery `static_analyze_sample` on queue
  `static`. Acquires a Linux pool slot, publishes a `mode=static_analysis`
  manifest, persists findings + signatures, runs LSH lookup, and either
  short-circuits (mark near-duplicate, skip detonation) or chains
  `analyze_malware_sample`.
- `linux_guest_agent/` — Linux static-analysis guest. **Stdlib only** for
  the watcher/runner; per-tool deps are optional and degrade to no-ops
  when missing. Reuses `orchestrator.schema` directly.
- `guest_agent/` — Windows-side collector. **Stdlib only** + `orchestrator.schema`.
  Runs inside the analysis VM, polls the staging share, drives ProcMon/tshark/RegShot,
  detonates the sample, packages artifacts. Deployed as a PyInstaller-frozen exe.
- `guest_agent/activity/` — user-activity simulator (mouse jiggle, cursor
  tour, keyboard noise, window dance). Spun up by `runner.py` around
  `execute_sample`; import-safe on Linux because `winapi.py` stubs the
  ctypes shims off-Windows. Config is env-var only (no schema bump).
- `migrations/` — forward-only numbered SQL files. Never edit an applied
  migration; add a new one.
- `infra/` — non-code configuration (firewall exports, guest prep scripts).

## Conventions

- **Licence:** Apache-2.0. Every source file starts with an SPDX header —
  `# SPDX-License-Identifier: Apache-2.0` and `# Copyright 2026 Bill Halpin`
  (or `--` for SQL). New files must include it.
- **Python 3.11+**, type-hinted. `psycopg` (v3) for Postgres. `stix2` for STIX.
  `celery` + `redis` for the queue. `proxmoxer` for Proxmox API.
- **IDs:** every STIX object gets a deterministic UUIDv5 derived from
  `(analysis_id, type, natural_key)` so re-ingest is idempotent. See
  `stix_builder.stix_id()`.
- **Analysis linkage:** every STIX object carries `x_analysis_metadata.analysis_id`.
  Never persist a STIX object without it.
- **Secrets/config:** all via env vars, read in `orchestrator/config.py`. No
  hard-coded hosts, tokens, or paths.
- **Testing:** parsers and analyzer are pure functions over fixture files.
  `pytest tests/` runs the full suite offline (no DB, no Proxmox, no Windows).
- **Windows paths from the guest:** the guest speaks Windows path syntax.
  On the host, use `PureWindowsPath(original_path).name` to extract filenames
  — `Path(...)` treats backslashes literally on POSIX and will bite you.
- **Staging protocol:** host writes `staging/pending/{job_id}.json`; guest
  atomically renames it into `staging/in-flight/{job_id}/`; guest writes the
  workspace, renames to `staging/completed/{job_id}/`, drops `result.json`
  last. Host polls for `result.json` — don't read other files until it exists.
- **Intake is the only row-creator for `analysis_jobs`.** The Celery task
  looks up by id; it never inserts. Sample bytes are staged to
  `{staging_root}/samples/{analysis_id}/{sample_name}` by intake before
  enqueue, and the task re-hashes before publishing a manifest to the guest.
- **VM pool is the only vmid allocator.** Never hard-code vmids in tasks —
  `VmPool.acquire(analysis_id)` hands out from the configured range and
  records a lease. Always `pool.release()` in a finally block.
- **Wire schema is v2.** `JobManifest.mode` discriminates between
  `MODE_DETONATION` (Windows guest) and `MODE_STATIC_ANALYSIS` (Linux
  guest). Each guest refuses manifests for the other mode at claim time —
  misrouted jobs fail fast instead of producing nonsense envelopes. Bumping
  `SCHEMA_VERSION` requires re-freezing both guests.
- **Static analysis runs first when enabled.** With
  `STATIC_ANALYSIS_ENABLED=1`, `intake.enqueue_analysis` routes to
  `static_analyze_sample` instead of `analyze_malware_sample`. The static
  task either short-circuits (near-duplicate found above the configured
  Jaccard threshold) or chains the detonation task itself. Detonation
  never inserts the job row — intake still does, just like before.
- **The export API is the GNAT integration surface.** External consumers
  (specifically the `gnat.connectors.sandgnat` connector in
  `wrhalpin/GNAT`) pull from HTTP, not from Postgres. Adding new read
  functionality means adding a query function to `persistence.py` and a
  route to `export_api.py` — never teaching a second module to read from
  the DB directly.

## Safety rules (non-negotiable)

- Never add code that downloads, executes, or unpacks malware samples on the
  orchestrator host. Execution only happens inside Proxmox guest VMs via the
  documented lifecycle.
- Never weaken network isolation: the default-deny OPNsense rules are the
  security boundary. Changes to `infra/opnsense/` require an explicit design-doc
  update first.
- Never log raw sample contents, raw PCAP payloads, or quarantine paths at
  INFO+ level. Hashes and STIX IDs only.

## Working on feature branches

Development branch for this workstream: `claude/intake-service-vm-manager-Azqfw`.
Commit and push to that branch; don't push to `main`.
