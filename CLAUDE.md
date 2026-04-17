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
- `guest_agent/` — Windows-side collector. **Stdlib only** + `orchestrator.schema`.
  Runs inside the analysis VM, polls the staging share, drives ProcMon/tshark/RegShot,
  detonates the sample, packages artifacts. Deployed as a PyInstaller-frozen exe.
- `migrations/` — forward-only numbered SQL files. Never edit an applied
  migration; add a new one.
- `infra/` — non-code configuration (firewall exports, guest prep scripts).

## Conventions

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

Development branch for this workstream: `claude/malware-analysis-sandbox-4jmVl`.
Commit and push to that branch; don't push to `main`.
