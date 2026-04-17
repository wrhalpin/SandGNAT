# SandGNAT

Automated malware runtime-analysis environment: detonate suspicious binaries in
isolated Windows VMs, capture behavioural artifacts (registry deltas, file I/O,
network traffic, process trees), and emit STIX 2.1 objects into PostgreSQL.

**Full design:** [`docs/MALWARE_ANALYSIS_SYSTEM_DESIGN.md`](docs/MALWARE_ANALYSIS_SYSTEM_DESIGN.md)

## Repository layout

```
.
├── docs/                         Design docs
├── migrations/                   Postgres schema (versioned SQL)
├── orchestrator/                 Python job orchestrator (Celery)
│   ├── config.py                 Environment-backed settings
│   ├── db.py                     psycopg connection pool
│   ├── models.py                 Dataclasses for job/artifact rows
│   ├── schema.py                 Shared host <-> guest wire schema (stdlib only)
│   ├── stix_builder.py           STIX 2.1 object factories + bundle export
│   ├── proxmox_client.py         Proxmox API wrapper (VM lifecycle)
│   ├── guest_driver.py           Stages samples, publishes jobs, waits for results
│   ├── analyzer.py               Turns guest artifacts into STIX + normalised rows
│   ├── persistence.py            Writes STIX objects + metadata to Postgres
│   ├── tasks.py                  Celery tasks (analyze_malware_sample)
│   └── parsers/                  Artifact parsers (ProcMon, RegShot, PCAP)
├── guest_agent/                  Windows-side collector (stdlib only, PyInstaller-friendly)
│   ├── config.py                 Env-backed guest settings
│   ├── watcher.py                Polls staging/pending, claims jobs atomically
│   ├── runner.py                 Per-job capture + detonate + package pipeline
│   ├── executor.py               Runs samples under a hard timeout
│   └── capture/                  Wrappers for ProcMon, tshark, RegShot, drop detection
├── infra/
│   ├── opnsense/                 Firewall rule exports / templates
│   └── guest/                    Windows guest prep + capture scripts
├── tests/                        Unit tests (schema, parsers, analyzer, guest_driver)
└── pyproject.toml                Python project metadata
```

## Quick start (orchestrator development)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# Apply schema to local Postgres
psql "$DATABASE_URL" -f migrations/001_initial_schema.sql

# Run unit tests
pytest
```

## Runtime dependencies

- PostgreSQL 15+ (JSONB GIN indices, `tsvector`)
- Redis 7+ (Celery broker)
- Proxmox VE 8+ (API token auth)
- Python 3.11+

## Status

Phases 1–2 complete: scaffold plus the host<->guest detonation protocol
(`guest_agent` + `guest_driver`) and the analyzer that turns captured
artifacts into STIX. Phase 3 remaining work is the intake service (sample
submission API, VT pre-check, YARA scan).
