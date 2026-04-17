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
│   ├── vm_pool.py                DB-backed VM pool manager (lease + reap)
│   ├── guest_driver.py           Stages samples, publishes jobs, waits for results
│   ├── analyzer.py               Turns guest artifacts into STIX + normalised rows
│   ├── persistence.py            Writes STIX objects + metadata to Postgres
│   ├── intake.py                 Sample intake pipeline (validate/hash/VT/YARA/enqueue)
│   ├── intake_api.py             Flask HTTP front-end for submissions
│   ├── intake_server.py          CLI entry point for the intake service
│   ├── vt_client.py              VirusTotal v3 hash-lookup client (no upload)
│   ├── yara_scanner.py           Optional YARA pre-classification
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

# Apply schema to local Postgres (run migrations in order)
psql "$DATABASE_URL" -f migrations/001_initial_schema.sql
psql "$DATABASE_URL" -f migrations/002_intake_and_vm_pool.sql

# Run unit tests
pytest
```

## Submitting a sample

```bash
# Intake API (requires INTAKE_API_KEY in env on the server):
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     -F "file=@/path/to/sample.exe" \
     -F "priority=3" \
     http://localhost:8080/submit

# Response:
# {"decision": "queued", "analysis_id": "...", "sha256": "...", "priority": 3, ...}

# Poll status:
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
     http://localhost:8080/jobs/<analysis_id>
```

Env knobs for intake:

| Variable                  | Purpose                                                |
|---------------------------|--------------------------------------------------------|
| `INTAKE_API_KEY`          | Shared secret for `X-API-Key` header (required)        |
| `INTAKE_BIND_HOST/PORT`   | HTTP bind address                                      |
| `INTAKE_MAX_SAMPLE_BYTES` | Hard cap on upload size (default 128 MiB)              |
| `INTAKE_YARA_RULES_DIR`   | Directory of `.yar` files to scan uploads against      |
| `VIRUSTOTAL_API_KEY`      | If set, hash-only VT pre-check (never uploads bytes)   |
| `VM_POOL_VMID_MIN/MAX`    | Proxmox vmid range for analysis clones (default 9100-9199) |
| `VM_POOL_STALE_LEASE_SECONDS` | Reap leases whose heartbeat is older than this     |

## Runtime dependencies

- PostgreSQL 15+ (JSONB GIN indices, `tsvector`)
- Redis 7+ (Celery broker)
- Proxmox VE 8+ (API token auth)
- Python 3.11+

## Status

Phases 1–3 complete: scaffold, host<->guest detonation protocol, analyzer,
intake service (HTTP API + VT hash pre-check + optional YARA scan), and the
DB-backed Proxmox VM pool manager with crash-safe lease reclamation.
Phase 4 is end-to-end orchestration testing against real Proxmox + Postgres.
