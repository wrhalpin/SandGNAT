# Configuration reference

Every runtime knob lives in an env var read by `orchestrator/config.py`.
Nothing is hard-coded. Services refuse to start if any `required=True`
variable is unset.

Canonical source: `orchestrator/config.py`.

## Core

| Variable                   | Default                      | Required | Purpose                                 |
|----------------------------|------------------------------|----------|-----------------------------------------|
| `DATABASE_URL`             | —                            | ✅       | Postgres DSN for the orchestrator       |
| `CELERY_BROKER_URL`        | `redis://localhost:6379/0`   |          | Celery broker                           |
| `CELERY_RESULT_BACKEND`    | `redis://localhost:6379/1`   |          | Celery results backend                  |
| `ANALYSIS_NETWORK_CIDR`    | `192.168.100.0/24`           |          | Analysis-bridge CIDR (used for IOC classification) |
| `QUARANTINE_ROOT`          | `/srv/sandgnat/quarantine`   |          | Where dropped files are moved after ingestion |
| `ARTIFACT_STAGING_ROOT`    | `/srv/sandgnat/staging`      |          | SMB/NFS staging share root              |
| `ANALYSIS_DEFAULT_TIMEOUT` | `300`                        |          | Detonation timeout in seconds           |
| `MAX_CONCURRENT_ANALYSES`  | `4`                          |          | Upper bound for the Postgres pool sizing |

## Proxmox

| Variable                 | Default     | Required | Purpose                              |
|--------------------------|-------------|----------|--------------------------------------|
| `PROXMOX_HOST`           | —           | ✅       | Proxmox API host                     |
| `PROXMOX_USER`           | `root@pam`  |          | API user                             |
| `PROXMOX_TOKEN_NAME`     | —           | ✅       | API token name                       |
| `PROXMOX_TOKEN_VALUE`    | —           | ✅       | API token value                      |
| `PROXMOX_VERIFY_SSL`     | `true`      |          | TLS verification                     |
| `PROXMOX_NODE`           | —           | ✅       | Proxmox node to place VMs on         |
| `PROXMOX_TEMPLATE_VMID`  | `9000`      |          | Windows template vmid                |
| `PROXMOX_CLEAN_SNAPSHOT` | `clean`     |          | Snapshot name to revert to           |

## Windows VM pool

| Variable                          | Default | Purpose                           |
|-----------------------------------|---------|-----------------------------------|
| `VM_POOL_VMID_MIN`                | `9100`  | First vmid in Windows pool range  |
| `VM_POOL_VMID_MAX`                | `9199`  | Last vmid in Windows pool range   |
| `VM_POOL_STALE_LEASE_SECONDS`     | `1800`  | Reap leases older than this       |

## Linux VM pool (static-analysis stage)

| Variable                                | Default | Purpose                          |
|-----------------------------------------|---------|----------------------------------|
| `LINUX_VM_POOL_VMID_MIN`                | `9200`  | First vmid in Linux pool range   |
| `LINUX_VM_POOL_VMID_MAX`                | `9299`  | Last vmid in Linux pool range    |
| `LINUX_TEMPLATE_VMID`                   | `9001`  | Linux template vmid              |
| `LINUX_CLEAN_SNAPSHOT`                  | `clean` | Linux template snapshot name     |
| `LINUX_VM_POOL_STALE_LEASE_SECONDS`     | `600`   | Reap stale Linux leases          |

## Static analysis

| Variable                              | Default  | Purpose                                       |
|---------------------------------------|----------|-----------------------------------------------|
| `STATIC_ANALYSIS_ENABLED`             | `false`  | Route intake through the static stage first    |
| `STATIC_SHORT_CIRCUIT_THRESHOLD`      | `0.85`   | Jaccard threshold for near-duplicate skip     |
| `STATIC_SHORT_CIRCUIT_FLAVOUR`        | `either` | `byte` / `opcode` / `either`                  |
| `STATIC_ANALYSIS_TIMEOUT`             | `240`    | Static-stage timeout in seconds               |
| `STATIC_YARA_DEEP_RULES_DIR`          | `""`     | Directory of `.yar` files for the deep scan   |

## Intake HTTP service

| Variable                   | Default                  | Required | Purpose                           |
|----------------------------|--------------------------|----------|-----------------------------------|
| `INTAKE_API_KEY`           | —                        | ✅ (to start service) | Shared secret for `X-API-Key` header |
| `INTAKE_BIND_HOST`         | `127.0.0.1`              |          | Flask bind address                |
| `INTAKE_BIND_PORT`         | `8080`                   |          | Flask bind port                   |
| `INTAKE_MAX_SAMPLE_BYTES`  | `134217728` (128 MiB)    |          | Hard upload-size cap              |
| `INTAKE_MIN_SAMPLE_BYTES`  | `16`                     |          | Reject anything smaller           |
| `INTAKE_YARA_RULES_DIR`    | `""`                     |          | Directory of intake-time YARA rules |
| `VIRUSTOTAL_API_KEY`       | `""`                     |          | If set, enable VT hash lookup     |
| `VIRUSTOTAL_BASE_URL`      | `https://www.virustotal.com/api/v3` |    | VT v3 base URL                    |
| `VIRUSTOTAL_TIMEOUT_SECONDS` | `10`                   |          | VT request timeout                |

## Linux guest agent

Set these on the Linux static-analysis guest, not on the orchestrator.

| Variable                              | Default                       | Purpose                         |
|---------------------------------------|-------------------------------|---------------------------------|
| `LINUX_GUEST_STAGING_ROOT`            | `/srv/sandgnat/staging`       | Where the SMB share is mounted  |
| `LINUX_GUEST_POLL_INTERVAL`           | `2.0`                         | Watcher poll interval, seconds  |
| `LINUX_GUEST_CAPA_EXE`                | `capa`                        | Path to the CAPA binary         |
| `LINUX_GUEST_YARA_DEEP_RULES_DIR`     | `""`                          | Deep YARA rules on the guest    |
| `LINUX_GUEST_MAX_STRINGS_BYTES`       | `1048576`                     | Cap on strings kept in envelope |

## Security posture

- `INTAKE_API_KEY` must be set before `intake_server` starts. The factory
  raises `RuntimeError` otherwise — no unauthenticated intake, ever.
- `VIRUSTOTAL_API_KEY` is optional. When unset, VT lookups short-circuit
  to "unknown"; samples never leave the box. We **never upload samples**
  to VT regardless of configuration.
- `PROXMOX_VERIFY_SSL` defaults to `true`. Set to `false` only in a
  well-understood lab; self-signed Proxmox certs are the common reason.

## Examples

### Minimal orchestrator `.env`

```bash
DATABASE_URL=postgresql://sandgnat:***@pg.internal:5432/sandgnat
CELERY_BROKER_URL=redis://redis.internal:6379/0
PROXMOX_HOST=proxmox.internal
PROXMOX_TOKEN_NAME=sandgnat
PROXMOX_TOKEN_VALUE=***
PROXMOX_NODE=pve1

INTAKE_API_KEY=some-long-opaque-string
QUARANTINE_ROOT=/srv/sandgnat/quarantine
ARTIFACT_STAGING_ROOT=/srv/sandgnat/staging
```

### Enable the static pre-stage

```bash
STATIC_ANALYSIS_ENABLED=1
STATIC_SHORT_CIRCUIT_THRESHOLD=0.85
STATIC_YARA_DEEP_RULES_DIR=/etc/sandgnat/yara-deep
LINUX_TEMPLATE_VMID=9001
```

### Enable VT pre-check

```bash
VIRUSTOTAL_API_KEY=xxxxxxxx...
```

### Dev / local stack

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/sandgnat
CELERY_BROKER_URL=redis://localhost:6379/0
INTAKE_API_KEY=dev-key-not-for-production
QUARANTINE_ROOT=/tmp/sandgnat/quarantine
ARTIFACT_STAGING_ROOT=/tmp/sandgnat/staging
# Proxmox vars still required to import the module; use placeholders:
PROXMOX_HOST=localhost
PROXMOX_TOKEN_NAME=dev
PROXMOX_TOKEN_VALUE=dev
PROXMOX_NODE=dev
```

See [tutorials/02-local-dev-stack.md](../tutorials/02-local-dev-stack.md)
for the full dev setup.
