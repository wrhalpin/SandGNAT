# Tutorial 02 — Stand up a local dev stack

By the end: Postgres + Redis running, SandGNAT's intake API accepting
submissions, Celery worker ready to pick them up. **No Proxmox, no
Windows, no Linux guest VMs — you'll mock them out.** This is the
setup for code development and for working through the other
tutorials.

Estimated time: 15 minutes.

## What you'll need

- Python 3.11+
- Docker (for Postgres + Redis — easiest path)
- ~1 GB of free disk space

## Step 1 — Clone and install

```bash
git clone https://github.com/wrhalpin/SandGNAT
cd SandGNAT
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

If you get a psycopg build error, you probably need libpq-dev:

```bash
# Debian/Ubuntu
sudo apt-get install libpq-dev
# macOS
brew install postgresql
```

## Step 2 — Start Postgres and Redis

The simplest way is Docker containers:

```bash
docker run -d --name sandgnat-postgres \
    -e POSTGRES_USER=sandgnat \
    -e POSTGRES_PASSWORD=sandgnat \
    -e POSTGRES_DB=sandgnat \
    -p 5432:5432 \
    postgres:16

docker run -d --name sandgnat-redis \
    -p 6379:6379 \
    redis:7
```

Both containers are throw-away dev fixtures. `docker rm -f` them when
you're done.

## Step 3 — Apply migrations

```bash
export DATABASE_URL=postgresql://sandgnat:sandgnat@localhost:5432/sandgnat
psql "$DATABASE_URL" -f migrations/001_initial_schema.sql
psql "$DATABASE_URL" -f migrations/002_intake_and_vm_pool.sql
psql "$DATABASE_URL" -f migrations/003_static_analysis.sql
```

Verify:

```bash
psql "$DATABASE_URL" -c "\dt"
```

You should see `analysis_jobs`, `static_analysis`, `sample_trigrams`,
and the other Phase 4 tables.

## Step 4 — Set the env

Create `.env` in the repo root (or export these directly in your
shell):

```bash
export DATABASE_URL=postgresql://sandgnat:sandgnat@localhost:5432/sandgnat
export CELERY_BROKER_URL=redis://localhost:6379/0
export CELERY_RESULT_BACKEND=redis://localhost:6379/1
export INTAKE_API_KEY=dev-key-not-for-production
export QUARANTINE_ROOT=/tmp/sandgnat/quarantine
export ARTIFACT_STAGING_ROOT=/tmp/sandgnat/staging

# Required by the import path but not used in this dev stack —
# placeholders are fine because Proxmox is never called.
export PROXMOX_HOST=placeholder
export PROXMOX_TOKEN_NAME=placeholder
export PROXMOX_TOKEN_VALUE=placeholder
export PROXMOX_NODE=placeholder

# Keep static analysis off — we don't have the Linux guest running.
export STATIC_ANALYSIS_ENABLED=0

# Create the staging dirs.
mkdir -p /tmp/sandgnat/staging /tmp/sandgnat/quarantine
```

## Step 5 — Run the tests

Full suite runs offline and proves your install is correct:

```bash
pytest
```

Expect **141 passed** (or more, if the project moved on). Any failure
here is a setup issue to fix before going further.

## Step 6 — Start the intake service

In one terminal:

```bash
python -m orchestrator.intake_server
```

You should see Flask's dev-server output plus an INFO log about the
intake routes. Leave this running.

In another terminal, hit `/healthz`:

```bash
curl -sS http://localhost:8080/healthz
# {"status": "ok"}
```

Submit a tiny dummy sample:

```bash
echo -n "this is a fake sample for dev" > /tmp/fake.bin
curl -sS \
    -H "X-API-Key: $INTAKE_API_KEY" \
    -F "file=@/tmp/fake.bin" \
    http://localhost:8080/submit
```

Response:

```json
{
  "decision": "queued",
  "analysis_id": "...",
  "sha256": "...",
  "size_bytes": 29,
  ...
}
```

Save the `analysis_id` — you'll use it in a moment.

## Step 7 — Start a Celery worker (optional for dev)

If you don't care about actually running the task (most dev work
doesn't — you're testing intake, parsers, STIX factories, etc.), skip
this. The row sits in `analysis_jobs` with `status='queued'` and
that's fine.

If you **do** want to drive the task:

```bash
# In another terminal:
celery -A orchestrator.celery_app worker --loglevel=INFO --queues=analysis
```

The task will pick up the job and immediately fail because the
"Proxmox" placeholder isn't a real host. That's expected. The row
will end up `status='failed'` — which is still useful feedback for
development.

## Step 8 — Poll the export API

```bash
# List every analysis you've submitted:
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
    http://localhost:8080/analyses | jq '.items[] | {id, status, sha: .sample_hash_sha256}'

# Get one by id:
curl -sS -H "X-API-Key: $INTAKE_API_KEY" \
    http://localhost:8080/analyses/<id> | jq '.'
```

If no Celery worker ran, status is `queued`. If the worker ran and
hit the Proxmox placeholder, status is `failed` — either way, the
full API surface is available.

## Step 9 — Clean up

When you're done for the day:

```bash
# Stop the intake service (Ctrl-C in its terminal).
# Stop the Celery worker (Ctrl-C in its terminal).

# Tear down the databases:
docker rm -f sandgnat-postgres sandgnat-redis

# Clean up the staging dirs:
rm -rf /tmp/sandgnat
```

To restart tomorrow: `docker start sandgnat-postgres sandgnat-redis`
(keep the containers around and re-use them).

## What you've accomplished

- A running intake service accepting authenticated submissions.
- A Postgres with the full SandGNAT schema applied.
- Redis ready for Celery tasks.
- The full offline test suite passing locally.

You can now:

- Write a new parser and unit-test it against fixtures — see
  [how-to/add-a-parser.md](../how-to/add-a-parser.md).
- Develop against the export API — see
  [how-to/query-export-api.md](../how-to/query-export-api.md).
- Walk through a completed-analysis flow — see
  [tutorial 03](03-force-reanalysis.md).

## Troubleshooting

- **Flask says "INTAKE_API_KEY is not set; refusing to start"** —
  export the env var in the same terminal you're launching the
  service from.
- **psycopg `FATAL: password authentication failed`** — the container
  init ran with different creds than your `DATABASE_URL` expects.
  `docker rm -f` and start fresh with the env vars above.
- **Celery worker logs "Unregistered task"** — you're running an old
  binary. `pip install -e .` in the same venv the worker uses.
- **The dev server says "Address already in use"** — something else
  is on port 8080. Set `INTAKE_BIND_PORT=8090` or pick another.
