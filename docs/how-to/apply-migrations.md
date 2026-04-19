# How to apply database migrations

SandGNAT migrations are plain forward-only SQL files in `migrations/`.
There is no migration runner — you apply them with `psql` in order,
once per environment.

## Apply a fresh database

```bash
psql "$DATABASE_URL" -f migrations/001_initial_schema.sql
psql "$DATABASE_URL" -f migrations/002_intake_and_vm_pool.sql
psql "$DATABASE_URL" -f migrations/003_static_analysis.sql
```

Each file is wrapped in `BEGIN; ... COMMIT;` so a failure during apply
rolls back cleanly.

## Apply one new migration to an existing database

```bash
psql "$DATABASE_URL" -f migrations/004_whatever_comes_next.sql
```

There's no bookkeeping table ("schema_migrations" style). Keep track
of which migration you last applied in your deploy tooling /
runbooks — or check the schema directly (e.g. `\d analysis_jobs`
tells you whether 002 and 003 landed).

## Adding a new migration

1. Pick the next unused number. Files are `NNN_description.sql`,
   zero-padded to 3 digits.
2. Wrap the body in `BEGIN; ... COMMIT;`.
3. Use `CREATE ... IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` only
   when you need idempotency. SandGNAT's existing migrations do not —
   they assume a clean apply.
4. **Never edit an applied migration.** If 003 has already landed in
   any environment, fix-forward with a 004 — don't rewrite history.
5. Add the new file to `docs/how-to/apply-migrations.md` (this
   document) and any scripts that list migrations.

## Backing up before migrations

For production, always capture a physical backup before applying a
migration:

```bash
# Point-in-time capture of the whole database.
pg_dump --format=custom --file=pre-004.dump "$DATABASE_URL"

# Apply the migration.
psql "$DATABASE_URL" -f migrations/004_new_thing.sql

# On disaster, restore:
# pg_restore --clean --if-exists -d "$DATABASE_URL" pre-004.dump
```

The dump is cheap (~100 MB per million STIX objects after JSONB
compression) and has saved us at least once.

## Checking applied state

If you're unsure whether a migration was applied, look at its table
additions directly. Examples:

- 001 applied if `analysis_jobs` exists:
  ```sql
  SELECT 1 FROM information_schema.tables WHERE table_name='analysis_jobs';
  ```
- 002 applied if `vm_pool_leases` exists.
- 003 applied if `static_analysis` exists AND `analysis_jobs.imphash`
  column exists.

## Failure modes

- **Permission denied** — the DB user needs `CREATE TABLE`, `CREATE
  INDEX`, `ALTER TABLE`, and `USAGE` on the schema. The SandGNAT
  runtime user needs `SELECT/INSERT/UPDATE`. Use a separate DDL user
  for migrations; the runtime user stays minimally privileged.
- **Extension missing** — 001 requires `pgcrypto` for
  `gen_random_uuid()`. `CREATE EXTENSION IF NOT EXISTS pgcrypto`
  lives in 001 but requires `SUPERUSER` on some managed Postgres
  flavours (RDS, Cloud SQL). If so, create the extension manually as
  superuser before running 001.
- **Migration halfway applied** — the `BEGIN/COMMIT` wrapper means
  this shouldn't happen with vanilla `psql`. If you used a tool that
  split statements, roll back the whole schema and start over (or
  hand-reverse the partial apply, which is usually harder).

## Rolling back

There is no `down` migration. Rollback is either:

- Restore from `pg_dump` — clean but drops all data written after the
  backup.
- Hand-write a compensating SQL file that undoes the change. Commit
  it as `NNN_revert_MMM_description.sql` (forward-only even for
  rollbacks).

Most of the time, fix-forward is the correct answer.
