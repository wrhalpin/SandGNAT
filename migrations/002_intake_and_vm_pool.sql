-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Bill Halpin
-- SandGNAT migration 002: intake metadata + VM pool leases.
--
-- Forward-only. Never edit after apply; add a new numbered file.
--
-- Phase 3 adds two concerns to the schema:
--   1. Intake pre-check results (VT hash lookup, YARA matches, submitter, priority).
--      These travel with the job row because an analyst looking at an analysis
--      wants to know "why was this even detonated?" alongside the behavioural
--      findings.
--   2. A DB-backed VM lease table so the orchestrator can allocate vmids from
--      a configured range without races across workers, and can recover
--      orphaned leases after a worker crash.

BEGIN;

-- ---------------------------------------------------------------------------
-- Intake metadata on analysis_jobs.
-- ---------------------------------------------------------------------------
ALTER TABLE analysis_jobs
    ADD COLUMN sample_hash_md5        TEXT,
    ADD COLUMN sample_hash_sha1       TEXT,
    ADD COLUMN sample_size_bytes      BIGINT,
    ADD COLUMN submitter              TEXT,
    ADD COLUMN intake_source          TEXT,
    ADD COLUMN intake_decision        TEXT
        CHECK (intake_decision IN ('queued','duplicate','rejected','prioritized')),
    ADD COLUMN intake_notes           TEXT,
    ADD COLUMN priority               SMALLINT NOT NULL DEFAULT 5
        CHECK (priority BETWEEN 0 AND 9),
    ADD COLUMN vt_verdict             TEXT
        CHECK (vt_verdict IN ('malicious','suspicious','harmless','undetected','unknown','error')),
    ADD COLUMN vt_detection_count     INTEGER,
    ADD COLUMN vt_total_engines       INTEGER,
    ADD COLUMN vt_last_seen           TIMESTAMPTZ,
    ADD COLUMN yara_matches           TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX idx_jobs_priority  ON analysis_jobs (priority);
CREATE INDEX idx_jobs_intake    ON analysis_jobs (intake_decision);
CREATE INDEX idx_jobs_md5       ON analysis_jobs (sample_hash_md5);
CREATE INDEX idx_jobs_yara_gin  ON analysis_jobs USING GIN (yara_matches);

-- ---------------------------------------------------------------------------
-- VM pool leases.
--
-- Each row tracks one vmid in the configured pool range. `status` advances
-- leased -> released on graceful cleanup, or leased -> orphaned when a
-- reaper notices a stale heartbeat. Acquisition is a single atomic UPSERT:
--
--   INSERT ... ON CONFLICT (vmid) DO UPDATE
--     WHERE status IN ('released','orphaned') OR heartbeat is stale
--
-- so the row doubles as the lock.
-- ---------------------------------------------------------------------------
CREATE TABLE vm_pool_leases (
    vmid          INTEGER PRIMARY KEY,
    node          TEXT NOT NULL,
    analysis_id   UUID REFERENCES analysis_jobs(id) ON DELETE SET NULL,
    status        TEXT NOT NULL
                  CHECK (status IN ('leased','released','orphaned')),
    acquired_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    heartbeat_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at   TIMESTAMPTZ
);

CREATE INDEX idx_pool_status     ON vm_pool_leases (status);
CREATE INDEX idx_pool_heartbeat  ON vm_pool_leases (heartbeat_at)
    WHERE status = 'leased';
CREATE INDEX idx_pool_analysis   ON vm_pool_leases (analysis_id);

-- At most one active lease per analysis_id (a job shouldn't hold two VMs).
CREATE UNIQUE INDEX uq_pool_active_analysis
    ON vm_pool_leases (analysis_id)
    WHERE status = 'leased' AND analysis_id IS NOT NULL;

COMMIT;
