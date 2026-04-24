-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Bill Halpin
-- Cross-tool investigation context (GNAT-o-sphere).
--
-- Forward-only migration. Never edit after apply; add a new numbered file.
--
-- Adds three nullable columns to analysis_jobs so a GNAT investigation_id
-- can travel with a submission through intake -> detonation -> STIX bundle
-- -> export. The ID itself is an opaque string owned by GNAT; SandGNAT
-- treats it as a tag and never validates it against GNAT's API.
--
-- Shared contract lives in the GNAT repo at
-- docs/reference/investigation-context-schema.md.

BEGIN;

ALTER TABLE analysis_jobs
    ADD COLUMN investigation_id        TEXT,
    ADD COLUMN investigation_link_type TEXT
        CHECK (investigation_link_type IN ('confirmed', 'inferred', 'suggested'))
        DEFAULT 'confirmed',
    ADD COLUMN investigation_tenant_id TEXT;

-- Partial index: most rows will have NULL investigation_id, no point
-- indexing them. The ?investigation_id=... query on /analyses is the only
-- use case and it's always a present-value equality match.
CREATE INDEX idx_analysis_jobs_investigation_id
    ON analysis_jobs (investigation_id)
    WHERE investigation_id IS NOT NULL;

COMMIT;
