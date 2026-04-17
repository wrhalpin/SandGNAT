-- SandGNAT initial schema.
--
-- Forward-only migration. Never edit after apply; add a new numbered file.
--
-- Storage model:
--   * Raw STIX 2.1 JSON lives in JSONB columns with GIN indices.
--   * Hot query columns (name, hashes, type, analysis_id, confidence) are
--     extracted for index locality.
--   * `analysis_jobs` is the lifecycle root; everything joins back via
--     `analysis_id`.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Lifecycle root: one row per malware detonation.
-- ---------------------------------------------------------------------------
CREATE TABLE analysis_jobs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sample_hash_sha256   TEXT NOT NULL,
    sample_name          TEXT,
    sample_mime_type     TEXT,
    status               TEXT NOT NULL
                         CHECK (status IN ('queued','running','completed','failed','quarantined')),
    submitted_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at           TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,
    duration_seconds     INTEGER,
    vm_uuid              UUID,
    execution_command    TEXT,
    timeout_seconds      INTEGER NOT NULL DEFAULT 300,
    network_isolation    BOOLEAN NOT NULL DEFAULT TRUE,
    evasion_observed     BOOLEAN NOT NULL DEFAULT FALSE,
    analyst_notes        TEXT,
    result_summary       JSONB,
    quarantine_path      TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_jobs_sample_hash ON analysis_jobs (sample_hash_sha256);
CREATE INDEX idx_jobs_status      ON analysis_jobs (status);
CREATE INDEX idx_jobs_submitted   ON analysis_jobs (submitted_at DESC);

-- ---------------------------------------------------------------------------
-- STIX Malware SDOs — one per analysis, linking all observables/indicators.
-- ---------------------------------------------------------------------------
CREATE TABLE stix_malware (
    id                UUID PRIMARY KEY,
    analysis_id       UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    created           TIMESTAMPTZ NOT NULL,
    modified          TIMESTAMPTZ NOT NULL,
    name              TEXT,
    description       TEXT,
    malware_types     TEXT[] NOT NULL DEFAULT '{}',
    labels            TEXT[] NOT NULL DEFAULT ARRAY['malware']::TEXT[],
    object_refs       UUID[] NOT NULL DEFAULT '{}',
    confidence_level  SMALLINT CHECK (confidence_level BETWEEN 0 AND 100),
    stix_object       JSONB NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_malware_name     ON stix_malware (name);
CREATE INDEX idx_malware_analysis ON stix_malware (analysis_id);
CREATE INDEX idx_malware_stix_gin ON stix_malware USING GIN (stix_object);

-- ---------------------------------------------------------------------------
-- STIX Cyber Observables (SCOs): files, processes, network-traffic, etc.
-- ---------------------------------------------------------------------------
CREATE TABLE stix_observables (
    id                UUID PRIMARY KEY,
    analysis_id       UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    type              TEXT NOT NULL,
    name              TEXT,
    created           TIMESTAMPTZ,
    modified          TIMESTAMPTZ,
    parent_analysis   BOOLEAN NOT NULL DEFAULT FALSE,
    observable        JSONB NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_observable_type     ON stix_observables (type);
CREATE INDEX idx_observable_analysis ON stix_observables (analysis_id);
CREATE INDEX idx_observable_gin      ON stix_observables USING GIN (observable);

-- ---------------------------------------------------------------------------
-- STIX Indicators (SDOs) derived from observables.
-- ---------------------------------------------------------------------------
CREATE TABLE stix_indicators (
    id                 UUID PRIMARY KEY,
    analysis_id        UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    created            TIMESTAMPTZ NOT NULL,
    modified           TIMESTAMPTZ NOT NULL,
    pattern            TEXT NOT NULL,
    labels             TEXT[] NOT NULL DEFAULT '{}',
    kill_chain_phases  JSONB,
    confidence_level   SMALLINT CHECK (confidence_level BETWEEN 0 AND 100),
    observable_refs    UUID[] NOT NULL DEFAULT '{}',
    stix_object        JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_indicator_analysis   ON stix_indicators (analysis_id);
CREATE INDEX idx_indicator_confidence ON stix_indicators (confidence_level);
CREATE INDEX idx_indicator_pattern    ON stix_indicators (pattern);

-- ---------------------------------------------------------------------------
-- Dropped files: immutable audit trail for quarantined artifacts.
-- ---------------------------------------------------------------------------
CREATE TABLE dropped_files (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id               UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    filename                  TEXT,
    original_path             TEXT,
    size_bytes                BIGINT,
    hash_sha256               TEXT NOT NULL,
    hash_md5                  TEXT,
    quarantine_path           TEXT,
    ingestion_timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified                  BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_process_name   TEXT,
    created_by_process_pid    INTEGER,
    created_by_malware_ref    UUID REFERENCES stix_malware(id) ON DELETE SET NULL
);

CREATE INDEX idx_dropped_hash      ON dropped_files (hash_sha256);
CREATE INDEX idx_dropped_analysis  ON dropped_files (analysis_id);
CREATE INDEX idx_dropped_timestamp ON dropped_files (ingestion_timestamp);

-- ---------------------------------------------------------------------------
-- Registry modifications (RegShot-derived).
-- ---------------------------------------------------------------------------
CREATE TABLE registry_modifications (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id             UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    action                  TEXT NOT NULL CHECK (action IN ('added','modified','deleted')),
    hive                    TEXT,
    key_path                TEXT,
    value_name              TEXT,
    value_data              TEXT,
    value_type              TEXT,
    observed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    persistence_indicator   BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_process_ref  UUID REFERENCES stix_observables(id) ON DELETE SET NULL
);

CREATE INDEX idx_registry_analysis    ON registry_modifications (analysis_id);
CREATE INDEX idx_registry_persistence ON registry_modifications (persistence_indicator);
CREATE INDEX idx_registry_key         ON registry_modifications (key_path);

-- ---------------------------------------------------------------------------
-- Network IOCs (Wireshark / INetSim derived).
-- ---------------------------------------------------------------------------
CREATE TABLE network_iocs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id          UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    type                 TEXT NOT NULL CHECK (type IN ('ipv4','ipv6','domain','url','dns_query')),
    indicator            TEXT NOT NULL,
    direction            TEXT CHECK (direction IN ('inbound','outbound')),
    protocol             TEXT,
    port                 INTEGER,
    observed_at          TIMESTAMPTZ,
    context              TEXT,
    confirmed_malicious  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_network_ioc_analysis  ON network_iocs (analysis_id);
CREATE INDEX idx_network_ioc_indicator ON network_iocs (indicator);
CREATE INDEX idx_network_ioc_type      ON network_iocs (type);

-- ---------------------------------------------------------------------------
-- Audit log (append-only).
-- ---------------------------------------------------------------------------
CREATE TABLE analysis_audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id   UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    event_type    TEXT NOT NULL,
    details       JSONB,
    actor         TEXT NOT NULL DEFAULT 'system',
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_analysis  ON analysis_audit_log (analysis_id);
CREATE INDEX idx_audit_occurred  ON analysis_audit_log (occurred_at DESC);

-- ---------------------------------------------------------------------------
-- Optional full-text search sidecar for IOCs.
-- ---------------------------------------------------------------------------
CREATE TABLE ioc_fts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id   UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    ioc_text      TEXT NOT NULL,
    ioc_type      TEXT,
    ioc_tsvector  TSVECTOR,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ioc_fts_gin ON ioc_fts USING GIN (ioc_tsvector);

CREATE OR REPLACE FUNCTION update_ioc_tsvector() RETURNS TRIGGER AS $$
BEGIN
    NEW.ioc_tsvector := to_tsvector('english', COALESCE(NEW.ioc_text, ''));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ioc_fts_update
    BEFORE INSERT OR UPDATE ON ioc_fts
    FOR EACH ROW EXECUTE FUNCTION update_ioc_tsvector();

COMMIT;
