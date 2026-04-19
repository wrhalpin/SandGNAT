-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Bill Halpin
-- SandGNAT migration 003: Linux static-analysis stage + trigram similarity.
--
-- Forward-only. Never edit after apply; add a new numbered file.
--
-- Phase 4 adds a pre-detonation static-analysis stage that runs in a
-- dedicated Linux guest VM. The host:
--   * persists structured static findings (PE/ELF, imports, sections,
--     strings, entropy, deep-YARA matches, CAPA capabilities) per analysis;
--   * stores per-sample MinHash signatures (byte trigrams over executable
--     sections, opcode trigrams from capstone disassembly) plus their LSH
--     bands so future submissions can be clustered with O(candidates)
--     work instead of O(N);
--   * tracks lineage when a new submission is short-circuited as a
--     near-duplicate of a prior analysis (no re-detonation, but the new
--     analysis_id is linked back to the parent's STIX bundle).

BEGIN;

-- ---------------------------------------------------------------------------
-- analysis_jobs: static fingerprint + near-duplicate bookkeeping.
-- ---------------------------------------------------------------------------
ALTER TABLE analysis_jobs
    ADD COLUMN imphash               TEXT,
    ADD COLUMN ssdeep                TEXT,
    ADD COLUMN tlsh                  TEXT,
    ADD COLUMN static_completed_at   TIMESTAMPTZ,
    ADD COLUMN near_duplicate_of     UUID REFERENCES analysis_jobs(id) ON DELETE SET NULL,
    ADD COLUMN near_duplicate_score  NUMERIC(4,3)
        CHECK (near_duplicate_score IS NULL
               OR near_duplicate_score BETWEEN 0 AND 1);

CREATE INDEX idx_jobs_imphash          ON analysis_jobs (imphash);
CREATE INDEX idx_jobs_near_duplicate   ON analysis_jobs (near_duplicate_of)
    WHERE near_duplicate_of IS NOT NULL;

-- Allow the intake_decision to record short-circuit outcomes too.
ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_intake_decision_check;
ALTER TABLE analysis_jobs
    ADD CONSTRAINT analysis_jobs_intake_decision_check
    CHECK (intake_decision IN
           ('queued','duplicate','rejected','prioritized','near_duplicate'));

-- ---------------------------------------------------------------------------
-- vm_pool_leases: discriminate Windows vs Linux guests.
-- ---------------------------------------------------------------------------
ALTER TABLE vm_pool_leases
    ADD COLUMN guest_type TEXT NOT NULL DEFAULT 'windows'
        CHECK (guest_type IN ('windows','linux'));

CREATE INDEX idx_pool_guest_type ON vm_pool_leases (guest_type, status);

-- ---------------------------------------------------------------------------
-- Static-analysis findings (one row per analysis_id).
-- ---------------------------------------------------------------------------
CREATE TABLE static_analysis (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id           UUID NOT NULL UNIQUE
                          REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    file_format           TEXT,           -- 'pe32', 'pe64', 'elf32', 'elf64'
    architecture          TEXT,           -- 'x86', 'x86_64', 'aarch64', 'arm'
    entry_point           BIGINT,
    is_packed_heuristic   BOOLEAN,
    section_count         INTEGER,
    overall_entropy       NUMERIC(5,3),
    imports               JSONB,          -- {dll: [funcs]} for PE; [{lib, sym}] for ELF
    exports               JSONB,
    sections              JSONB,          -- [{name, vsize, rsize, entropy, flags}, ...]
    strings_summary       JSONB,          -- {ascii_count, utf16_count, urls, ips, registry_keys}
    capa_capabilities     JSONB,          -- normalised CAPA output
    deep_yara_matches     TEXT[] NOT NULL DEFAULT '{}',
    raw_envelope          JSONB NOT NULL, -- full guest envelope for forensic recovery
    completed_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_static_analysis_id   ON static_analysis (analysis_id);
CREATE INDEX idx_static_format        ON static_analysis (file_format);
CREATE INDEX idx_static_imports_gin   ON static_analysis USING GIN (imports);
CREATE INDEX idx_static_capa_gin      ON static_analysis USING GIN (capa_capabilities);
CREATE INDEX idx_static_yara_gin      ON static_analysis USING GIN (deep_yara_matches);

-- ---------------------------------------------------------------------------
-- Sample trigrams: full MinHash signatures (byte + optional opcode).
-- ---------------------------------------------------------------------------
--
-- byte_minhash and opcode_minhash are fixed-size little-endian uint32 arrays
-- packed as BYTEA: 128 permutations * 4 bytes = 512 bytes each. Storing the
-- full signature here lets us compute exact Jaccard estimates against any
-- candidate produced by the bands table.
CREATE TABLE sample_trigrams (
    analysis_id           UUID PRIMARY KEY
                          REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    sample_sha256         TEXT NOT NULL,
    signature_version     SMALLINT NOT NULL DEFAULT 1,
    byte_minhash          BYTEA NOT NULL,
    byte_trigram_count    INTEGER NOT NULL,
    opcode_minhash        BYTEA,
    opcode_trigram_count  INTEGER,
    extracted_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_trigrams_sha256  ON sample_trigrams (sample_sha256);
CREATE INDEX idx_trigrams_version ON sample_trigrams (signature_version);

-- ---------------------------------------------------------------------------
-- LSH bands: one row per (analysis, flavour, band_index). Index on
-- (flavour, band_index, band_value) is the heart of the candidate query.
-- ---------------------------------------------------------------------------
CREATE TABLE sample_minhash_bands (
    analysis_id   UUID NOT NULL
                  REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    flavour       TEXT NOT NULL CHECK (flavour IN ('byte','opcode')),
    band_index    SMALLINT NOT NULL,
    band_value    BYTEA NOT NULL,
    PRIMARY KEY (analysis_id, flavour, band_index)
);

CREATE INDEX idx_bands_lookup
    ON sample_minhash_bands (flavour, band_index, band_value);

-- ---------------------------------------------------------------------------
-- Pairwise similarity edges (cached). Canonical ordering: left < right.
-- ---------------------------------------------------------------------------
CREATE TABLE sample_similarity (
    left_analysis_id   UUID NOT NULL
                       REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    right_analysis_id  UUID NOT NULL
                       REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    flavour            TEXT NOT NULL CHECK (flavour IN ('byte','opcode')),
    similarity_score   NUMERIC(4,3) NOT NULL
                       CHECK (similarity_score BETWEEN 0 AND 1),
    computed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (left_analysis_id, right_analysis_id, flavour),
    CHECK (left_analysis_id < right_analysis_id)
);

CREATE INDEX idx_similarity_left
    ON sample_similarity (left_analysis_id, similarity_score DESC);
CREATE INDEX idx_similarity_right
    ON sample_similarity (right_analysis_id, similarity_score DESC);

-- ---------------------------------------------------------------------------
-- Lineage edges: when a job is short-circuited as a near-duplicate, we
-- record the relation here so analysts can query "what depends on X?"
-- without scanning analysis_jobs.near_duplicate_of by hand.
-- ---------------------------------------------------------------------------
CREATE TABLE analysis_lineage (
    child_analysis_id   UUID PRIMARY KEY
                        REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    parent_analysis_id  UUID NOT NULL
                        REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    relation            TEXT NOT NULL
                        CHECK (relation IN ('near_duplicate','reanalysis','manual_link')),
    similarity_score    NUMERIC(4,3),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_lineage_parent ON analysis_lineage (parent_analysis_id);

COMMIT;
