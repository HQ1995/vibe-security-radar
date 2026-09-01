CREATE TABLE IF NOT EXISTS ledger_change_sets (
    change_set_id text PRIMARY KEY,
    actor text NOT NULL,
    description text NOT NULL,
    source_assessment_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    committed_at timestamptz
);

CREATE TABLE IF NOT EXISTS ledger_rows (
    class_id text PRIMARY KEY,
    ordinal integer NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN (
        'UNANALYZED', 'PARTIALLY_ANALYZED', 'NOT_AI',
        'AI_ROOT_CAUSE', 'AI_CODE_FLAWED', 'BLOCKED', 'FALSE_POSITIVE'
    )),
    repo text,
    advisory_ids jsonb NOT NULL,
    raw_json text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    change_set_id text NOT NULL REFERENCES ledger_change_sets(change_set_id),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL
);

CREATE INDEX IF NOT EXISTS ledger_rows_status_idx ON ledger_rows(status);
CREATE INDEX IF NOT EXISTS ledger_rows_repo_idx ON ledger_rows(repo);
CREATE INDEX IF NOT EXISTS ledger_rows_advisory_ids_idx ON ledger_rows USING gin(advisory_ids);

CREATE TABLE IF NOT EXISTS ledger_versions (
    class_id text NOT NULL,
    revision bigint NOT NULL,
    change_set_id text NOT NULL REFERENCES ledger_change_sets(change_set_id),
    operation text NOT NULL CHECK (operation IN ('IMPORT', 'UPDATE')),
    raw_json text NOT NULL,
    checksum char(64) NOT NULL,
    source_assessment_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    actor text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (class_id, revision)
);

CREATE INDEX IF NOT EXISTS ledger_versions_change_set_idx
    ON ledger_versions(change_set_id);

ALTER TABLE ledger_change_sets
    ADD COLUMN IF NOT EXISTS source_assessment_ids jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE ledger_versions
    ADD COLUMN IF NOT EXISTS source_assessment_ids jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS ledger_display (
    kind text PRIMARY KEY,
    value_json jsonb NOT NULL,
    source text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    run_id text PRIMARY KEY,
    model_provider text NOT NULL,
    model_name text NOT NULL,
    model_version text NOT NULL,
    prompt_text text NOT NULL,
    prompt_hash char(64) NOT NULL CHECK (prompt_hash ~ '^[0-9a-f]{64}$'),
    scanner_version text NOT NULL,
    source_snapshot_sha256 char(64) NOT NULL
        CHECK (source_snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    actor text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE INDEX IF NOT EXISTS scan_runs_model_idx
    ON scan_runs(model_provider, model_name, model_version);

CREATE TABLE IF NOT EXISTS case_assessments (
    assessment_id text PRIMARY KEY,
    class_id text NOT NULL,
    run_id text NOT NULL REFERENCES scan_runs(run_id),
    base_ledger_revision bigint NOT NULL,
    base_row_checksum char(64) NOT NULL
        CHECK (base_row_checksum ~ '^[0-9a-f]{64}$'),
    verdict text NOT NULL,
    confidence double precision CHECK (
        confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
    ),
    reasoning text NOT NULL CHECK (length(reasoning) > 0),
    causal_chain jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    raw_output text NOT NULL,
    agent_id text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    supersedes_assessment_id text REFERENCES case_assessments(assessment_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (class_id, base_ledger_revision)
        REFERENCES ledger_versions(class_id, revision)
);

CREATE INDEX IF NOT EXISTS case_assessments_class_idx
    ON case_assessments(class_id, created_at);
CREATE INDEX IF NOT EXISTS case_assessments_run_idx
    ON case_assessments(run_id, created_at);

CREATE OR REPLACE FUNCTION reject_immutable_history_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'ledger_versions_append_only'
    ) THEN
        CREATE TRIGGER ledger_versions_append_only
            BEFORE UPDATE OR DELETE ON ledger_versions
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_history_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'case_assessments_append_only'
    ) THEN
        CREATE TRIGGER case_assessments_append_only
            BEFORE UPDATE OR DELETE ON case_assessments
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_history_mutation();
    END IF;
END
$$;

-- Expand the status domain in place for existing deployments. The CREATE
-- TABLE IF NOT EXISTS above keeps the in-file definition current for fresh
-- bootstraps; this ALTER makes already-bootstrapped databases match.
ALTER TABLE ledger_rows
    DROP CONSTRAINT IF EXISTS ledger_rows_status_check;
ALTER TABLE ledger_rows
    ADD CONSTRAINT ledger_rows_status_check
    CHECK (status IN (
        'UNANALYZED', 'PARTIALLY_ANALYZED', 'NOT_AI',
        'AI_ROOT_CAUSE', 'AI_CODE_FLAWED', 'BLOCKED', 'FALSE_POSITIVE'
    ));
