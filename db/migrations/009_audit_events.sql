-- Step 7: the append-only audit log gets a universal face.
--
-- Nothing about the existing trail changes: audit_log stays the one append-only table, written in the same
-- transaction as the change it records (the transactional outbox). This migration adds what the universal
-- event stream needs on top of it, plus the hash chain, the WORM index and the verification ledger.
--
-- audit_log remains the source of truth for *what happened*; audit_events is a derived, chained index of it
-- (and can be rebuilt from WORM storage). The chain is what makes tampering detectable.

BEGIN;

-- A correlation id ties every event of one business action together across components: a transaction id for
-- payments, a terminal id for registry changes. Defaulted at insert so producers keep writing as they do now.
ALTER TABLE audit_log ADD COLUMN correlation_id VARCHAR;
ALTER TABLE audit_log ADD COLUMN payload JSONB NOT NULL DEFAULT '{}';

-- The append-only trigger blocks UPDATE, which is the point. This one backfill is the sanctioned exception:
-- rows written before this migration have no correlation id, and it is derivable from entity_id.
ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;
UPDATE audit_log SET correlation_id = entity_id::text WHERE correlation_id IS NULL;
ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;

CREATE FUNCTION audit_log_default_correlation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.correlation_id IS NULL THEN
        NEW.correlation_id := NEW.entity_id::text;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER audit_log_default_correlation BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_default_correlation();

-- Support's main query: "show me everything for this transaction, oldest first."
CREATE INDEX audit_log_correlation_idx ON audit_log (correlation_id, audit_id);

-- The chained, queryable projection of audit_log. `sequence` is the chain position: 1, 2, 3 ... with no gaps.
CREATE TABLE audit_events (
    sequence       BIGINT PRIMARY KEY,
    event_id       UUID NOT NULL UNIQUE,
    occurred_at    TIMESTAMPTZ NOT NULL,
    event_type     VARCHAR NOT NULL,
    actor          VARCHAR NOT NULL,
    entity_id      VARCHAR NOT NULL,
    correlation_id VARCHAR NOT NULL,
    payload        JSONB NOT NULL,
    prev_hash      CHAR(64) NOT NULL,
    hash           CHAR(64) NOT NULL,
    worm_key       TEXT NOT NULL,          -- the immutable object that holds this record
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_correlation_idx ON audit_events (correlation_id, sequence);
CREATE INDEX audit_events_entity_idx ON audit_events (entity_id, sequence);
CREATE INDEX audit_events_type_idx ON audit_events (event_type, sequence);
CREATE INDEX audit_events_time_idx ON audit_events (occurred_at);

-- Append-only, like audit_log. Deleting a chained row would put a hole in the sequence; the verifier would
-- catch it, but the database should refuse in the first place.
CREATE FUNCTION audit_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

-- One row: the head of the chain and how far audit_log has been ingested. The ingester locks it FOR UPDATE,
-- so exactly one chain is built at a time and sequence numbers never interleave.
CREATE TABLE audit_chain_head (
    singleton     BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    last_sequence BIGINT NOT NULL,
    last_hash     CHAR(64) NOT NULL,
    last_audit_id BIGINT NOT NULL
);
INSERT INTO audit_chain_head (last_sequence, last_hash, last_audit_id)
    VALUES (0, repeat('0', 64), 0);

-- How far the Kafka fan-out has published (Step 7.2). Separate cursor: publishing must not gate ingestion.
CREATE TABLE audit_publish_cursor (
    singleton        BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    last_sequence    BIGINT NOT NULL
);
INSERT INTO audit_publish_cursor (last_sequence) VALUES (0);

-- Every integrity verification run (Step 7.7), so a gap in the hourly schedule is visible too.
CREATE TABLE audit_verification_runs (
    run_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at      TIMESTAMPTZ NOT NULL,
    finished_at     TIMESTAMPTZ,
    events_checked  BIGINT,
    chain_head      BIGINT,
    status          VARCHAR NOT NULL CHECK (status IN ('OK', 'TAMPERED', 'ERROR')),
    detail          VARCHAR
);

COMMIT;
