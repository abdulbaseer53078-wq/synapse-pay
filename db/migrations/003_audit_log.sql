-- Audit trail for terminal status changes (and, later, every admin action).

BEGIN;

CREATE TYPE audit_actor AS ENUM ('TERMINAL', 'MERCHANT', 'ADMIN', 'SYSTEM');

CREATE TABLE audit_log (
    audit_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type  audit_actor NOT NULL,
    actor_id    VARCHAR,          -- token subject; NULL for SYSTEM
    entity_type VARCHAR NOT NULL,
    entity_id   UUID NOT NULL,
    action      VARCHAR NOT NULL,
    from_status VARCHAR,
    to_status   VARCHAR,
    reason      VARCHAR
);
CREATE INDEX audit_log_entity_idx ON audit_log (entity_type, entity_id, occurred_at);

-- Append-only. shortcut: TRUNCATE and table owners can still bypass this; enforce with
-- DB roles (app role gets INSERT/SELECT only) when deployment roles are defined.
CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

COMMIT;
