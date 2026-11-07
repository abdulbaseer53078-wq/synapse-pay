-- Registry events to Kafka (Task 2.9). audit_log is the transactional outbox: every registry event is written
-- there in the same transaction as the change, and the event relay publishes it to terminal.registry.events.
-- firmware_change rows carry firmware versions in from_status/to_status; health_change rows carry health states.

BEGIN;

-- Stable id per event, so consumers can drop the duplicates at-least-once delivery may produce.
ALTER TABLE audit_log ADD COLUMN event_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE;

-- How far the relay has published audit_log. Exactly one row.
CREATE TABLE event_outbox_cursor (
    singleton     BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    last_audit_id BIGINT NOT NULL
);
INSERT INTO event_outbox_cursor (last_audit_id) VALUES (0);

COMMIT;
