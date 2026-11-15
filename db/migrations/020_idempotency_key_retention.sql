-- Flaw #9: idempotency_keys only grew, and its two scans read the whole table. The stuck-key sweep and the metrics
-- gauge look for state = 'IN_FLIGHT' by age; the retention purge (app/jobs.py, sweep) deletes state = 'DONE' by age.
-- One index serves both.

BEGIN;

CREATE INDEX idempotency_keys_state_created_idx ON idempotency_keys (state, created_at);

COMMIT;
