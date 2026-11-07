-- Query API (Task 2.7): merchants page through their terminals ordered by terminal_id, so the
-- merchant index carries terminal_id too and each page is an index range scan, not a sort.

BEGIN;

DROP INDEX terminals_merchant_id_idx;
CREATE INDEX terminals_merchant_id_idx ON terminals (merchant_id, terminal_id);

COMMIT;
