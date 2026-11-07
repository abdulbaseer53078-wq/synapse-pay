-- Step 17.3: audit chain epochs, so a region failover can never fork the chain inside the WORM bucket.
--
-- After an unplanned failover the new region inherits a chain head that may be behind the old region's: the
-- replication lag's worth of events was chained and written to WORM in the old region, but never reached this
-- database. Continuing the same key space would put two different records at the same sequence number in a
-- bucket nobody can clean for five years. The new region instead starts the next epoch: its objects live under
-- `<prefix>/epoch-NNNN/`, and its first record links back to the head it inherited. Epoch 1 keeps today's keys.

BEGIN;

ALTER TABLE audit_chain_head ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1 CHECK (epoch >= 1);

COMMIT;
