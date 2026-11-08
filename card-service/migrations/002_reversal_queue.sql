-- Durable reversal queue (PR 3), in card-service's own database beside the token vault. Idempotent: applied at
-- startup.
--
-- A row exists only when a payment's outcome was unknown and its in-line reversal also failed. It holds what a
-- reversal must quote, so it can be resent after a restart. sealed_pan is HSM ciphertext bound to the transaction
-- id; it is wiped the moment the row leaves PENDING, so card data lives here only while a reversal is owed.

CREATE TABLE IF NOT EXISTS pending_reversals (
    transaction_id       VARCHAR(64) PRIMARY KEY,
    host_id              VARCHAR(64) NOT NULL,
    state                VARCHAR(12) NOT NULL DEFAULT 'PENDING'
                         CHECK (state IN ('PENDING', 'REVERSED', 'NOT_AT_HOST', 'MANUAL')),
    sealed_pan           TEXT CHECK (sealed_pan LIKE 'sv_.%'),
    card_expiry          CHAR(4) NOT NULL,          -- YYMM, as DE 14
    amount_minor         BIGINT NOT NULL,
    currency             CHAR(3) NOT NULL,
    acquirer_merchant_id VARCHAR(64) NOT NULL,
    acquirer_terminal_id VARCHAR(64) NOT NULL,
    original_mti         CHAR(4) NOT NULL,
    original_stan        CHAR(6) NOT NULL,
    original_transmitted CHAR(10) NOT NULL,         -- DE 7 of the original
    response_code        VARCHAR(4),                -- DE 39 of the answer that ended it
    attempts             INTEGER NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((state = 'PENDING') = (sealed_pan IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS pending_reversals_due ON pending_reversals (created_at) WHERE state = 'PENDING';
