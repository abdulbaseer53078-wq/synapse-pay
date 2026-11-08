-- Refunds (PR 4). A refund is reserved before the network is asked, so a crash at any point leaves a row the
-- recovery worker can finish, and two concurrent refunds can't both pass the "not more than was paid" check.
--
--   PENDING    reserved; the network was (or is about to be) asked; counts against the refundable amount
--   COMPLETED  the network refunded it; transactions.refunded_amount and the ledger include it
--   FAILED     the network refused it, or the rail can't refund; releases the reserved amount

BEGIN;

CREATE TABLE refunds (
    refund_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- exposed as rfnd_<32 hex>; the network's idempotency key too
    transaction_id    UUID NOT NULL REFERENCES transactions,
    merchant_id       UUID NOT NULL REFERENCES merchants,
    amount            BIGINT NOT NULL CHECK (amount > 0),  -- minor units
    reason            VARCHAR(255),
    status            VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED')),
    idempotency_key   UUID NOT NULL,
    request_hash      BYTEA NOT NULL,  -- SHA-256 of the request: the same key with a different refund is a 409
    network_reference VARCHAR,
    -- The fee this refund gave back, fixed when it completes (not when it is reserved: a refund reserved while an
    -- earlier one is still in flight can't yet know whether it will be the one that closes the payment).
    fee_reversed      BIGINT CHECK (fee_reversed >= 0),
    error             JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (merchant_id, idempotency_key),
    CHECK ((status = 'FAILED') = (error IS NOT NULL)),
    CHECK ((status = 'COMPLETED') = (fee_reversed IS NOT NULL))
);
CREATE INDEX refunds_transaction ON refunds (transaction_id);
CREATE INDEX refunds_pending ON refunds (updated_at) WHERE status = 'PENDING';

ALTER TABLE transactions ADD COLUMN refunded_amount BIGINT NOT NULL DEFAULT 0;
ALTER TABLE transactions ADD CONSTRAINT transactions_refund_within_amount
    CHECK (refunded_amount >= 0 AND refunded_amount <= amount);

COMMIT;
