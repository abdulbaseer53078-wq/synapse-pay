-- Transactions and idempotency keys (Stage 1, Step 5): the card path from terminal to acquirer.

BEGIN;

CREATE TABLE transactions (
    transaction_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- exposed as txn_<32 hex>
    idempotency_key  UUID NOT NULL,
    merchant_id      UUID NOT NULL REFERENCES merchants,
    terminal_id      UUID NOT NULL REFERENCES terminals,
    amount           BIGINT NOT NULL CHECK (amount > 0),          -- minor units
    currency         CHAR(3) NOT NULL,
    payment_method   VARCHAR NOT NULL CHECK (payment_method IN ('CARD', 'UPI', 'WALLET', 'QR', 'OFFLINE')),
    capture_mode     VARCHAR NOT NULL CHECK (capture_mode IN ('AUTO', 'MANUAL')),
    status           VARCHAR NOT NULL CHECK (status IN ('INITIATED', 'PENDING', 'AUTHORIZED', 'CAPTURED', 'SETTLED',
                                                        'VOIDED', 'FAILED', 'REFUNDED', 'PARTIALLY_REFUNDED')),
    -- PCI DSS allows the first 6 and last 4 digits. The full PAN is never stored, here or anywhere else.
    card_network     VARCHAR,
    card_bin         CHAR(6),
    card_last4       CHAR(4),
    method_reference VARCHAR,
    auth_code        VARCHAR,
    error            JSONB,
    -- NOT_NEEDED, REVERSED, or FAILED (a PENDING transaction that reconciliation must settle).
    reversal         VARCHAR CHECK (reversal IN ('NOT_NEEDED', 'REVERSED', 'FAILED')),
    metadata         JSONB NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((status = 'FAILED') = (error IS NOT NULL))
);
CREATE INDEX transactions_terminal_created_idx ON transactions (terminal_id, created_at);
CREATE INDEX transactions_pending_idx ON transactions (status) WHERE status = 'PENDING';

-- One row per (merchant, key). IN_FLIGHT while the first request runs; DONE holds the response to replay.
-- A retryable failure deletes its row, so a retry with the same key is processed again (spec: Error.retryable).
CREATE TABLE idempotency_keys (
    merchant_id     UUID NOT NULL REFERENCES merchants,
    idempotency_key UUID NOT NULL,
    request_hash    BYTEA NOT NULL,                -- SHA-256 of the canonical request body
    transaction_id  UUID REFERENCES transactions,
    state           VARCHAR NOT NULL CHECK (state IN ('IN_FLIGHT', 'DONE')),
    response        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (merchant_id, idempotency_key),
    CHECK ((state = 'DONE') = (response IS NOT NULL))
);

COMMIT;
