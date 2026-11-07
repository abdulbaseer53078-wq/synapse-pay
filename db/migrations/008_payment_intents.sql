-- Merchant SDK (Stage 1, Step 6): API keys, payment intents, online card payments, webhook delivery.

BEGIN;

-- Secret API keys for merchant servers (Authorization: Bearer sk_test_...). Only a SHA-256 is stored.
CREATE TABLE api_keys (
    key_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants,
    key_hash    BYTEA NOT NULL UNIQUE,
    key_prefix  VARCHAR NOT NULL,            -- first characters, to tell keys apart in a dashboard
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX api_keys_merchant_idx ON api_keys (merchant_id);

-- shortcut: the webhook signing secret is stored as is (it must be readable to sign with). Move it to a
-- KMS-backed secret store, selected by merchants.webhook_secret_id, before production.
ALTER TABLE merchants ADD COLUMN webhook_secret VARCHAR;

CREATE TABLE payment_intents (
    intent_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- exposed as pi_<32 hex>
    merchant_id          UUID NOT NULL REFERENCES merchants,
    idempotency_key      UUID NOT NULL,
    request_hash         BYTEA NOT NULL,
    amount               BIGINT NOT NULL CHECK (amount > 0),
    currency             CHAR(3) NOT NULL,
    capture_mode         VARCHAR NOT NULL CHECK (capture_mode IN ('AUTO', 'MANUAL')),
    description          VARCHAR,
    metadata             JSONB NOT NULL DEFAULT '{}',
    webhook_url          VARCHAR,
    terminal_id          UUID REFERENCES terminals,  -- set: pay on this physical terminal
    status               VARCHAR NOT NULL CHECK (status IN ('REQUIRES_PAYMENT_METHOD', 'REQUIRES_ACTION',
                                                 'PROCESSING', 'SUCCEEDED', 'CANCELED')),
    -- shortcut: stored as is so it can be returned to the merchant's server on retrieve, as other gateways do;
    -- it only lets its holder pay this one intent, and expires.
    client_secret        VARCHAR NOT NULL UNIQUE,
    expires_at           TIMESTAMPTZ NOT NULL,
    -- The card waiting on a 3-D Secure challenge: still encrypted to the HSM, deleted as soon as it's used.
    pending_card         JSONB,
    transaction_id       UUID,                      -- the latest attempt
    last_payment_error   JSONB,
    card_bin             CHAR(6),
    card_last4           CHAR(4),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (merchant_id, idempotency_key),
    CHECK (pending_card IS NULL OR status = 'REQUIRES_ACTION')
);
CREATE INDEX payment_intents_terminal_idx ON payment_intents (terminal_id, created_at)
    WHERE terminal_id IS NOT NULL AND status = 'REQUIRES_PAYMENT_METHOD';

-- Online payments have no terminal; each attempt still is a transaction.
ALTER TABLE transactions ALTER COLUMN terminal_id DROP NOT NULL;
ALTER TABLE transactions ADD COLUMN channel VARCHAR NOT NULL DEFAULT 'TERMINAL' CHECK (channel IN ('TERMINAL', 'ONLINE'));
ALTER TABLE transactions ADD COLUMN payment_intent_id UUID REFERENCES payment_intents;
ALTER TABLE transactions ADD COLUMN webhook_url VARCHAR;
ALTER TABLE transactions ADD CONSTRAINT transactions_channel_terminal
    CHECK ((channel = 'TERMINAL') = (terminal_id IS NOT NULL));
ALTER TABLE payment_intents ADD FOREIGN KEY (transaction_id) REFERENCES transactions;

-- Webhook outbox: written in the same database transaction as the status change, delivered with retries.
CREATE TABLE webhook_deliveries (
    delivery_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id     UUID NOT NULL REFERENCES merchants,
    url             VARCHAR NOT NULL,
    body            TEXT NOT NULL,                -- exact bytes that are signed and sent
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ,
    gave_up_at      TIMESTAMPTZ,
    last_error      VARCHAR,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL AND gave_up_at IS NULL;

COMMIT;
