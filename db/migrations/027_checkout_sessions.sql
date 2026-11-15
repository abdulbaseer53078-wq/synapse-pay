-- Web Checkout Sessions (1.19.0): a merchant server creates a short-lived hosted payment page
-- for browser-based e-commerce. The customer opens checkout_url, enters card details on
-- Synapse's hosted page, and is redirected to success_url or cancel_url when done.
--
-- Relationship to payment_intents: a checkout session owns a payment_intent once the customer
-- submits the form. The session is the merchant-facing object; the intent is the payment-engine object.
-- A session that expires without payment is EXPIRED; one the customer abandons is CANCELED.

BEGIN;

CREATE TABLE checkout_sessions (
    session_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- exposed as cs_<32 hex>
    merchant_id     UUID NOT NULL REFERENCES merchants,
    amount          BIGINT NOT NULL CHECK (amount > 0),
    currency        CHAR(3) NOT NULL DEFAULT 'INR',
    description     VARCHAR(255),
    -- Where to redirect the browser after success or cancellation.
    success_url     VARCHAR(2048) NOT NULL,
    cancel_url      VARCHAR(2048) NOT NULL,
    -- The token embedded in checkout_url. Single-use: cleared once the customer submits the form.
    -- shortcut: stored in plaintext; move to a signed JWT or opaque reference before production.
    url_token       VARCHAR NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(32), 'base64url'),
    status          VARCHAR(20) NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN', 'PROCESSING', 'COMPLETED', 'EXPIRED', 'CANCELED')),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '30 minutes',
    -- Linked payment_intent created when the customer submits their card.
    intent_id       UUID REFERENCES payment_intents,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX checkout_sessions_merchant_idx ON checkout_sessions (merchant_id, created_at DESC);
-- Sweep job: expire sessions past their deadline.
CREATE INDEX checkout_sessions_expiry_idx   ON checkout_sessions (expires_at)
    WHERE status = 'OPEN';

COMMIT;
