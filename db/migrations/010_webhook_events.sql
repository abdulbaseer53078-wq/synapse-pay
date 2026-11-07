-- Step 10B: idempotency for inbound webhooks.
--
-- At-least-once delivery means the same event arrives twice. The primary key is the deduplication: an
-- INSERT ... ON CONFLICT DO NOTHING tells the handler "you are the first" or "someone already applied this",
-- atomically, without a read-then-write race between two workers receiving the same retry.

BEGIN;

CREATE TABLE webhook_events (
    provider     VARCHAR NOT NULL,          -- 'upi'; more providers later
    event_id     VARCHAR NOT NULL,          -- the provider's delivery id, not ours
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, event_id)
);

-- The webhook handler resolves a payment from the network's reference, so that lookup needs an index.
CREATE INDEX transactions_method_reference_idx ON transactions (payment_method, method_reference);

COMMIT;
