-- Auto-renewal (API 1.17.0): how many times a subscription's paid period was renewed.

BEGIN;

ALTER TABLE merchant_subscriptions
    ADD COLUMN IF NOT EXISTS renewal_count INTEGER NOT NULL DEFAULT 0 CHECK (renewal_count >= 0);

COMMIT;
