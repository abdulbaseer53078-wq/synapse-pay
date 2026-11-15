-- SaaS subscriptions: which plan a merchant is on. A merchant with no row is on FREE.
-- Offline (edge node) payments need an ACTIVE PRO or ENTERPRISE plan whose period hasn't ended.

BEGIN;

CREATE TABLE merchant_subscriptions (
    merchant_id        UUID PRIMARY KEY REFERENCES merchants,
    tier               VARCHAR NOT NULL CHECK (tier IN ('FREE', 'PRO', 'ENTERPRISE')),
    status             VARCHAR NOT NULL CHECK (status IN ('ACTIVE', 'PAST_DUE', 'CANCELED')),
    current_period_end TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
