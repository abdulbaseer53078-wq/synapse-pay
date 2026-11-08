-- Step 20: edge nodes. An edge node is an on-premise box that keeps a merchant taking payments while the internet
-- is down. It authenticates with its own certificate (URI SAN urn:synapsepay:edge:<id>, same CA as terminals) and
-- receives signed offline rules; it signs every payment it queues, and the cloud verifies them at sync.

BEGIN;

CREATE TABLE edge_nodes (
    edge_node_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id             UUID NOT NULL REFERENCES merchants,
    status                  VARCHAR NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
    certificate_serial      VARCHAR UNIQUE,
    public_key_pem          TEXT,               -- verifies the payments it signs (Step 21, checked at sync)
    -- The rules the edge enforces offline. rules_version only moves forward: the edge refuses anything older
    -- than what it already holds, so a replayed old (looser) rule set can't be slipped back in.
    rules_version           BIGINT NOT NULL DEFAULT 1 CHECK (rules_version >= 1),
    offline_per_transaction BIGINT NOT NULL CHECK (offline_per_transaction > 0),
    offline_per_day         BIGINT NOT NULL CHECK (offline_per_day >= offline_per_transaction),
    offline_max_age_minutes INTEGER NOT NULL DEFAULT 4320 CHECK (offline_max_age_minutes > 0),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX edge_nodes_merchant_idx ON edge_nodes (merchant_id);

COMMIT;
