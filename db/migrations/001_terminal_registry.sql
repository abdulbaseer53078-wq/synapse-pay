-- Terminal Registry (Stage 1, Step 2): terminals, their certificates, and heartbeats.
-- Target: Aurora PostgreSQL 13+ (gen_random_uuid() is built in).

BEGIN;

CREATE TYPE terminal_status AS ENUM
    ('PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'DECOMMISSIONED', 'REJECTED');
CREATE TYPE terminal_health AS ENUM ('HEALTHY', 'DEGRADED', 'UNREACHABLE');

-- Minimal owner table so terminals.merchant_id has something to reference.
-- webhook_secret_id selects the per-merchant HMAC secret that signs webhooks (spec v1.0.0).
CREATE TABLE merchants (
    merchant_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_secret_id VARCHAR,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE terminals (
    terminal_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id              UUID NOT NULL REFERENCES merchants,
    device_serial            VARCHAR NOT NULL UNIQUE,
    device_model             VARCHAR NOT NULL,
    firmware_version         VARCHAR NOT NULL,
    secure_element_id        VARCHAR NOT NULL,
    status                   terminal_status NOT NULL DEFAULT 'PENDING',
    certificate_id           UUID,  -- FK added below, after certificates exists
    -- shortcut: no FK until Step 26's certification registry exists; add it then.
    certification_profile_id UUID,
    health_state             terminal_health NOT NULL DEFAULT 'UNREACHABLE',
    last_heartbeat_at        TIMESTAMPTZ,
    registered_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at             TIMESTAMPTZ,
    status_changed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata                 JSONB NOT NULL DEFAULT '{}',
    -- An active terminal must have a certificate to authenticate with.
    CHECK (status <> 'ACTIVE' OR (certificate_id IS NOT NULL AND activated_at IS NOT NULL))
);

CREATE TABLE certificates (
    certificate_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    terminal_id       UUID NOT NULL REFERENCES terminals,
    serial_number     VARCHAR NOT NULL UNIQUE,
    public_key_pem    TEXT NOT NULL,
    issued_at         TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    revoked_at        TIMESTAMPTZ,
    revocation_reason VARCHAR,
    UNIQUE (certificate_id, terminal_id),  -- target of the composite FK below
    CHECK (expires_at > issued_at),
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);

-- Composite FK: a terminal's current certificate must be one issued to that same terminal.
ALTER TABLE terminals
    ADD FOREIGN KEY (certificate_id, terminal_id) REFERENCES certificates (certificate_id, terminal_id);

CREATE TABLE heartbeats (
    heartbeat_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    terminal_id       UUID NOT NULL REFERENCES terminals,
    sent_at           TIMESTAMPTZ NOT NULL,                -- terminal's clock
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),  -- server's clock
    signature_valid   BOOLEAN NOT NULL,
    connectivity_type VARCHAR NOT NULL CHECK (connectivity_type IN ('ETHERNET', 'CELLULAR', 'MESH')),
    latency_ms        INTEGER NOT NULL CHECK (latency_ms >= 0),
    firmware_version  VARCHAR NOT NULL,
    battery_level     INTEGER CHECK (battery_level BETWEEN 0 AND 100)
);

-- device_serial is already indexed by its UNIQUE constraint.
CREATE INDEX terminals_merchant_id_idx       ON terminals (merchant_id);
CREATE INDEX terminals_status_idx            ON terminals (status);
CREATE INDEX terminals_last_heartbeat_at_idx ON terminals (last_heartbeat_at);
-- Postgres doesn't index FK columns automatically; these back the FKs and per-terminal lookups.
CREATE INDEX certificates_terminal_id_idx    ON certificates (terminal_id);
CREATE INDEX heartbeats_terminal_received_idx ON heartbeats (terminal_id, received_at DESC);

COMMIT;
