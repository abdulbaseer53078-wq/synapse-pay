-- The token vault (Step 29), in its own database: only card-service has its credentials.
-- Idempotent: card-service applies it at startup.
--
-- Nothing here is a readable card number. encrypted_pan is HSM ciphertext bound to its token (moved to another
-- row, it no longer decrypts); pan_fingerprint is a keyed HMAC, which unlike a plain SHA-256 can't be reversed by
-- trying every card number in a BIN range. The BIN and last 4 are kept in clear, as PCI DSS allows.

CREATE TABLE IF NOT EXISTS token_vault (
    token           VARCHAR(40) PRIMARY KEY CHECK (token ~ '^tok_[0-9a-f]{32}$'),
    merchant_id     VARCHAR(64) NOT NULL,
    pan_fingerprint CHAR(64) NOT NULL,
    encrypted_pan   TEXT NOT NULL CHECK (encrypted_pan LIKE 'sv_.%'),
    token_type      VARCHAR(4) NOT NULL CHECK (token_type IN ('PAN', 'DPAN')),
    card_bin        CHAR(6) NOT NULL,
    card_last4      CHAR(4) NOT NULL,
    card_network    VARCHAR(16) NOT NULL,
    card_expiry     CHAR(5) NOT NULL,
    customer_ref    VARCHAR(128),
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One live token per card per merchant: the same card saved twice gets the same token, even when two saves race.
CREATE UNIQUE INDEX IF NOT EXISTS token_vault_live_card ON token_vault (merchant_id, pan_fingerprint)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS token_vault_merchant ON token_vault (merchant_id, created_at);
