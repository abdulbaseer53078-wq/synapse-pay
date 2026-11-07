-- Two-phase registration (Stage 1, Step 2, Task 2.3).

BEGIN;

ALTER TYPE terminal_status ADD VALUE 'PENDING_ACTIVATION' AFTER 'PENDING';

-- The merchant creates the record before the device reports these; they arrive with the CSR.
ALTER TABLE terminals
    ALTER COLUMN secure_element_id DROP NOT NULL,
    ALTER COLUMN firmware_version DROP NOT NULL,
    ADD CHECK (status IN ('PENDING', 'REJECTED')
               OR (secure_element_id IS NOT NULL AND firmware_version IS NOT NULL));

-- Only a SHA-256 hash of the token is stored; the token itself is shown once.
CREATE TABLE registration_tokens (
    token_hash  BYTEA PRIMARY KEY,
    terminal_id UUID NOT NULL REFERENCES terminals,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE INDEX registration_tokens_terminal_id_idx ON registration_tokens (terminal_id);

-- The challenge is a public nonce (the terminal signs it), so it is stored as-is.
CREATE TABLE activation_challenges (
    terminal_id UUID PRIMARY KEY REFERENCES terminals,
    challenge   BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

COMMIT;
