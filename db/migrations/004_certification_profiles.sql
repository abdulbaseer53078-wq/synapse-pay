-- Certification profiles for transaction-time authorization (Stage 1, Step 2, Task 2.6).

BEGIN;

-- shortcut: profiles are inserted and assigned to terminals directly; Step 26's certification
-- registry takes over managing them (and per-day usage tracking needs the transaction engine).
CREATE TABLE certification_profiles (
    profile_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    certified_for         VARCHAR[] NOT NULL
        CHECK (certified_for <@ ARRAY['CARD', 'UPI', 'WALLET', 'QR', 'OFFLINE']::VARCHAR[]),
    expires_at            TIMESTAMPTZ NOT NULL,
    per_transaction_limit BIGINT NOT NULL CHECK (per_transaction_limit > 0),  -- minor units
    per_day_limit         BIGINT NOT NULL CHECK (per_day_limit >= per_transaction_limit)
);

-- The FK migration 001 deferred until profiles existed.
ALTER TABLE terminals ADD FOREIGN KEY (certification_profile_id) REFERENCES certification_profiles;
CREATE INDEX terminals_certification_profile_id_idx ON terminals (certification_profile_id);

COMMIT;
