-- Step 11: a QR payment is recorded as QR, but executed on an underlying rail (UPI or card).
-- Without this column the audit trail says "QR" and nothing says which rail actually moved the money.

BEGIN;

ALTER TABLE transactions ADD COLUMN qr_encoded_rail VARCHAR
    CHECK (qr_encoded_rail IS NULL OR qr_encoded_rail IN ('UPI', 'CARD', 'WALLET', 'UNKNOWN'));

COMMIT;
