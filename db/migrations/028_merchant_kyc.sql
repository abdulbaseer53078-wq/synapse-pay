-- Merchant KYC (Task 1): one row per merchant, updated in-place on resubmission.
-- shortcut: PAN/GST stored in plaintext; encrypt at rest (KMS) before production.
BEGIN;

CREATE TABLE merchant_kyc (
    merchant_id UUID        PRIMARY KEY REFERENCES merchants,
    pan_number  VARCHAR(10) NOT NULL,
    gst_number  VARCHAR(15) NOT NULL,
    status      VARCHAR(10) NOT NULL DEFAULT 'PENDING'
                CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
