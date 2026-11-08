-- Step 26: the certification registry. Which exact firmware of which terminal model a card scheme (or NPCI) has
-- certified, and for which acquirer. A firmware change voids certification until its own row exists: there are no
-- patterns or ranges, because a patch release can break EMV parsing as easily as a major one.
--
-- certification_profiles (migration 004) stays: it is the per-terminal limits and expiry, not the scheme matrix.
-- No rows are seeded here. A made-up certification must never reach production; sandbox and tests add their own.

BEGIN;

CREATE TABLE certifications (
    certification_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_model       VARCHAR NOT NULL,
    firmware_version   VARCHAR NOT NULL,
    scheme             VARCHAR NOT NULL CHECK (scheme IN ('VISA', 'MASTERCARD', 'RUPAY', 'AMEX', 'NPCI_UPI')),
    acquirer_id        VARCHAR NOT NULL,
    certificate_number VARCHAR NOT NULL,  -- the scheme's own reference, quoted in a dispute or an audit
    status             VARCHAR NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    valid_from         TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until        TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_until > valid_from),
    UNIQUE (device_model, firmware_version, scheme, acquirer_id)
);

-- Below this, a firmware is refused even if certified: a downgrade to a version with a known hole is an attack.
CREATE TABLE firmware_minimums (
    device_model             VARCHAR PRIMARY KEY,
    minimum_secure_firmware  VARCHAR NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
