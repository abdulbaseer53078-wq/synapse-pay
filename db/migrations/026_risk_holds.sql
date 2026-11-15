-- Risk holds (1.18.0): replaces the black-box "account under review" experience.
-- Merchants can see exactly why a transaction or their account is on hold, what documents are
-- required to release it, and the current status.
--
-- Per CLAUDE.md compliance rules: the risk engine that creates these rows must go through
-- a RiskEngineInterface → mock implementation, same pattern as KYCProviderInterface.
-- The table is storage only; hold creation belongs in infrastructure/risk_engine.py (not yet written).

BEGIN;

CREATE TABLE risk_holds (
    hold_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id         UUID NOT NULL REFERENCES merchants,
    -- nullable: a hold may be on the merchant account level (no specific transaction)
    transaction_id      UUID REFERENCES transactions,
    -- VELOCITY_BREACH | DOCUMENT_REQUIRED | AML_REVIEW | SANCTIONS_HIT | MANUAL_REVIEW
    reason              VARCHAR(50)  NOT NULL,
    -- JSON array of document types the merchant must upload to release the hold.
    -- e.g. ["PAN", "GST_CERTIFICATE", "BANK_STATEMENT_90_DAYS"]
    required_documents  JSONB        NOT NULL DEFAULT '[]',
    status              VARCHAR(20)  NOT NULL DEFAULT 'OPEN'
                        CHECK (status IN ('OPEN', 'REVIEWING', 'RELEASED', 'ESCALATED')),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    -- internal notes written by the compliance team; never returned in merchant-facing API responses
    internal_notes      TEXT
);

CREATE INDEX risk_holds_merchant_status_idx ON risk_holds (merchant_id, status, created_at DESC);
-- sparse: most holds are not tied to a transaction
CREATE INDEX risk_holds_transaction_idx     ON risk_holds (transaction_id) WHERE transaction_id IS NOT NULL;

COMMIT;
