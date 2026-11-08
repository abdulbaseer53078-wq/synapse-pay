-- Chargebacks (PR 8). A chargeback is a fact the card network imposes, not a request we may refuse: every notice is
-- recorded, even one for a payment already refunded (which is alerted).
--
-- The acquirer takes the money when the chargeback is opened, not when it's decided, so the ledger moves it then:
--
--   opened  Dr 2000 Merchant Payable   Cr 1100 Settlement Bank   (settled: taken back from our bank)
--                                   or Cr 1000 Payment Clearing  (not yet settled: the acquirer won't pay it)
--   WON     the opening entry reversed, into the same account (the acquirer returns it)
--   LOST    nothing: the money already left
--
-- So the ledger's bank balance matches the real one for the whole dispute.

BEGIN;

ALTER TABLE journal_entries DROP CONSTRAINT journal_entries_entry_type_check;
ALTER TABLE journal_entries ADD CONSTRAINT journal_entries_entry_type_check
    CHECK (entry_type IN ('SALE', 'REFUND', 'FEE', 'CHARGEBACK', 'CHARGEBACK_RESOLUTION', 'SETTLEMENT', 'ADJUSTMENT'));

CREATE TABLE chargebacks (
    chargeback_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- exposed as cb_<32 hex>
    transaction_id        UUID REFERENCES transactions,  -- NULL: a notice for a payment we have no record of
    merchant_id           UUID REFERENCES merchants,
    acquirer_id           VARCHAR(64) NOT NULL,
    acquirer_case_id      VARCHAR(64) NOT NULL,
    network_reference     VARCHAR(64) NOT NULL,  -- the RRN the acquirer names
    amount                BIGINT NOT NULL CHECK (amount > 0),
    currency              CHAR(3) NOT NULL,
    reason_code           VARCHAR(10) NOT NULL,  -- the network's, e.g. 10.4 (Visa), 4837 (Mastercard)
    -- Where the money left from when it opened, so a WON returns it to the same place even if the payment settled since.
    cash_account          CHAR(4) CHECK (cash_account IN ('1000', '1100')),
    status                VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN ('PENDING', 'UNDER_REVIEW', 'WON', 'LOST')),
    evidence_deadline     TIMESTAMPTZ NOT NULL,
    evidence              JSONB,  -- structured text the merchant submitted; documents are a follow-up
    evidence_submitted_at TIMESTAMPTZ,
    resolved_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (acquirer_id, acquirer_case_id),  -- the same notice delivered twice is one chargeback
    CHECK ((status IN ('WON', 'LOST')) = (resolved_at IS NOT NULL)),
    CHECK ((transaction_id IS NULL) = (merchant_id IS NULL))
);
CREATE INDEX chargebacks_transaction ON chargebacks (transaction_id);
CREATE INDEX chargebacks_merchant ON chargebacks (merchant_id, created_at);

-- The acquirer's notices, by its event id: a re-sent delivery is acknowledged and not applied twice.
CREATE TABLE chargeback_events (
    acquirer_id VARCHAR(64) NOT NULL,
    event_id    VARCHAR(128) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (acquirer_id, event_id)
);

COMMIT;
