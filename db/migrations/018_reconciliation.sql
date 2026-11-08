-- Settlement reconciliation (PR 7, audit F-05) and offline edge chain verification (PR 6 cloud side, F-06/F-07).
--
-- Reconciliation compares three things: the ledger (what we think happened), the acquirer's or PSP's settlement file
-- (what it says happened), and the bank credit (what actually arrived). Outcomes are recorded here, never as payment
-- statuses: a payment's state and the bank's paperwork about it are different facts.

BEGIN;

INSERT INTO accounts (code, name, type) VALUES
    ('1100', 'Settlement Bank Account', 'ASSET'),
    ('5000', 'Interchange Fee Expense', 'EXPENSE');

ALTER TABLE journal_entries DROP CONSTRAINT journal_entries_entry_type_check;
ALTER TABLE journal_entries ADD CONSTRAINT journal_entries_entry_type_check
    CHECK (entry_type IN ('SALE', 'REFUND', 'FEE', 'CHARGEBACK', 'SETTLEMENT', 'ADJUSTMENT'));
-- A payment's money arrives once: one SETTLEMENT per transaction.
CREATE UNIQUE INDEX journal_entries_one_settlement ON journal_entries (transaction_id) WHERE entry_type = 'SETTLEMENT';

CREATE TABLE settlement_files (
    file_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source          VARCHAR NOT NULL,  -- where it came from, e.g. s3://bucket/key
    rail            VARCHAR NOT NULL CHECK (rail IN ('CARD', 'UPI', 'WALLET')),
    acquirer_id     VARCHAR NOT NULL,
    settlement_date DATE NOT NULL,
    sha256          CHAR(64) NOT NULL UNIQUE,  -- the same file ingested twice is the same file
    row_count       INTEGER NOT NULL,
    gross_total     BIGINT NOT NULL,
    fee_total       BIGINT NOT NULL,
    net_total       BIGINT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE reconciliation_runs (
    run_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          VARCHAR NOT NULL CHECK (kind IN ('FILE', 'CLOSE_DAY')),
    file_id       UUID REFERENCES settlement_files,
    rail          VARCHAR NOT NULL,
    business_date DATE NOT NULL,
    bank_credited BIGINT,  -- what reached the bank for this file, when known: the third leg
    summary       JSONB NOT NULL,  -- counts per outcome, totals, the liquidity gap
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((kind = 'FILE') = (file_id IS NOT NULL))
);

CREATE TABLE reconciliation_items (
    item_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id            UUID NOT NULL REFERENCES reconciliation_runs,
    transaction_id    UUID REFERENCES transactions,  -- NULL when the file names a payment we have no record of
    method_reference  VARCHAR,
    outcome           VARCHAR NOT NULL CHECK (outcome IN ('MATCHED', 'FEE_ADJUSTED', 'AMOUNT_MISMATCH',
                          'MISSING_IN_LEDGER', 'MISSING_IN_SETTLEMENT', 'DUPLICATE_IN_SETTLEMENT', 'UNSUPPORTED_ROW')),
    expected_amount   BIGINT,
    gross_amount      BIGINT,
    fee_amount        BIGINT,
    net_amount        BIGINT,
    detail            TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX reconciliation_items_run ON reconciliation_items (run_id);
CREATE UNIQUE INDEX reconciliation_items_settled_once ON reconciliation_items (transaction_id)
    WHERE outcome IN ('MATCHED', 'FEE_ADJUSTED');

-- PR 6: every chained item an edge has sent, so a resent item must be byte-identical and a gap or fork is visible.
CREATE TABLE edge_sync_items (
    edge_node_id UUID NOT NULL REFERENCES edge_nodes,
    edge_seq     BIGINT NOT NULL CHECK (edge_seq >= 1),
    item_hash    CHAR(64) NOT NULL,  -- SHA-256 of the item's canonical JSON, signature included
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (edge_node_id, edge_seq)
);
ALTER TABLE edge_nodes ADD COLUMN flagged_at TIMESTAMPTZ;  -- set on a broken chain; its batches are refused
ALTER TABLE edge_nodes ADD COLUMN flagged_reason VARCHAR;

COMMIT;
