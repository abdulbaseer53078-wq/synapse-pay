-- Double-entry ledger (PR 1, audit finding F-01). Written in the same database transaction as the payment state
-- change that causes it, so a payment and its money can never disagree.
--
-- The rules are the database's, not the application's:
--   * every journal entry balances (debits = credits) and has at least two postings, checked at COMMIT by a
--     deferred trigger: an unbalanced entry rolls back the whole transaction, status change and audit row included;
--   * entries and postings are append-only: a mistake is corrected by a compensating entry, never an edit;
--   * one SALE per transaction, so a payment that moves CAPTURED -> SETTLED is not counted twice.
-- Amounts are BIGINT minor units (paise), never negative; a posting is a debit or a credit, never both.

BEGIN;

CREATE TABLE accounts (
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code       VARCHAR(50) UNIQUE NOT NULL,
    name       VARCHAR(100) NOT NULL,
    type       VARCHAR(20) NOT NULL CHECK (type IN ('ASSET', 'LIABILITY', 'REVENUE', 'EXPENSE')),
    is_active  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE journal_entries (
    journal_entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id   UUID NOT NULL REFERENCES transactions,
    merchant_id      UUID NOT NULL REFERENCES merchants,  -- whose payable this is: the merchant sub-ledger
    currency         CHAR(3) NOT NULL,
    entry_type       VARCHAR(50) NOT NULL CHECK (entry_type IN ('SALE', 'REFUND', 'FEE', 'CHARGEBACK')),
    description      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX journal_entries_one_sale ON journal_entries (transaction_id) WHERE entry_type = 'SALE';
CREATE INDEX journal_entries_transaction ON journal_entries (transaction_id);
CREATE INDEX journal_entries_merchant ON journal_entries (merchant_id, created_at);

CREATE TABLE ledger_postings (
    posting_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    journal_entry_id UUID NOT NULL REFERENCES journal_entries,  -- no cascade: nothing here is ever deleted
    account_id       UUID NOT NULL REFERENCES accounts,
    debit_amount     BIGINT NOT NULL DEFAULT 0 CHECK (debit_amount >= 0),
    credit_amount    BIGINT NOT NULL DEFAULT 0 CHECK (credit_amount >= 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT check_one_side CHECK ((debit_amount > 0 AND credit_amount = 0) OR (credit_amount > 0 AND debit_amount = 0))
);
CREATE INDEX ledger_postings_entry ON ledger_postings (journal_entry_id);
CREATE INDEX ledger_postings_account ON ledger_postings (account_id);

CREATE FUNCTION ledger_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: correct it with a compensating entry', TG_TABLE_NAME;
END $$;
CREATE TRIGGER journal_entries_append_only BEFORE UPDATE OR DELETE ON journal_entries
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER ledger_postings_append_only BEFORE UPDATE OR DELETE ON ledger_postings
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();
-- shortcut: TRUNCATE isn't blocked (test fixtures reset with it); in production the application's database role
-- must not hold TRUNCATE on these tables.

-- Runs at COMMIT for every entry touched in the transaction, after all its postings exist.
CREATE FUNCTION ledger_entry_balances() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    entry UUID := NEW.journal_entry_id;  -- both tables carry it
    debits BIGINT;
    credits BIGINT;
    lines INTEGER;
BEGIN
    SELECT coalesce(sum(debit_amount), 0), coalesce(sum(credit_amount), 0), count(*)
      INTO debits, credits, lines FROM ledger_postings WHERE journal_entry_id = entry;
    IF lines < 2 OR debits <> credits THEN
        RAISE EXCEPTION 'LEDGER IMBALANCE in journal entry %: debits % <> credits % (% postings)',
            entry, debits, credits, lines;
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER journal_entries_balance AFTER INSERT ON journal_entries
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger_entry_balances();
CREATE CONSTRAINT TRIGGER ledger_postings_balance AFTER INSERT ON ledger_postings
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger_entry_balances();

INSERT INTO accounts (code, name, type) VALUES
    ('1000', 'Payment Clearing Account', 'ASSET'),
    ('2000', 'Merchant Payable Account', 'LIABILITY'),
    ('4000', 'Synapse Fee Revenue', 'REVENUE');

COMMIT;
