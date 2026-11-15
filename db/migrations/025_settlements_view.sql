-- Transparent settlements view (1.18.0): merchants can see exactly what they were paid and what was deducted.
-- This is a VIEW over the existing double-entry ledger (migration 016), not a new table.
-- Data is authoritative because it derives from the same journal_entries/ledger_postings the platform uses
-- for its own books: it cannot drift from the source.
--
-- Account codes (domain/ledger.py):
--   2000 = MERCHANT_PAYABLE (liability): what the platform owes the merchant
--   4000 = FEE_REVENUE (revenue): the platform's fee (MDR)
--
-- shortcut: GST on MDR is computed as 18% of mdr_fee, not a separate ledger account yet.
-- To upgrade: add a '2001' GST_PAYABLE account, update sale_postings() in domain/ledger.py
-- to post it, then rewrite this view to read that account instead.

BEGIN;

CREATE VIEW merchant_settlements AS
SELECT
    je.journal_entry_id                                                               AS settlement_id,
    je.transaction_id,
    je.merchant_id,
    je.currency,
    je.created_at                                                                     AS settled_at,
    -- gross: what the customer paid. In a SALE entry debits equal credits, so sum of debits = sum of credits = gross.
    sum(lp.debit_amount)                                                              AS gross_amount,
    -- mdr_fee: the platform's fee posted to FEE_REVENUE (account 4000).
    sum(CASE WHEN a.code = '4000' THEN lp.credit_amount ELSE 0 END)                 AS mdr_fee,
    -- gst_on_fee: 18% of MDR (shortcut: derived, not a separate ledger posting).
    round(sum(CASE WHEN a.code = '4000' THEN lp.credit_amount ELSE 0 END) * 0.18)  AS gst_on_fee,
    -- net_amount: what the merchant receives. MERCHANT_PAYABLE credit minus GST is not yet deducted
    -- in the ledger; the endpoint subtracts gst_on_fee for the merchant-facing display.
    sum(CASE WHEN a.code = '2000' THEN lp.credit_amount ELSE 0 END)                 AS net_amount_ledger
FROM journal_entries  je
JOIN ledger_postings  lp ON lp.journal_entry_id = je.journal_entry_id
JOIN accounts          a ON a.account_id        = lp.account_id
WHERE je.entry_type = 'SALE'
GROUP BY je.journal_entry_id, je.transaction_id, je.merchant_id, je.currency, je.created_at;

COMMIT;
