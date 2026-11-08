"""Writes journal entries on the caller's connection (PR 1). It never opens its own transaction: the ledger is only
correct if it commits or rolls back together with the payment state change that caused it."""
from uuid import UUID, uuid4

from psycopg import Connection

from app.domain.ledger import FEE_REVENUE, LedgerImbalance, Posting, balanced, sale_postings


def record_entry(conn: Connection, transaction_id: UUID, merchant_id: UUID, currency: str, entry_type: str,
                 description: str, postings: list[Posting]) -> UUID:
    """Insert one balanced entry. The database checks the balance again at commit (migration 016)."""
    balanced(postings)
    entry = uuid4()
    conn.execute("INSERT INTO journal_entries (journal_entry_id, transaction_id, merchant_id, currency, entry_type,"
                 " description) VALUES (%s, %s, %s, %s, %s, %s)",
                 (entry, transaction_id, merchant_id, currency, entry_type, description))
    for p in postings:
        inserted = conn.execute(
            "INSERT INTO ledger_postings (journal_entry_id, account_id, debit_amount, credit_amount)"
            " SELECT %s, account_id, %s, %s FROM accounts WHERE code = %s AND is_active RETURNING 1",
            (entry, p.debit, p.credit, p.account)).fetchone()
        if inserted is None:
            raise LedgerImbalance(f"account {p.account} does not exist or is inactive")
    return entry


def has_sale(conn: Connection, transaction_id: UUID) -> bool:
    return conn.execute("SELECT 1 FROM journal_entries WHERE transaction_id = %s AND entry_type = 'SALE'",
                        (transaction_id,)).fetchone() is not None


def fee_history(conn: Connection, transaction_id: UUID) -> tuple[int, int] | None:
    """(fee the SALE earned, fee refunds have reversed so far), or None if the payment has no SALE entry."""
    row = conn.execute(
        "SELECT count(*) FILTER (WHERE e.entry_type = 'SALE'),"
        " coalesce(sum(p.credit_amount) FILTER (WHERE e.entry_type = 'SALE' AND a.code = %s), 0),"
        " coalesce(sum(p.debit_amount) FILTER (WHERE e.entry_type = 'REFUND' AND a.code = %s), 0)"
        " FROM journal_entries e JOIN ledger_postings p USING (journal_entry_id) JOIN accounts a USING (account_id)"
        " WHERE e.transaction_id = %s", (FEE_REVENUE, FEE_REVENUE, transaction_id)).fetchone()
    return (int(row[1]), int(row[2])) if row[0] else None


def post_sale_once(conn: Connection, transaction_id: UUID, merchant_id: UUID, currency: str, method: str,
                   amount: int, fee: int) -> bool:
    """The SALE for a payment whose money just moved, unless it already has one (CAPTURED then SETTLED, a re-sent
    answer). The unique index in migration 016 enforces once-only as well. True if an entry was written."""
    if has_sale(conn, transaction_id):
        return False
    record_entry(conn, transaction_id, merchant_id, currency, "SALE", f"{method} sale", sale_postings(amount, fee))
    return True
