"""PR 1: the double-entry ledger. Money in equals money out, an imbalance can't be committed, and a ledger entry is
written with the payment's state change or not at all. Runs against the real Postgres test database."""
from uuid import uuid4

import psycopg
import pytest
from psycopg_pool import ConnectionPool

from app.application.fees import ConfigFeePolicy
from app.application.methods import MethodResult
from app.domain import ledger
from app.domain.ledger import LedgerImbalance, Posting, balanced, fee_for, sale_postings
from app.infrastructure.postgres_transactions import PostgresTransactionRepository


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=2) as connections:
        yield connections


def _pending(db, amount=100_000, method="CARD"):
    merchant_id, terminal_id, transaction_id = uuid4(), uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model)"
               " VALUES (%s, %s, %s, %s)", (terminal_id, merchant_id, f"SN-{transaction_id.hex[:8]}", "PAX A920 Pro"))
    db.execute(
        "INSERT INTO transactions (transaction_id, idempotency_key, merchant_id, terminal_id, amount, currency,"
        " payment_method, capture_mode, status) VALUES (%s, %s, %s, %s, %s, 'INR', %s, 'AUTO', 'PENDING')",
        (transaction_id, uuid4(), merchant_id, terminal_id, amount, method))
    return transaction_id, terminal_id, merchant_id


def _postings(db, transaction_id):
    """{account code: (debits, credits)} for every entry of this payment."""
    rows = db.execute(
        "SELECT a.code, sum(p.debit_amount), sum(p.credit_amount) FROM ledger_postings p"
        " JOIN accounts a USING (account_id) JOIN journal_entries e USING (journal_entry_id)"
        " WHERE e.transaction_id = %s GROUP BY a.code", (transaction_id,)).fetchall()
    return {code: (debit, credit) for code, debit, credit in rows}


def _captured(repo, transaction_id, terminal_id, status="CAPTURED"):
    return repo.finish(transaction_id, terminal_id, MethodResult(status=status), status, None, store_response=True)


# --- the rules -------------------------------------------------------------------------------------------------

def test_a_sale_splits_into_merchant_and_fee_and_balances():
    assert sale_postings(100_000, 2_000) == [Posting("1000", debit=100_000), Posting("2000", credit=98_000),
                                             Posting("4000", credit=2_000)]
    assert sale_postings(100_000, 0) == [Posting("1000", debit=100_000), Posting("2000", credit=100_000)]
    assert sale_postings(500, 500) == [Posting("1000", debit=500), Posting("4000", credit=500)]
    for total, fee in ((100, 101), (100, -1), (0, 0)):
        with pytest.raises(ValueError):
            sale_postings(total, fee)


def test_an_unbalanced_or_malformed_entry_is_refused():
    for bad in ([Posting("1000", debit=100), Posting("2000", credit=99)],  # a fee bug: a paisa missing
                [Posting("1000", debit=100)],  # one-sided
                [Posting("1000", debit=100, credit=100), Posting("2000", credit=0)],  # both sides
                [Posting("1000", debit=-5), Posting("2000", credit=-5)]):
        with pytest.raises(LedgerImbalance):
            balanced(bad)


def test_fees_are_integer_basis_points_rounded_down():
    assert fee_for(100_000, 200) == 2_000
    assert fee_for(99, 200) == 1  # 1.98 paise: the merchant keeps the fraction
    assert ConfigFeePolicy({"CARD": 200}).fee(uuid4(), "UPI", 100_000) == 0, "no rate configured: no fee"
    with pytest.raises(ValueError):
        ConfigFeePolicy({"CARD": 10_001})


# --- in the database, with the payment -------------------------------------------------------------------------

def test_1000_rupees_in_is_980_to_the_merchant_and_20_to_synapse(pool, db):
    transaction_id, terminal_id, merchant_id = _pending(db)
    repo = PostgresTransactionRepository(pool, ConfigFeePolicy({"CARD": 200}))

    _captured(repo, transaction_id, terminal_id)

    assert _postings(db, transaction_id) == {"1000": (100_000, 0), "2000": (0, 98_000), "4000": (0, 2_000)}
    entry = db.execute("SELECT entry_type, merchant_id, currency FROM journal_entries WHERE transaction_id = %s",
                       (transaction_id,)).fetchall()
    assert entry == [("SALE", merchant_id, "INR")]
    # The whole ledger balances, not just this entry.
    assert db.execute("SELECT sum(debit_amount) = sum(credit_amount) FROM ledger_postings").fetchone()[0] is True


def test_an_imbalance_rolls_back_the_payment_state_change_too(pool, db, monkeypatch):
    """A bug in the fee split must not leave a CAPTURED payment with no money behind it."""
    transaction_id, terminal_id, _ = _pending(db)
    repo = PostgresTransactionRepository(pool, ConfigFeePolicy({"CARD": 200}))
    from app.infrastructure import postgres_ledger
    monkeypatch.setattr(postgres_ledger, "sale_postings",
                        lambda total, fee: [Posting("1000", debit=total), Posting("2000", credit=total - fee)])

    with pytest.raises(LedgerImbalance):
        _captured(repo, transaction_id, terminal_id)

    assert db.execute("SELECT status FROM transactions WHERE transaction_id = %s", (transaction_id,)).fetchone()[0] \
        == "PENDING"
    assert db.execute("SELECT count(*) FROM journal_entries WHERE transaction_id = %s", (transaction_id,)).fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM audit_log WHERE entity_id = %s AND action = 'transaction.finish'",
                      (transaction_id,)).fetchone()[0] == 0


def test_the_database_refuses_an_unbalanced_entry_even_if_the_code_skips_its_check(database_url, db):
    transaction_id, _, merchant_id = _pending(db)
    with psycopg.connect(database_url) as conn:
        entry = uuid4()
        conn.execute("INSERT INTO journal_entries (journal_entry_id, transaction_id, merchant_id, currency, entry_type)"
                     " VALUES (%s, %s, %s, 'INR', 'SALE')", (entry, transaction_id, merchant_id))
        for code, debit, credit in (("1000", 100, 0), ("2000", 0, 99)):
            conn.execute("INSERT INTO ledger_postings (journal_entry_id, account_id, debit_amount, credit_amount)"
                         " SELECT %s, account_id, %s, %s FROM accounts WHERE code = %s", (entry, debit, credit, code))
        with pytest.raises(psycopg.errors.RaiseException, match="LEDGER IMBALANCE"):
            conn.commit()  # the deferred trigger runs here
    assert db.execute("SELECT count(*) FROM journal_entries WHERE transaction_id = %s", (transaction_id,)).fetchone()[0] == 0


def test_capture_then_settle_records_the_sale_once(pool, db):
    transaction_id, terminal_id, _ = _pending(db)
    repo = PostgresTransactionRepository(pool)
    _captured(repo, transaction_id, terminal_id, "CAPTURED")
    _captured(repo, transaction_id, terminal_id, "SETTLED")
    _captured(repo, transaction_id, terminal_id, "SETTLED")  # a duplicate webhook or poller answer
    assert _postings(db, transaction_id) == {"1000": (100_000, 0), "2000": (0, 100_000)}


def test_failed_pending_and_authorized_payments_post_nothing(pool, db):
    repo = PostgresTransactionRepository(pool, ConfigFeePolicy({"CARD": 200}))
    for status in ("PENDING", "AUTHORIZED", "FAILED"):
        transaction_id, terminal_id, _ = _pending(db)
        error = {"error_code": "ISSUER_DECLINED", "error_message": "declined", "error_category": "HARD_DECLINE",
                 "retryable": False} if status == "FAILED" else None
        repo.finish(transaction_id, terminal_id, MethodResult(status=status), status, error, store_response=True)
        assert _postings(db, transaction_id) == {}, status


def test_ledger_rows_are_append_only(pool, db):
    transaction_id, terminal_id, _ = _pending(db)
    _captured(PostgresTransactionRepository(pool), transaction_id, terminal_id)
    for statement in ("UPDATE ledger_postings SET credit_amount = credit_amount + 1",
                      "DELETE FROM ledger_postings", "UPDATE journal_entries SET currency = 'USD'",
                      "DELETE FROM journal_entries"):
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            db.execute(statement)


def test_a_card_payment_through_the_api_lands_in_the_ledger(routed_client, ready, merchant, cards, db):
    from test_observability import pay
    r = pay(routed_client, ready, merchant)
    assert r.status_code == 201 and r.json()["status"] == "CAPTURED", r.text
    from app.application.transactions import parse_public_id
    transaction_id = parse_public_id(r.json()["transaction_id"], "txn_")
    assert _postings(db, transaction_id) == {"1000": (50_000, 0), "2000": (0, 50_000)}


def test_the_account_codes_the_rules_use_exist(db):
    codes = {code for (code,) in db.execute("SELECT code FROM accounts WHERE is_active").fetchall()}
    assert {ledger.PAYMENT_CLEARING, ledger.MERCHANT_PAYABLE, ledger.FEE_REVENUE} <= codes


from test_authorization import ready  # noqa: E402,F401  (fixtures)
from test_cascade_e2e import cards, routed_client, routed_settings  # noqa: E402,F401

