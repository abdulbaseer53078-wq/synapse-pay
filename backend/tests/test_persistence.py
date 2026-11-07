"""SQL that the fake-based tests cannot reach: migrations 010 and 011.

The adapter and webhook suites substitute in-memory doubles, which proves the *logic* of deduplication but not
the statement that implements it. These four run the real SQL against Postgres.
"""
from uuid import uuid4

import pytest
from psycopg_pool import ConnectionPool

from app.infrastructure.postgres_transactions import PostgresTransactionRepository
from app.infrastructure.postgres_webhooks import PostgresWebhookEvents


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=1) as connections:
        yield connections


def _terminal(db) -> tuple:
    merchant_id, terminal_id = uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model)"
               " VALUES (%s, %s, %s, %s)", (terminal_id, merchant_id, "SN-1", "PAX A920 Pro"))
    return merchant_id, terminal_id


def _transaction(db, merchant_id, terminal_id, method="UPI", status="PENDING", reference="psp_x") -> object:
    transaction_id = uuid4()
    db.execute(
        "INSERT INTO transactions (transaction_id, idempotency_key, merchant_id, terminal_id, amount, currency,"
        " payment_method, capture_mode, status, method_reference)"
        " VALUES (%s, %s, %s, %s, 100, 'INR', %s, 'AUTO', %s, %s)",
        (transaction_id, uuid4(), merchant_id, terminal_id, method, status, reference))
    return transaction_id


# --- 010: webhook deduplication -------------------------------------------------------------------------

def test_a_delivery_id_is_claimed_exactly_once(pool, db):
    db.execute("TRUNCATE webhook_events")
    events = PostgresWebhookEvents(pool)

    assert events.claim("upi", "evt_1") is True
    assert events.claim("upi", "evt_1") is False  # the PSP retrying
    assert events.claim("upi", "evt_2") is True
    assert events.claim("wallet", "evt_1") is True  # providers are namespaced


def test_the_claim_is_atomic_under_a_second_writer(pool, db):
    """Two workers receiving the same retry must not both win: that is the whole point of the unique key."""
    db.execute("TRUNCATE webhook_events")
    first, second = PostgresWebhookEvents(pool), PostgresWebhookEvents(pool)
    assert first.claim("upi", "evt_race") is True
    assert second.claim("upi", "evt_race") is False


# --- 010: the polling fallback's query -------------------------------------------------------------------

def test_stale_pending_finds_only_old_pending_rows_of_that_method(pool, db):
    merchant_id, terminal_id = _terminal(db)
    stale = _transaction(db, merchant_id, terminal_id)
    fresh = _transaction(db, merchant_id, terminal_id)
    other_method = _transaction(db, merchant_id, terminal_id, method="CARD")
    db.execute("UPDATE transactions SET updated_at = now() - interval '10 minutes'"
               " WHERE transaction_id = ANY(%s)", ([stale, other_method],))

    rows = PostgresTransactionRepository(pool).stale_pending("UPI", older_than_seconds=300)

    assert [row[0] for row in rows] == [stale]
    assert rows[0][2] == "psp_x"  # the reference the poller needs to ask the PSP


def test_settled_rows_are_never_polled(pool, db):
    merchant_id, terminal_id = _terminal(db)
    _transaction(db, merchant_id, terminal_id, status="SETTLED")
    db.execute("UPDATE transactions SET updated_at = now() - interval '1 hour'")

    assert PostgresTransactionRepository(pool).stale_pending("UPI", older_than_seconds=300) == []


# --- 011: the rail a QR payment actually used ------------------------------------------------------------

def test_by_method_reference_finds_a_qr_payment_by_its_upi_reference(pool, db):
    """The bug Step 11 exposed: a QR payment is stored as QR but carries a UPI PSP reference."""
    merchant_id, terminal_id = _terminal(db)
    qr_transaction = _transaction(db, merchant_id, terminal_id, method="QR", reference="psp_qr_1")
    db.execute("UPDATE transactions SET qr_encoded_rail = 'UPI' WHERE transaction_id = %s", (qr_transaction,))

    found = PostgresTransactionRepository(pool).by_method_reference("psp_qr_1")  # no method filter
    assert found is not None and found[0] == qr_transaction

    narrowed = PostgresTransactionRepository(pool).by_method_reference("psp_qr_1", method="UPI")
    assert narrowed is None  # filtering by UPI would miss it, which is why the filter is optional


def test_the_qr_rail_column_rejects_an_unknown_rail(pool, db):
    merchant_id, terminal_id = _terminal(db)
    transaction_id = _transaction(db, merchant_id, terminal_id, method="QR")
    with pytest.raises(Exception) as raised:
        db.execute("UPDATE transactions SET qr_encoded_rail = 'MAGIC' WHERE transaction_id = %s", (transaction_id,))
    assert "qr_encoded_rail" in str(raised.value)
