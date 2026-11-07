"""The cascade's attempt trail commits with the state, or not at all (Step 15.5's safety property)."""
from uuid import uuid4

import pytest
from psycopg_pool import ConnectionPool

from app.application.methods import MethodResult
from app.infrastructure.postgres_transactions import PostgresTransactionRepository

TRAIL = [{"host": "psp_1", "status": "FAILED", "retryable": True, "error": "HOST_TIMEOUT"},
         {"host": "psp_2", "status": "SETTLED", "retryable": False, "error": None}]


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=1) as connections:
        yield connections


def _pending_transaction(db):
    merchant_id, terminal_id, transaction_id = uuid4(), uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model)"
               " VALUES (%s, %s, %s, %s)", (terminal_id, merchant_id, "SN-1", "PAX A920 Pro"))
    db.execute(
        "INSERT INTO transactions (transaction_id, idempotency_key, merchant_id, terminal_id, amount, currency,"
        " payment_method, capture_mode, status, method_reference)"
        " VALUES (%s, %s, %s, %s, 100, 'INR', 'UPI', 'AUTO', 'PENDING', 'psp_2')",
        (transaction_id, uuid4(), merchant_id, terminal_id))
    return transaction_id, terminal_id


def _payload(db, transaction_id) -> dict:
    row = db.execute("SELECT payload FROM audit_log WHERE entity_id = %s AND action = 'transaction.finish'",
                     (transaction_id,)).fetchone()
    return row[0]


def test_the_trail_is_written_with_the_final_state(pool, db):
    transaction_id, terminal_id = _pending_transaction(db)
    repo = PostgresTransactionRepository(pool)

    repo.finish(transaction_id, terminal_id, MethodResult(status="SETTLED", method_reference="psp_2"),
                "SETTLED", None, store_response=True, attempts=TRAIL)

    assert _payload(db, transaction_id) == {"attempts": TRAIL}


def test_a_cascade_that_ends_in_failure_still_records_every_attempt(pool, db):
    transaction_id, terminal_id = _pending_transaction(db)
    repo = PostgresTransactionRepository(pool)
    trail = [{"host": "psp_1", "status": "FAILED", "retryable": True, "error": "HOST_TIMEOUT"},
             {"host": "psp_2", "status": "FAILED", "retryable": True, "error": "HOST_TIMEOUT"}]

    repo.finish(transaction_id, terminal_id, None, "FAILED",
                {"error_code": "ALL_HOSTS_FAILED", "error_message": "no host accepted it",
                 "error_category": "SYSTEM_ERROR", "retryable": True},
                store_response=False, attempts=trail)

    assert _payload(db, transaction_id)["attempts"] == trail


def test_a_single_attempt_leaves_the_payload_empty(pool, db):
    """No cascade means no attempts array: existing rows keep the shape they always had."""
    transaction_id, terminal_id = _pending_transaction(db)

    PostgresTransactionRepository(pool).finish(
        transaction_id, terminal_id, MethodResult(status="AUTHORIZED"), "AUTHORIZED", None, store_response=True)

    assert _payload(db, transaction_id) == {}


def test_the_trail_rolls_back_with_the_state(pool, db):
    """The property that matters: a failure after the state write must leave no state and no log.

    The payload here is deliberately unserialisable, so the audit insert fails after the transaction row has
    already been updated inside finish()'s own transaction. Both must disappear together.
    """
    transaction_id, terminal_id = _pending_transaction(db)
    repo = PostgresTransactionRepository(pool)

    with pytest.raises(Exception):
        repo.finish(transaction_id, terminal_id, MethodResult(status="SETTLED"), "SETTLED", None,
                    store_response=True, attempts=[{"host": "psp_1", "bad": object()}])

    assert db.execute("SELECT status FROM transactions WHERE transaction_id = %s",
                      (transaction_id,)).fetchone()[0] == "PENDING"
    assert db.execute("SELECT count(*) FROM audit_log WHERE entity_id = %s AND action = 'transaction.finish'",
                      (transaction_id,)).fetchone()[0] == 0
