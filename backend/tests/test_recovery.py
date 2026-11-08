"""PR 2 and PR 3 gates, against Postgres: a late answer can't overwrite a final one, a request that died before the
network is failed and its key freed, and a stuck card payment resolves once its queued reversal lands."""
import hashlib
import hmac
import json
import time
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg_pool import ConnectionPool

from app.api import upi_webhooks as webhook_api
from app.application.methods import MethodResult
from app.application.recovery import sweep_async_pending, sweep_card_pending, sweep_stuck_keys
from app.application.transactions import NewTransaction, TransactionSuperseded
from app.application.upi_webhooks import UpiWebhookHandler
from app.infrastructure.methods.upi import UpiMethodAdapter
from app.infrastructure.postgres_transactions import PostgresTransactionRepository

SECRET = "whsec_test_secret"


@pytest.fixture
def repo(database_url, db):
    with ConnectionPool(database_url, min_size=1, max_size=2) as pool:
        yield PostgresTransactionRepository(pool)


@pytest.fixture
def new(repo, created, merchant):
    """claim(method) -> (transaction_id, terminal_id): an INITIATED payment holding an IN_FLIGHT key."""
    terminal_id = UUID(created["terminal_id"])

    def claim(method="UPI", amount=15000):
        key = uuid4()
        c = repo.claim(NewTransaction(key, hashlib.sha256(key.bytes).digest(), merchant, terminal_id, amount, "INR",
                                      method, "AUTO", None, {}))
        return c.transaction_id, terminal_id
    return claim


def statuses(db, transaction_id):
    return db.execute("SELECT status FROM transactions WHERE transaction_id = %s", (transaction_id,)).fetchone()[0]


def key_state(db, transaction_id):
    row = db.execute("SELECT state FROM idempotency_keys WHERE transaction_id = %s", (transaction_id,)).fetchone()
    return row and row[0]


class FakeEvents:
    def claim(self, provider, event_id):
        return True


class FakePsp:
    def validate_vpa(self, vpa):
        return {"vpa": vpa, "name": "Asha Menon"}


def upi_webhook(client, **body):
    raw = json.dumps({"event_id": str(uuid4()), "rrn": "123456789012", **body}).encode()
    sent_at = int(time.time())
    signature = hmac.new(SECRET.encode(), f"{sent_at}.".encode() + raw, hashlib.sha256).hexdigest()
    return client.post("/api/v1/webhooks/upi", content=raw, headers={
        "X-UPI-Timestamp": str(sent_at), "X-UPI-Signature": signature, "Content-Type": "application/json"})


def test_1_a_late_failed_webhook_cannot_overwrite_a_settled_payment(repo, new, db):
    transaction_id, terminal_id = new("UPI")
    repo.mark_pending(transaction_id, terminal_id)
    repo.finish(transaction_id, terminal_id, MethodResult(status="SETTLED", method_reference="psp_late"), "SETTLED",
                None, store_response=True)
    app = FastAPI()
    app.state.upi_webhooks = UpiWebhookHandler(UpiMethodAdapter(FakePsp(), webhook_secret=SECRET), repo, FakeEvents())
    app.include_router(webhook_api.router)

    r = upi_webhook(TestClient(app), psp_transaction_id="psp_late", status="FAILURE", reason="INSUFFICIENT_FUNDS")

    assert r.status_code == 200, r.text
    assert statuses(db, transaction_id) == "SETTLED", "the late FAILED answer must not overwrite the success"
    row = db.execute("SELECT from_status, to_status, payload FROM audit_log WHERE entity_id = %s"
                     " AND action = 'transaction.discrepancy'", (transaction_id,)).fetchone()
    assert row is not None and row[0] == row[1] == "SETTLED"
    assert row[2]["current"] == "SETTLED" and row[2]["attempted"] == "FAILED"
    (stored,) = db.execute("SELECT response FROM idempotency_keys WHERE transaction_id = %s",
                           (transaction_id,)).fetchone()
    assert stored["status"] == "SETTLED", "a retry still replays the truth"


def test_the_same_success_again_is_silent(repo, new, db):
    transaction_id, terminal_id = new("UPI")
    repo.mark_pending(transaction_id, terminal_id)
    for _ in range(2):
        repo.finish(transaction_id, terminal_id, MethodResult(status="SETTLED"), "SETTLED", None, store_response=True)
    assert db.execute("SELECT count(*) FROM audit_log WHERE entity_id = %s AND action = 'transaction.discrepancy'",
                      (transaction_id,)).fetchone()[0] == 0


def test_2_a_request_that_died_before_the_network_is_failed_and_its_key_freed(repo, new, db):
    stuck, terminal_id = new("UPI")                      # died between claim and send
    sent, _ = new("UPI")
    repo.mark_pending(sent, terminal_id)                 # reached the network: must be left alone
    db.execute("UPDATE idempotency_keys SET created_at = now() - interval '10 minutes'")

    assert sweep_stuck_keys(repo) == 1
    assert statuses(db, stuck) == "FAILED" and key_state(db, stuck) is None, "failed, and the key is reusable"
    (error,) = db.execute("SELECT error FROM transactions WHERE transaction_id = %s", (stuck,)).fetchone()
    assert error["retryable"] is True
    assert statuses(db, sent) == "PENDING" and key_state(db, sent) == "IN_FLIGHT", "a sent payment keeps its key"

    # The stalled request wakes up after the sweep: it must not send the payment it no longer owns.
    with pytest.raises(TransactionSuperseded):
        repo.mark_pending(stuck, terminal_id)


class Reversals:
    def __init__(self, states):
        self.states = states

    def reversal_state(self, transaction_id):
        return self.states.get(transaction_id)


def test_3_a_stuck_card_payment_resolves_once_its_reversal_lands(repo, new, db):
    reversed_, terminal_id = new("CARD")
    owed, _ = new("CARD")
    for transaction_id in (reversed_, owed):
        repo.mark_pending(transaction_id, terminal_id)
        repo.finish(transaction_id, terminal_id, MethodResult(status="PENDING", reversal="FAILED", bin="411111",
                                                              last4="1111"), "PENDING", None, store_response=True)
    db.execute("UPDATE transactions SET updated_at = now() - interval '10 minutes'")

    assert sweep_card_pending(repo, Reversals({reversed_: "REVERSED", owed: "PENDING"})) == 1
    row = db.execute("SELECT status, reversal, card_last4, error->>'error_code' FROM transactions"
                     " WHERE transaction_id = %s", (reversed_,)).fetchone()
    assert row == ("FAILED", "REVERSED", "1111", "HOST_TIMEOUT"), "resolved, keeping what was already known"
    assert key_state(db, reversed_) is None, "the customer was not charged: a retry with the same key is safe"
    assert statuses(db, owed) == "PENDING", "still owed: left for the next pass"
    # Nothing posted to the ledger for a payment that never took money.
    assert db.execute("SELECT count(*) FROM journal_entries WHERE transaction_id = %s",
                      (reversed_,)).fetchone()[0] == 0


class ApprovingPsp:
    """The PSP's status endpoint says the collect succeeded: the webhook that should have said so was lost."""

    def status(self, reference):
        return {"psp_transaction_id": reference, "status": "SUCCESS", "rrn": "123456789012"}


def test_3b_a_stuck_upi_payment_settles_from_the_psp_and_the_ledger_balances(repo, new, db):
    transaction_id, terminal_id = new("UPI", amount=25000)
    repo.mark_pending(transaction_id, terminal_id)
    repo.finish(transaction_id, terminal_id, MethodResult(status="PENDING", method_reference="psp_lost"), "PENDING",
                None, store_response=True)
    db.execute("UPDATE transactions SET updated_at = now() - interval '10 minutes'")

    assert sweep_async_pending(repo, [("UPI", UpiMethodAdapter(ApprovingPsp()))], older_than_seconds=300) == 1

    assert statuses(db, transaction_id) == "SETTLED"
    debits, credits, entries = db.execute(
        "SELECT sum(p.debit_amount), sum(p.credit_amount), count(DISTINCT e.journal_entry_id)"
        " FROM journal_entries e JOIN ledger_postings p USING (journal_entry_id) WHERE e.transaction_id = %s",
        (transaction_id,)).fetchone()
    assert entries == 1 and debits == credits == 25000, "one SALE, and it balances"
