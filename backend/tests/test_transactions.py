"""Step 5: POST /api/v1/transactions against a scripted card service.

Requests carry x-terminal-id as the Envoy gateway sets it from the verified client certificate
(gateway/envoy.yaml drops any client-supplied value). End-to-end runs with the real card service and
mock acquirer are in test_transactions_e2e.py."""
import logging
import threading
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.application.transactions import (BadCardData, CardOutcomeUnknown, CardResult, CardServiceUnavailable)
from app.main import create_app
from card_sim import TEST_PAN, encrypted_card

PER_TRANSACTION, PER_DAY = 1_000_000, 2_000_000


class FakeCards:
    """Answers with scripted results (or raises scripted exceptions), then approves."""

    def __init__(self):
        self.script, self.received = [], []

    def process(self, request):
        self.received.append(request)
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return approved()


def approved(status="CAPTURED"):
    return CardResult(status, "431298765012", "A1B2C3", None, "NOT_NEEDED", "411111", "1111")


def failed(code="INSUFFICIENT_FUNDS", category="HARD_DECLINE", retryable=False, reversal="NOT_NEEDED"):
    error = {"error_code": code, "error_message": "declined", "error_category": category, "retryable": retryable}
    return CardResult("FAILED", None, None, error, reversal, "411111", "1111")


@pytest.fixture
def cards():
    return FakeCards()


@pytest.fixture
def pay_client(settings, db, cards):
    with TestClient(create_app(settings, cards=cards)) as c:
        yield c


@pytest.fixture
def ready(db, active):
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', %s, %s) RETURNING profile_id",
        (PER_TRANSACTION, PER_DAY)).fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now()"
               " WHERE terminal_id = %s", (profile_id, active["terminal_id"]))
    return active


@pytest.fixture
def pay(pay_client, ready, merchant):
    """POSTs a card transaction as `ready` (through the gateway). Keyword args override body fields."""
    def call(terminal=None, headers=None, details=None, **fields):
        body = {
            "idempotency_key": str(uuid4()), "amount": 50000, "currency": "INR", "payment_method": "CARD",
            "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28",
                               "card_network": "VISA", **(details or {})},
            "terminal_id": ready["terminal_id"], "merchant_id": str(merchant), **fields,
        }
        h = {"x-terminal-id": terminal or ready["terminal_id"]} if headers is None else headers
        call.last_body = body  # set before sending, so a concurrent test can resend it
        return pay_client.post("/api/v1/transactions", json=body, headers=h), body
    return call


def error_of(r):
    return r.json()["error_code"], r.json()["error_category"], r.json()["retryable"]


def test_approved_card_payment(pay, cards, db, ready):
    r, body = pay(metadata={"order_id": "7781"})
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["status"] == "CAPTURED" and out["auth_code"] == "A1B2C3" and out["method_reference"] == "431298765012"
    assert out["transaction_id"].startswith("txn_") and out["idempotency_key"] == body["idempotency_key"]
    assert out["metadata"] == {"order_id": "7781"} and "error" not in out
    # The card service got the encrypted blob as sent, and acquirer-format IDs.
    sent = cards.received[0]
    assert sent.encrypted_card_data == body["method_details"]["encrypted_card_data"]
    assert sent.kind == "PURCHASE" and len(sent.acquirer_terminal_id) == 8 and len(sent.acquirer_merchant_id) == 15
    row = db.execute("SELECT status, card_bin, card_last4, reversal FROM transactions").fetchone()
    assert row == ("CAPTURED", "411111", "1111", "NOT_NEEDED")
    actions = [a for (a,) in db.execute("SELECT action FROM audit_log WHERE entity_type = 'transaction'"
                                        " ORDER BY audit_id")]
    assert actions == ["transaction.create", "transaction.send", "transaction.finish"]


def test_manual_capture_authorizes_only(pay, cards):
    cards.script.append(approved("AUTHORIZED"))
    r, _ = pay(capture_mode="MANUAL")
    assert r.json()["status"] == "AUTHORIZED" and cards.received[0].kind == "AUTHORIZATION"


def test_decline_is_a_failed_transaction(pay, cards):
    cards.script.append(failed())
    r, _ = pay()
    assert r.status_code == 201 and r.json()["status"] == "FAILED"
    assert r.json()["error"]["error_code"] == "INSUFFICIENT_FUNDS"


def test_same_key_and_body_replays_without_reprocessing(pay, pay_client, cards, ready):
    r1, body = pay()
    r2 = pay_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
    assert r2.status_code == 201 and r2.json() == r1.json()
    assert len(cards.received) == 1


def test_replay_ignores_key_order(pay, pay_client, cards, ready):
    _, body = pay()
    reordered = dict(reversed(list(body.items())))
    r = pay_client.post("/api/v1/transactions", json=reordered, headers={"x-terminal-id": ready["terminal_id"]})
    assert r.status_code == 201 and len(cards.received) == 1


def test_same_key_different_body_is_409(pay, pay_client, ready):
    _, body = pay()
    r = pay_client.post("/api/v1/transactions", json={**body, "amount": 99},
                        headers={"x-terminal-id": ready["terminal_id"]})
    assert r.status_code == 409 and error_of(r) == ("IDEMPOTENCY_KEY_CONFLICT", "VALIDATION_ERROR", False)


def test_retryable_failure_is_not_replayed(pay, pay_client, cards, ready, db):
    cards.script.append(failed("HOST_TIMEOUT", "SYSTEM_ERROR", True, reversal="REVERSED"))
    r1, body = pay()
    assert r1.json()["status"] == "FAILED" and r1.json()["error"]["retryable"] is True
    r2 = pay_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
    assert r2.json()["status"] == "CAPTURED", "the retry was processed, not replayed"
    assert len(cards.received) == 2
    assert db.execute("SELECT count(*) FROM transactions").fetchone()[0] == 2


def test_unknown_outcome_is_pending_and_never_reprocessed(pay, pay_client, cards, ready):
    cards.script.append(CardOutcomeUnknown())
    r1, body = pay()
    assert r1.status_code == 201 and r1.json()["status"] == "PENDING" and "error" not in r1.json()
    r2 = pay_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
    assert r2.json() == r1.json() and len(cards.received) == 1, "a retry must not charge twice"


def test_card_service_down_is_503_and_retryable(pay, pay_client, cards, ready):
    cards.script.append(CardServiceUnavailable("the card service is unavailable; nothing was charged"))
    r, body = pay()
    assert r.status_code == 503 and error_of(r) == ("INTERNAL_ERROR", "SYSTEM_ERROR", True)
    r2 = pay_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
    assert r2.status_code == 201 and r2.json()["status"] == "CAPTURED"


def test_undecryptable_card_is_400(pay, cards):
    cards.script.append(BadCardData("encrypted data could not be decrypted"))
    r, _ = pay()
    assert r.status_code == 400 and error_of(r) == ("INVALID_REQUEST", "VALIDATION_ERROR", False)


def test_concurrent_duplicate_is_told_to_retry(pay, pay_client, cards, ready):
    gate, entered = threading.Event(), threading.Event()
    original = cards.process

    def slow(request):
        entered.set()
        gate.wait(5)
        return original(request)
    cards.process = slow
    results = {}

    def first():
        results["first"], results["body"] = pay()
    t = threading.Thread(target=first)
    t.start()
    assert entered.wait(5)
    # The same request again (identical body) while the first is still with the card service.
    body = pay.last_body
    r = pay_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
    gate.set()
    t.join(5)
    assert r.status_code == 409 and error_of(r) == ("IDEMPOTENCY_KEY_CONFLICT", "SYSTEM_ERROR", True)
    assert results["first"].status_code == 201


def test_no_terminal_identity_is_401(pay):
    r, _ = pay(headers={})
    assert r.status_code == 401 and r.json()["error_code"] == "UNAUTHENTICATED"


def test_body_terminal_must_match_certificate(pay):
    r, _ = pay(terminal_id=str(uuid4()))
    assert r.status_code == 403 and r.json()["error_code"] == "FORBIDDEN"


def test_merchant_must_own_the_terminal(pay):
    r, _ = pay(merchant_id=str(uuid4()))
    assert r.status_code == 422 and r.json()["error_code"] == "MERCHANT_NOT_FOUND"


def test_an_unregistered_method_is_422(pay):
    # CARD, UPI, QR and WALLET are adapters now; OFFLINE is not registered until Step 13.
    r, _ = pay(payment_method="OFFLINE", method_details={})
    assert r.status_code == 422 and r.json()["error_code"] == "INVALID_REQUEST"


@pytest.mark.parametrize("details,field", [
    ({"card_expiry": "13/28"}, "card_expiry"),
    ({"card_network": "DINERS"}, "card_network"),
    ({"pan": TEST_PAN}, "pan"),  # raw card numbers are refused, never stored or echoed
])
def test_invalid_card_details_are_400_without_echoing_values(pay, cards, details, field):
    r, _ = pay(details=details)
    assert r.status_code == 400 and field in r.json()["error_message"]
    assert TEST_PAN not in r.text and not cards.received


def test_per_transaction_limit_declines(pay, cards):
    r, _ = pay(amount=PER_TRANSACTION + 1)
    assert r.status_code == 201 and r.json()["status"] == "FAILED"
    assert "LIMIT_EXCEEDED" in r.json()["error"]["error_message"] and not cards.received


def test_per_day_limit_declines(pay, cards):
    assert pay(amount=PER_TRANSACTION)[0].json()["status"] == "CAPTURED"
    assert pay(amount=PER_TRANSACTION)[0].json()["status"] == "CAPTURED"
    r, _ = pay(amount=1)
    assert r.json()["status"] == "FAILED" and "LIMIT_EXCEEDED" in r.json()["error"]["error_message"]
    assert len(cards.received) == 2


def test_failed_transactions_dont_count_toward_the_daily_limit(pay, cards):
    cards.script.extend([failed(), failed()])
    pay(amount=PER_TRANSACTION)
    pay(amount=PER_TRANSACTION)
    assert pay(amount=PER_TRANSACTION)[0].json()["status"] == "CAPTURED"


def test_unhealthy_terminal_is_declined(pay, cards, db, ready):
    db.execute("UPDATE terminals SET last_heartbeat_at = now() - interval '10 minutes'")
    r, _ = pay()
    assert r.json()["status"] == "FAILED" and "TERMINAL_UNREACHABLE" in r.json()["error"]["error_message"]
    assert not cards.received


def test_nothing_card_related_is_logged(pay, caplog):
    caplog.set_level(logging.DEBUG)
    _, body = pay(details={"cardholder_name": "A Kumar"})
    assert body["method_details"]["encrypted_card_data"] not in caplog.text
    assert "A Kumar" not in caplog.text and TEST_PAN not in caplog.text
