"""Step 6: payment intents (merchant server → customer's page), 3-D Secure, terminal checkout and webhooks,
against a scripted card service. test_checkout_browser.py runs the real card frame in a browser."""
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg_pool import ConnectionPool

from app.application.payment_intents import Authentication
from app.application.transactions import CardOutcomeUnknown
from app.infrastructure.postgres_api_keys import create_merchant
from app.main import create_app
from card_sim import encrypted_card
from test_transactions import FakeCards, approved, failed


class FakeCheckoutCards(FakeCards):
    def __init__(self):
        super().__init__()
        self.three_ds = []  # scripted outcomes; FRICTIONLESS once they run out
        self.authenticated = []

    def authenticate(self, transaction_id, encrypted_card_data, encrypted_cvv, amount, currency):
        self.authenticated.append((encrypted_card_data, encrypted_cvv))
        outcome = self.three_ds.pop(0) if self.three_ds else "FRICTIONLESS"
        return Authentication(outcome, "411111", "1111")

    def checkout_key(self):
        return {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}


@pytest.fixture
def cards():
    return FakeCheckoutCards()


@pytest.fixture
def app_client(settings, db, cards):
    app = create_app(settings, cards=cards)
    with TestClient(app) as c:
        c.app_state = app.state
        yield c


@pytest.fixture
def account(database_url, db):
    with ConnectionPool(database_url, min_size=1, max_size=1) as pool:
        return create_merchant(pool)


@pytest.fixture
def merchant_api(app_client, account):
    headers = {"Authorization": f"Bearer {account['secret_key']}"}

    def create(**fields):
        body = {"idempotency_key": str(uuid4()), "amount": 50000, "currency": "INR", **fields}
        return app_client.post("/api/v1/payment_intents", json=body, headers=headers)
    create.headers = headers
    return create


def card(**overrides):
    return {"encrypted_card_data": encrypted_card(), "encrypted_cvv": "sp1.cvv.blob", "card_expiry": "08/28",
            "card_network": "VISA", **overrides}


def confirm(client, intent, secret=None, **card_fields):
    return client.post(f"/api/v1/payment_intents/{intent['id']}/confirm",
                       json={"client_secret": secret or intent["client_secret"], "card": card(**card_fields)})


def otp(client, intent, code):
    return client.post(f"/sandbox/acs/{intent['id']}", json={"client_secret": intent["client_secret"], "otp": code})


def test_create_needs_a_secret_key(app_client):
    r = app_client.post("/api/v1/payment_intents", json={"idempotency_key": str(uuid4()), "amount": 50000,
                                                         "currency": "INR"})
    assert r.status_code == 401 and r.json()["error_code"] == "UNAUTHENTICATED"
    r = app_client.post("/api/v1/payment_intents", headers={"Authorization": "Bearer sk_test_nope"},
                        json={"idempotency_key": str(uuid4()), "amount": 50000, "currency": "INR"})
    assert r.status_code == 401


def test_create_is_idempotent(merchant_api, app_client):
    key = str(uuid4())
    r1 = merchant_api(idempotency_key=key, metadata={"order": "7781"})
    assert r1.status_code == 201, r1.text
    intent = r1.json()
    assert intent["id"].startswith("pi_") and intent["client_secret"].startswith(intent["id"] + "_secret_")
    assert intent["status"] == "REQUIRES_PAYMENT_METHOD" and intent["metadata"] == {"order": "7781"}
    r2 = merchant_api(idempotency_key=key, metadata={"order": "7781"})
    assert r2.status_code == 200 and r2.json()["id"] == intent["id"]
    r3 = merchant_api(idempotency_key=key, amount=1)
    assert r3.status_code in (400, 409)
    r4 = merchant_api(idempotency_key=key, amount=60000)
    assert r4.status_code == 409 and r4.json()["error_code"] == "IDEMPOTENCY_KEY_CONFLICT"


def test_minimum_amount_is_one_rupee(merchant_api):
    assert merchant_api(amount=99).status_code == 400


def test_frictionless_card_payment(merchant_api, app_client, cards, db):
    intent = merchant_api().json()
    r = confirm(app_client, intent)
    assert r.status_code == 200, r.text
    paid = r.json()
    assert paid["status"] == "SUCCEEDED" and paid["transaction_id"].startswith("txn_")
    assert paid["card"] == {"bin": "411111", "last4": "1111"}
    assert "client_secret" not in paid and "metadata" not in paid, "the customer's page sees the public view"
    sent = cards.received[0]
    assert sent.amount == 50000 and sent.kind == "PURCHASE" and sent.acquirer_terminal_id.startswith("E")
    row = db.execute("SELECT channel, terminal_id, status FROM transactions").fetchone()
    assert row == ("ONLINE", None, "CAPTURED")


def test_three_ds_challenge_then_otp(merchant_api, app_client, cards, db):
    cards.three_ds += ["CHALLENGE", "CHALLENGE"]
    intent = merchant_api().json()
    waiting = confirm(app_client, intent).json()
    assert waiting["status"] == "REQUIRES_ACTION"
    assert waiting["next_action"]["type"] == "THREE_DS_CHALLENGE"
    assert waiting["next_action"]["url"].startswith(f"/sandbox/acs/{intent['id']}?client_secret=")
    (pending,) = db.execute("SELECT pending_card FROM payment_intents").fetchone()
    assert "encrypted_cvv" not in pending, "the CVV is never kept, even encrypted"
    assert not cards.received, "nothing is authorized before the cardholder is authenticated"

    page = app_client.get(waiting["next_action"]["url"])
    assert page.status_code == 200 and "500.00" in page.text and "1111" in page.text

    wrong = otp(app_client, intent, "000000").json()
    assert wrong["status"] == "REQUIRES_PAYMENT_METHOD"
    assert wrong["last_payment_error"]["error_code"] == "AUTHENTICATION_FAILED"
    assert db.execute("SELECT pending_card FROM payment_intents").fetchone() == (None,)

    assert confirm(app_client, intent).json()["status"] == "REQUIRES_ACTION"
    paid = otp(app_client, intent, "123456").json()
    assert paid["status"] == "SUCCEEDED" and len(cards.received) == 1
    assert db.execute("SELECT pending_card FROM payment_intents").fetchone() == (None,)


def test_issuer_refuses_authentication(merchant_api, app_client, cards):
    cards.three_ds.append("REJECTED")
    r = confirm(app_client, merchant_api().json()).json()
    assert r["status"] == "REQUIRES_PAYMENT_METHOD" and r["last_payment_error"]["error_code"] == "AUTHENTICATION_FAILED"
    assert not cards.received


def test_decline_lets_the_customer_try_another_card(merchant_api, app_client, cards):
    cards.script.append(failed())
    intent = merchant_api().json()
    declined = confirm(app_client, intent).json()
    assert declined["status"] == "REQUIRES_PAYMENT_METHOD"
    assert declined["last_payment_error"]["error_code"] == "INSUFFICIENT_FUNDS"
    retried = confirm(app_client, intent).json()
    assert retried["status"] == "SUCCEEDED" and "last_payment_error" not in retried
    assert len(cards.received) == 2


def test_double_click_never_charges_twice(merchant_api, app_client, cards):
    intent = merchant_api().json()
    assert confirm(app_client, intent).json()["status"] == "SUCCEEDED"
    again = confirm(app_client, intent)
    assert again.status_code == 200 and again.json()["status"] == "SUCCEEDED"
    assert len(cards.received) == 1


def test_unknown_outcome_leaves_it_processing(merchant_api, app_client, cards):
    cards.script.append(CardOutcomeUnknown())
    r = confirm(app_client, merchant_api().json()).json()
    assert r["status"] == "PROCESSING"


def test_client_secret_must_match(merchant_api, app_client):
    intent = merchant_api().json()
    other = merchant_api().json()
    r = confirm(app_client, intent, secret=other["client_secret"])
    assert r.status_code == 404 and r.json()["error_code"] == "PAYMENT_INTENT_NOT_FOUND"
    r = app_client.get(f"/api/v1/payment_intents/{intent['id']}", params={"client_secret": intent["client_secret"]})
    assert r.status_code == 200 and "client_secret" not in r.json()
    assert app_client.get(f"/api/v1/payment_intents/{intent['id']}").status_code == 401


def test_merchants_only_see_their_own_intents(merchant_api, app_client, database_url):
    intent = merchant_api().json()
    r = app_client.get(f"/api/v1/payment_intents/{intent['id']}", headers=merchant_api.headers)
    assert r.status_code == 200 and r.json()["client_secret"] == intent["client_secret"]
    with ConnectionPool(database_url, min_size=1, max_size=1) as pool:
        other = create_merchant(pool)
    r = app_client.get(f"/api/v1/payment_intents/{intent['id']}",
                       headers={"Authorization": f"Bearer {other['secret_key']}"})
    assert r.status_code == 404


def test_cancel(merchant_api, app_client, cards):
    intent = merchant_api().json()
    r = app_client.post(f"/api/v1/payment_intents/{intent['id']}/cancel", headers=merchant_api.headers)
    assert r.status_code == 200 and r.json()["status"] == "CANCELED"
    assert confirm(app_client, intent).json()["status"] == "CANCELED" and not cards.received
    again = app_client.post(f"/api/v1/payment_intents/{intent['id']}/cancel", headers=merchant_api.headers)
    assert again.status_code == 409


def test_checkout_key_and_card_frame_are_served(app_client):
    assert app_client.get("/api/v1/checkout/key").json()["crv"] == "P-256"
    frame = app_client.get("/checkout/card-frame")
    assert frame.status_code == 200 and "script-src 'self'" in frame.headers["content-security-policy"]
    assert app_client.get("/checkout/card-frame.js").status_code == 200
    assert app_client.get("/checkout/../main.py").status_code == 404


def test_browsers_on_other_origins_may_read_with_a_client_secret(app_client):
    r = app_client.options("/api/v1/checkout/key", headers={
        "Origin": "https://shop.example", "Access-Control-Request-Method": "GET"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] in ("*", "https://shop.example")


# Terminal checkout: a web POS creates an intent for a terminal; the terminal picks it up and takes the card.


@pytest.fixture
def ready_terminal(db, active, account):
    """`active`, moved to the account's merchant, certified for CARD and heard from just now."""
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', 10000000, 100000000) RETURNING profile_id").fetchone()
    db.execute("UPDATE terminals SET merchant_id = %s, certification_profile_id = %s, last_heartbeat_at = now()"
               " WHERE terminal_id = %s", (account["merchant_id"], profile_id, active["terminal_id"]))
    return active


def test_terminal_checkout(merchant_api, app_client, ready_terminal, account, cards):
    terminal_id = ready_terminal["terminal_id"]
    as_terminal = {"x-terminal-id": terminal_id}
    checkout = f"/api/v1/terminals/{terminal_id}/checkout"
    assert app_client.get(checkout, headers=as_terminal).status_code == 204

    intent = merchant_api(terminal_id=terminal_id, description="Table 4").json()
    job = app_client.get(checkout, headers=as_terminal, params={"wait": 1})
    assert job.status_code == 200, job.text
    assert job.json() == {"payment_intent_id": intent["id"], "amount": 50000, "currency": "INR",
                          "capture_mode": "AUTO", "description": "Table 4", "expires_at": intent["expires_at"]}
    assert app_client.get(checkout, headers={"x-terminal-id": str(uuid4())}).status_code == 403
    assert confirm(app_client, intent).status_code == 409, "a terminal intent is paid on the terminal"

    def pay(amount):
        body = {"idempotency_key": str(uuid4()), "amount": amount, "currency": "INR", "payment_method": "CARD",
                "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28",
                                   "card_network": "VISA"},
                "terminal_id": terminal_id, "merchant_id": account["merchant_id"],
                "payment_intent_id": intent["id"]}
        return app_client.post("/api/v1/transactions", json=body, headers=as_terminal)

    wrong = pay(1)
    assert wrong.status_code == 409 and "amount" in wrong.json()["error_message"]
    r = pay(50000)
    assert r.status_code == 201 and r.json()["status"] == "CAPTURED" and r.json()["payment_intent_id"] == intent["id"]
    status = app_client.get(f"/api/v1/payment_intents/{intent['id']}",
                            params={"client_secret": intent["client_secret"]}).json()
    assert status["status"] == "SUCCEEDED" and status["transaction_id"] == r.json()["transaction_id"]
    assert app_client.get(checkout, headers=as_terminal).status_code == 204, "picked up once only"
    assert pay(50000).status_code == 409, "an intent is paid once"


def test_terminal_intent_needs_an_active_terminal_of_the_merchant(merchant_api, active):
    r = merchant_api(terminal_id=active["terminal_id"])  # belongs to another merchant
    assert r.status_code == 404


# Webhooks


class Receiver:
    """A local webhook endpoint that records requests and answers with a scripted status."""

    def __init__(self):
        self.requests, self.statuses = [], []
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                receiver.requests.append((dict(self.headers), body))
                self.send_response(receiver.statuses.pop(0) if receiver.statuses else 200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/webhooks"

    def close(self):
        self.server.shutdown()


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


def test_webhook_is_signed_and_delivered(merchant_api, app_client, receiver, account):
    intent = merchant_api(webhook_url=receiver.url).json()
    confirm(app_client, intent)
    assert app_client.app_state.webhooks.deliver_due() == 1
    headers, body = receiver.requests[0]
    expected = hmac.new(account["webhook_secret"].encode(), body, hashlib.sha256).hexdigest()
    assert headers["x-signature"] == expected or headers.get("X-Signature") == expected
    event = json.loads(body)
    assert event["status"] == "CAPTURED" and event["payment_intent_id"] == intent["id"]
    assert app_client.app_state.webhooks.deliver_due() == 0, "delivered once"


def test_failed_webhook_is_retried_later(merchant_api, app_client, receiver, db):
    receiver.statuses.append(500)
    confirm(app_client, merchant_api(webhook_url=receiver.url).json())
    assert app_client.app_state.webhooks.deliver_due() == 0
    attempts, error, later = db.execute(
        "SELECT attempts, last_error, next_attempt_at > now() FROM webhook_deliveries").fetchone()
    assert (attempts, error, later) == (1, "HTTP 500", True)
    db.execute("UPDATE webhook_deliveries SET next_attempt_at = now()")
    assert app_client.app_state.webhooks.deliver_due() == 1


def test_terminal_payment_webhook(app_client, ready, merchant, receiver, db):
    db.execute("UPDATE merchants SET webhook_secret = 'whsec_test'")
    body = {"idempotency_key": str(uuid4()), "amount": 50000, "currency": "INR", "payment_method": "CARD",
            "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA"},
            "terminal_id": ready["terminal_id"], "merchant_id": str(merchant), "webhook_url": "https://example.invalid/h"}
    assert app_client.post("/api/v1/transactions", json=body,
                           headers={"x-terminal-id": ready["terminal_id"]}).status_code == 201
    (queued,) = db.execute("SELECT count(*) FROM webhook_deliveries").fetchone()
    assert queued == 1


@pytest.fixture
def ready(db, active):
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', 10000000, 100000000) RETURNING profile_id").fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now()"
               " WHERE terminal_id = %s", (profile_id, active["terminal_id"]))
    return active


def test_an_online_card_payment_lands_in_the_ledger(merchant_api, app_client, account, cards, db):
    """PR 1: intents finish through their own repository, and post the SALE there, in the same transaction."""
    paid = confirm(app_client, merchant_api().json()).json()
    assert paid["status"] == "SUCCEEDED", paid
    rows = db.execute(
        "SELECT e.merchant_id::text, a.code, p.debit_amount, p.credit_amount FROM journal_entries e"
        " JOIN ledger_postings p USING (journal_entry_id) JOIN accounts a USING (account_id)"
        " WHERE e.transaction_id = (SELECT transaction_id FROM transactions) ORDER BY a.code").fetchall()
    assert rows == [(account["merchant_id"], "1000", 50_000, 0), (account["merchant_id"], "2000", 0, 50_000)]
