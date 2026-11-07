"""Step 5 end to end: backend → card service (Rust, simulated HSM) → host connector → mock acquirer over
mutual TLS (host-connector/mock_host/mock_host.py). Real processes, real ISO 8583 on the wire.

Needs cargo (builds card-service) and the openssl CLI (terminal fixtures). The mock acquirer picks the outcome
by amount: 5100 declines, 2000 times out, anything else approves."""
import statistics
import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.infrastructure.card_service_client import HttpCardProcessor
from app.main import create_app
from card_sim import TEST_PAN, encrypted_card, encrypted_pin
from e2e_stack import needs_cargo

pytestmark = needs_cargo


@pytest.fixture
def e2e_client(settings, db, acquirer):
    cards = HttpCardProcessor(acquirer[0])
    with TestClient(create_app(settings, cards=cards)) as c:
        yield c
    cards.close()


@pytest.fixture
def ready(db, active):
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', 10000000, 100000000) RETURNING profile_id").fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now()"
               " WHERE terminal_id = %s", (profile_id, active["terminal_id"]))
    return active


@pytest.fixture
def pay(e2e_client, ready, merchant):
    def call(amount, pin=None):
        details = {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA"}
        if pin:
            details["pin_block"] = encrypted_pin(pin)
        body = {"idempotency_key": str(uuid4()), "amount": amount, "currency": "INR", "payment_method": "CARD",
                "method_details": details, "terminal_id": ready["terminal_id"], "merchant_id": str(merchant)}
        r = e2e_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
        assert r.status_code in (201, 400), r.text
        return r
    return call


def test_approval_end_to_end(pay, db):
    r = pay(15000)
    assert r.json()["status"] == "CAPTURED" and r.json()["auth_code"] == "AUTH00", r.text
    assert db.execute("SELECT card_bin, card_last4 FROM transactions").fetchone() == ("411111", "1111")


def test_decline_end_to_end(pay):
    r = pay(5100)
    assert r.json()["status"] == "FAILED" and r.json()["error"]["error_code"] == "INSUFFICIENT_FUNDS"


def test_pin_payment_over_5000_rupees(pay):
    assert pay(600000, pin="1234").json()["status"] == "CAPTURED"


def test_host_timeout_is_reversed_end_to_end(pay, db, acquirer):
    started = time.monotonic()
    r = pay(2000)
    body = r.json()
    assert body["status"] == "FAILED" and body["error"]["error_code"] == "HOST_TIMEOUT", r.text
    assert body["error"]["retryable"] is True
    assert db.execute("SELECT reversal FROM transactions").fetchone() == ("REVERSED",)
    assert time.monotonic() - started < 6
    assert "0400" in acquirer[1].output and "-> reversed" in acquirer[1].output, "the acquirer got the reversal"


def test_undecryptable_card_is_rejected_end_to_end(e2e_client, ready, merchant):
    body = {"idempotency_key": str(uuid4()), "amount": 15000, "currency": "INR", "payment_method": "CARD",
            "method_details": {"encrypted_card_data": encrypted_card(bdk_hex="11" * 32), "card_expiry": "08/28",
                               "card_network": "VISA"},
            "terminal_id": ready["terminal_id"], "merchant_id": str(merchant)}
    r = e2e_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
    assert r.status_code == 400 and r.json()["error_code"] == "INVALID_REQUEST"


def test_p95_latency_under_2_seconds(pay):
    pay(15000)  # warm up
    times = []
    for _ in range(30):
        started = time.monotonic()
        assert pay(15000).json()["status"] == "CAPTURED"
        times.append(time.monotonic() - started)
    p95 = statistics.quantiles(times, n=20)[-1]
    print(f"card payment latency: median {statistics.median(times) * 1000:.0f} ms, p95 {p95 * 1000:.0f} ms")
    assert p95 < 2.0, f"p95 {p95:.3f}s"


def test_card_number_never_leaves_the_card_service(pay, acquirer):
    pay(15000)
    _, mock, service, audit = acquirer
    assert TEST_PAN not in service.output, "card service output"
    assert TEST_PAN not in audit.read_text(), "ISO 8583 audit log"
    assert '"2":"411111******1111"' in audit.read_text(), "DE 2 is audited masked"
