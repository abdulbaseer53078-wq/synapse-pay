"""Step 15 end to end: a soft decline on the first host cascades to the second, and the audit trail records
both what we asked for and what actually answered.

Two layers, both against the same engine and the same audit table:

* the card service is scripted, so the test is about the cascade and the trail the repository persists;
* the real stack runs Python → card service (Rust fleet) → two mock ISO 8583 acquirers, one answering DE 39
  "91" (a soft decline) and one approving. That is the cross-runtime path a merchant actually exercises.
"""
from dataclasses import replace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.application.transactions import CardResult, parse_public_id
from app.infrastructure.card_service_client import HttpCardProcessor
from app.main import create_app
from card_sim import encrypted_card
from e2e_stack import needs_cargo

PER_TRANSACTION, PER_DAY = 1_000_000, 2_000_000


class TwoHostCards:
    """The card service as the fleet sees it: `host_hint` chooses who is asked.

    psp_1 soft-declines (the issuer is temporarily unavailable: response code 91), psp_2 approves. Both report
    `host_used`, exactly as the Rust service does.
    """

    def __init__(self):
        self.received = []

    def process(self, request):
        self.received.append(request)
        host = (request.host_hint or [None])[0]
        if host == "psp_1":
            return CardResult(
                status="FAILED", method_reference=None, auth_code=None,
                error={"error_code": "ISSUER_DECLINED",
                       "error_message": "declined by the issuer (response code 91)",
                       "error_category": "SOFT_DECLINE", "retryable": True},
                reversal="NOT_NEEDED", card_bin="411111", card_last4="1111", host_used="psp_1")
        if host == "psp_2":
            return CardResult(
                status="CAPTURED", method_reference="ref_psp_2", auth_code="A1B2C3", error=None,
                reversal="NOT_NEEDED", card_bin="411111", card_last4="1111", host_used="psp_2")
        raise AssertionError(f"the engine asked a host it was not routed to: {request.host_hint}")


@pytest.fixture
def cards():
    return TwoHostCards()


@pytest.fixture
def routed_settings(settings):
    # No background poll for the duration of the test; the test installs the health snapshot itself.
    return replace(settings, routing_rules={"CARD": ("psp_1", "psp_2")},
                   card_hosts=("psp_1", "psp_2"), health_poll_seconds=3600)


@pytest.fixture
def routed_client(routed_settings, db, cards):
    app = create_app(routed_settings, cards=cards)
    with TestClient(app) as client:
        app.state.health.registry.card_source = lambda: [
            {"host_id": "psp_1", "status": "UP", "latency_ms": 20},
            {"host_id": "psp_2", "status": "UP", "latency_ms": 30},
        ]
        app.state.health.refresh()
        yield client


@pytest.fixture
def ready(db, active):
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', %s, %s) RETURNING profile_id",
        (PER_TRANSACTION, PER_DAY)).fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now()"
               " WHERE terminal_id = %s", (profile_id, active["terminal_id"]))
    return active


def _payload(db, transaction_id):
    row = db.execute("SELECT payload FROM audit_log WHERE entity_id = %s AND action = 'transaction.finish'",
                     (transaction_id,)).fetchone()
    assert row is not None, "the finish step must leave exactly one audit row"
    return row[0]


def test_a_soft_decline_cascades_and_the_audit_records_both_hosts(routed_client, ready, merchant, cards, db):
    body = {
        "idempotency_key": str(uuid4()), "amount": 50_000, "currency": "INR", "payment_method": "CARD",
        "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28",
                           "card_network": "VISA"},
        "terminal_id": ready["terminal_id"], "merchant_id": str(merchant),
    }
    response = routed_client.post("/api/v1/transactions", json=body,
                                  headers={"x-terminal-id": ready["terminal_id"]})

    assert response.status_code == 201, response.text
    out = response.json()
    assert out["status"] == "CAPTURED" and out["method_reference"] == "ref_psp_2"

    # The engine asked psp_1 first, heard a soft decline, then asked psp_2. One host per attempt, in order.
    assert [request.host_hint for request in cards.received] == [["psp_1"], ["psp_2"]]

    transaction_id = parse_public_id(out["transaction_id"], "txn_")
    attempts = _payload(db, transaction_id)["attempts"]
    assert [attempt["asked"] for attempt in attempts] == ["psp_1", "psp_2"]
    assert [attempt["host"] for attempt in attempts] == ["psp_1", "psp_2"]
    assert attempts[0]["status"] == "FAILED" and attempts[0]["retryable"] is True
    assert attempts[0]["error"] == "ISSUER_DECLINED"
    assert attempts[0]["error_category"] == "SOFT_DECLINE"
    assert attempts[1]["status"] == "CAPTURED" and attempts[1]["retryable"] is False
    assert attempts[1]["error"] is None

    # The customer was charged once, by the host that approved: the soft decline never became a transaction.
    assert db.execute("SELECT status, method_reference FROM transactions WHERE transaction_id = %s",
                      (transaction_id,)).fetchone() == ("CAPTURED", "ref_psp_2")


@needs_cargo
def test_a_soft_decline_cascades_across_two_real_acquirers(settings, db, ready, merchant, multi_acquirer):
    """The same cascade through the real stack: Python → card service (Rust fleet) → two mock acquirers.

    psp_1 is a real ISO 8583 host answering DE 39 "91" (issuer unavailable: a soft decline), psp_2 is a second
    real host that approves. The card service runs in fleet mode from `HOSTS`, so this also pins the per-host
    address mapping in main.rs — the wiring that makes the whole thing a fleet rather than two processes.
    """
    routed = replace(settings, card_service_url=multi_acquirer["url"],
                     routing_rules={"CARD": ("psp_1", "psp_2")},
                     card_hosts=("psp_1", "psp_2"), health_poll_seconds=3600)
    cards = HttpCardProcessor(multi_acquirer["url"])
    try:
        with TestClient(create_app(routed, cards=cards)) as client:
            body = {
                "idempotency_key": str(uuid4()), "amount": 5300, "currency": "INR", "payment_method": "CARD",
                "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28",
                                   "card_network": "VISA"},
                "terminal_id": ready["terminal_id"], "merchant_id": str(merchant),
            }
            response = client.post("/api/v1/transactions", json=body,
                                   headers={"x-terminal-id": ready["terminal_id"]})
    finally:
        cards.close()

    assert response.status_code == 201, response.text
    out = response.json()
    assert out["status"] == "CAPTURED" and out["auth_code"] == "AUTH00"

    attempts = _payload(db, parse_public_id(out["transaction_id"], "txn_"))["attempts"]
    assert [attempt["asked"] for attempt in attempts] == ["psp_1", "psp_2"]
    assert [attempt["host"] for attempt in attempts] == ["psp_1", "psp_2"]
    assert attempts[0]["error_category"] == "SOFT_DECLINE" and attempts[0]["retryable"] is True
    assert attempts[1]["status"] == "CAPTURED" and attempts[1]["retryable"] is False

    # What the acquirers themselves saw: the first was asked and said "91"; the second only saw the cascade.
    assert "amount=5300 -> soft-decline" in multi_acquirer["mock_a"].output
    assert "amount=5300 -> approve" in multi_acquirer["mock_b"].output
