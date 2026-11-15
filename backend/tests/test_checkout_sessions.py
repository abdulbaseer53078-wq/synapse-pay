"""Checkout sessions: create, retrieve, and pay. No database — FakeCheckoutSessions stands in."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import checkout_sessions as checkout_sessions_api
from app.api import errors as errors_module
from app.api.api_keys import verify_api_key
from app.application.transactions import CardRequest, CardResult

MERCHANT = uuid4()
BASE_URL = "https://pay.example.com"


class FakeCheckoutSessions:
    def __init__(self, base_url: str = BASE_URL):
        self._rows: dict[str, dict] = {}
        self._base_url = base_url

    def create(self, merchant_id, amount, currency, description, success_url, cancel_url, metadata) -> dict:
        session_id = uuid4()
        url_token = f"tok_{session_id.hex[:16]}"
        now = datetime.now(UTC)
        row = {
            "session_id": f"cs_{session_id.hex}",
            "checkout_url": f"{self._base_url}/pay/{url_token}",
            "amount": amount,
            "currency": currency,
            "description": description,
            "status": "OPEN",
            "intent_id": None,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata": metadata,
            "expires_at": (now + timedelta(minutes=30)).isoformat(),
            "created_at": now.isoformat(),
            "_merchant_id": merchant_id,
        }
        self._rows[row["session_id"]] = row
        return {k: v for k, v in row.items() if not k.startswith("_")}

    def get(self, session_id_str: str, merchant_id) -> dict | None:
        row = self._rows.get(session_id_str)
        if row is None or row["_merchant_id"] != merchant_id:
            return None
        return {k: v for k, v in row.items() if not k.startswith("_")}

    def get_for_pay(self, session_id_str: str) -> dict | None:
        row = self._rows.get(session_id_str)
        if row is None:
            return None
        return {"session_id": row["session_id"], "merchant_id": row["_merchant_id"],
                "amount": row["amount"], "currency": row["currency"], "status": row["status"],
                "expires_at": datetime.now(UTC) + timedelta(minutes=30),
                "success_url": row["success_url"], "cancel_url": row["cancel_url"]}

    def begin_pay(self, session_id_str: str) -> bool:
        row = self._rows.get(session_id_str)
        if row is None or row["status"] != "OPEN":
            return False
        row["status"] = "PROCESSING"
        return True

    def complete(self, session_id_str: str) -> None:
        self._rows[session_id_str]["status"] = "COMPLETED"

    def reopen(self, session_id_str: str) -> None:
        row = self._rows.get(session_id_str)
        if row and row["status"] == "PROCESSING":
            row["status"] = "OPEN"


class FakeCardProcessor:
    def __init__(self, status: str = "APPROVED", error: dict | None = None):
        self.status = status
        self.error = error
        self.calls: list[CardRequest] = []

    def process(self, request: CardRequest) -> CardResult:
        self.calls.append(request)
        return CardResult(status=self.status, method_reference="REF123", auth_code="AUTH1",
                          error=self.error, reversal="NONE", card_bin="411111", card_last4="1111")


@pytest.fixture
def api():
    fake = FakeCheckoutSessions()
    cards = FakeCardProcessor()
    app = FastAPI()
    errors_module.install(app)
    app.include_router(checkout_sessions_api.router)
    app.state.checkout_sessions = fake
    app.state.cards = cards
    app.dependency_overrides[verify_api_key] = lambda: MERCHANT
    with TestClient(app) as client:
        yield client, fake, cards


def _body(**kwargs):
    return {"amount": 50_000, "currency": "INR", "success_url": "https://shop.example/ok",
            "cancel_url": "https://shop.example/cancel", **kwargs}


def test_create_returns_open_session_with_checkout_url(api):
    client, _, _c = api
    r = client.post("/api/v1/checkout/sessions", json=_body(description="Test order"))
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "OPEN"
    assert body["session_id"].startswith("cs_")
    assert "/pay/" in body["checkout_url"]
    assert body["amount"] == 50_000
    assert body["intent_id"] is None


def test_get_returns_created_session(api):
    client, _, _c = api
    created = client.post("/api/v1/checkout/sessions", json=_body()).json()
    r = client.get(f"/api/v1/checkout/sessions/{created['session_id']}")
    assert r.status_code == 200
    fetched = r.json()
    assert fetched["session_id"] == created["session_id"]
    assert fetched["amount"] == created["amount"]
    assert fetched["status"] == "OPEN"


def test_get_unknown_session_returns_404(api):
    client, _, _c = api
    r = client.get(f"/api/v1/checkout/sessions/cs_{'0' * 32}")
    assert r.status_code == 404
    assert r.json()["error_code"] == "CHECKOUT_SESSION_NOT_FOUND"


def test_amount_below_minimum_rejected(api):
    client, _, _c = api
    r = client.post("/api/v1/checkout/sessions", json=_body(amount=99))
    assert r.status_code == 400  # RequestValidationError → 400 per errors.install


def test_create_with_metadata(api):
    client, _, _c = api
    r = client.post("/api/v1/checkout/sessions", json=_body(metadata={"order_ref": "ORD-123"}))
    assert r.status_code == 201
    assert r.json()["metadata"] == {"order_ref": "ORD-123"}


# ── Pay endpoint ──────────────────────────────────────────────────────────────

def _pay_body(**kwargs):
    return {"encrypted_card_data": "base64ciphertext==", "card_expiry": "2027-12", **kwargs}


def _open_session(client):
    return client.post("/api/v1/checkout/sessions", json=_body()).json()


def test_pay_approved_returns_success_url(api):
    client, fake, cards = api
    session = _open_session(client)
    r = client.post(f"/api/v1/checkout/sessions/{session['session_id']}/pay", json=_pay_body())
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "APPROVED"
    assert body["success_url"] == _body()["success_url"]
    assert fake._rows[session["session_id"]]["status"] == "COMPLETED"


def test_pay_declined_returns_402(api):
    client, fake, _ = api
    app_cards = FakeCardProcessor(status="DECLINED", error={"error_message": "insufficient funds"})
    # swap cards on the app
    client.app.state.cards = app_cards
    session = _open_session(client)
    r = client.post(f"/api/v1/checkout/sessions/{session['session_id']}/pay", json=_pay_body())
    assert r.status_code == 402
    assert r.json()["error_code"] == "CARD_DECLINED"
    assert fake._rows[session["session_id"]]["status"] == "OPEN"  # reopened for retry


def test_pay_unknown_session_returns_404(api):
    client, _, _c = api
    r = client.post(f"/api/v1/checkout/sessions/cs_{'0' * 32}/pay", json=_pay_body())
    assert r.status_code == 404


def test_pay_completed_session_returns_400(api):
    client, fake, _ = api
    session = _open_session(client)
    fake._rows[session["session_id"]]["status"] = "COMPLETED"
    r = client.post(f"/api/v1/checkout/sessions/{session['session_id']}/pay", json=_pay_body())
    assert r.status_code == 400
    assert r.json()["error_code"] == "CHECKOUT_SESSION_NOT_PAYABLE"


def test_pay_sends_encrypted_data_to_card_service(api):
    client, _, cards = api
    session = _open_session(client)
    client.post(f"/api/v1/checkout/sessions/{session['session_id']}/pay",
                json=_pay_body(encrypted_card_data="MYCIPHER", card_expiry="2028-06"))
    assert len(cards.calls) == 1
    req = cards.calls[0]
    assert req.encrypted_card_data == "MYCIPHER"
    assert req.card_expiry == "2028-06"
    assert req.kind == "PURCHASE"
