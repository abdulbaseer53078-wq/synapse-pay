"""Checkout sessions: create and retrieve. No database — FakeCheckoutSessions stands in."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import checkout_sessions as checkout_sessions_api
from app.api import errors as errors_module
from app.api.api_keys import verify_api_key

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


@pytest.fixture
def api():
    fake = FakeCheckoutSessions()
    app = FastAPI()
    errors_module.install(app)
    app.include_router(checkout_sessions_api.router)
    app.state.checkout_sessions = fake
    app.dependency_overrides[verify_api_key] = lambda: MERCHANT
    with TestClient(app) as client:
        yield client, fake


def _body(**kwargs):
    return {"amount": 50_000, "currency": "INR", "success_url": "https://shop.example/ok",
            "cancel_url": "https://shop.example/cancel", **kwargs}


def test_create_returns_open_session_with_checkout_url(api):
    client, _ = api
    r = client.post("/api/v1/checkout/sessions", json=_body(description="Test order"))
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "OPEN"
    assert body["session_id"].startswith("cs_")
    assert "/pay/" in body["checkout_url"]
    assert body["amount"] == 50_000
    assert body["intent_id"] is None


def test_get_returns_created_session(api):
    client, _ = api
    created = client.post("/api/v1/checkout/sessions", json=_body()).json()
    r = client.get(f"/api/v1/checkout/sessions/{created['session_id']}")
    assert r.status_code == 200
    fetched = r.json()
    assert fetched["session_id"] == created["session_id"]
    assert fetched["amount"] == created["amount"]
    assert fetched["status"] == "OPEN"


def test_get_unknown_session_returns_404(api):
    client, _ = api
    r = client.get(f"/api/v1/checkout/sessions/cs_{'0' * 32}")
    assert r.status_code == 404
    assert r.json()["error_code"] == "CHECKOUT_SESSION_NOT_FOUND"


def test_amount_below_minimum_rejected(api):
    client, _ = api
    r = client.post("/api/v1/checkout/sessions", json=_body(amount=99))
    assert r.status_code == 400  # RequestValidationError → 400 per errors.install


def test_create_with_metadata(api):
    client, _ = api
    r = client.post("/api/v1/checkout/sessions", json=_body(metadata={"order_ref": "ORD-123"}))
    assert r.status_code == 201
    assert r.json()["metadata"] == {"order_ref": "ORD-123"}
