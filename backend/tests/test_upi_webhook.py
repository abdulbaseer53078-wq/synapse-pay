"""Step 10B: the UPI webhook endpoint, attacked from every angle a PSP's retry queue can produce."""
import hashlib
import hmac
import json
import time
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import upi_webhooks as webhook_api
from app.application.upi_webhooks import UpiWebhookHandler
from app.infrastructure.methods.upi import UpiMethodAdapter

SECRET = "whsec_test_secret"
PATH = "/api/v1/webhooks/upi"
TERMINAL, TRANSACTION = uuid4(), uuid4()


class FakePsp:
    """Only the webhook path is exercised here; the outbound calls are not made."""

    def collect(self, **_kwargs):
        raise AssertionError("a webhook must never trigger an outbound collect")

    def status(self, _reference):
        raise AssertionError("a webhook must never trigger a status poll")

    def validate_vpa(self, vpa):
        return {"vpa": vpa, "name": "Asha Menon"}

    def refund(self, _reference, _amount):
        return {"refund_id": "rfnd_x"}


class FakeEvents:
    def __init__(self):
        self.seen = set()

    def claim(self, provider, event_id):
        key = (provider, event_id)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


class FakeTransactions:
    def __init__(self):
        self.finished, self.lookups = [], []

    def by_method_reference(self, reference, method=None):
        self.lookups.append((reference, method))
        if reference != "psp_known":
            return None
        return TRANSACTION, TERMINAL, "PENDING"

    def finish(self, transaction_id, terminal_id, result, status, error, store_response):
        self.finished.append({"transaction_id": transaction_id, "status": status, "result": result,
                              "stored": store_response})
        return {"transaction_id": f"txn_{transaction_id.hex}", "status": status}


def _signed(body: dict, *, secret: str = SECRET, timestamp: int | None = None) -> tuple[bytes, dict]:
    raw = json.dumps(body).encode()
    sent_at = int(time.time()) if timestamp is None else timestamp
    signature = hmac.new(secret.encode(), f"{sent_at}.".encode() + raw, hashlib.sha256).hexdigest()
    return raw, {"X-UPI-Timestamp": str(sent_at), "X-UPI-Signature": signature, "Content-Type": "application/json"}


def _body(**overrides) -> dict:
    base = {"event_id": str(uuid4()), "psp_transaction_id": "psp_known", "status": "SUCCESS", "rrn": "123456789012"}
    return {**base, **overrides}


@pytest.fixture
def wired():
    repo, events = FakeTransactions(), FakeEvents()
    adapter = UpiMethodAdapter(FakePsp(), webhook_secret=SECRET)
    app = FastAPI()
    app.state.upi_webhooks = UpiWebhookHandler(adapter, repo, events)
    app.include_router(webhook_api.router)
    return TestClient(app), repo, events, adapter


def test_a_valid_webhook_settles_once(wired):
    client, repo, _, _ = wired
    body = _body()
    raw, headers = _signed(body)

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 200, r.text
    assert r.json() == {"received": True, "duplicate": False, "applied": True, "status": "SETTLED", "reason": None}
    assert len(repo.finished) == 1 and repo.finished[0]["status"] == "SETTLED"
    assert repo.finished[0]["stored"] is True


def test_a_bad_signature_is_401_and_changes_nothing(wired):
    client, repo, _, _ = wired
    raw, headers = _signed(_body(), secret="wrong_secret")

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 401 and r.json()["error_code"] == "BAD_SIGNATURE"
    assert repo.finished == [] and repo.lookups == []


def test_a_missing_signature_is_401(wired):
    client, _, _, _ = wired
    raw, headers = _signed(_body())
    for header in ("X-UPI-Signature", "X-UPI-Timestamp"):
        partial = {k: v for k, v in headers.items() if k != header}
        r = client.post(PATH, content=raw, headers=partial)
        assert r.status_code == 401 and r.json()["error_code"] == "MISSING_SIGNATURE"


def test_an_old_timestamp_is_rejected(wired):
    client, repo, _, _ = wired
    raw, headers = _signed(_body(), timestamp=int(time.time()) - 301)  # one second past the window

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 400 and r.json()["error_code"] == "STALE_TIMESTAMP"
    assert repo.finished == []


def test_a_future_timestamp_is_also_rejected(wired):
    """Clock skew in the other direction is a forged timestamp, not a slow network."""
    client, repo, _, _ = wired
    raw, headers = _signed(_body(), timestamp=int(time.time()) + 3600)

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 400 and r.json()["error_code"] == "STALE_TIMESTAMP"
    assert repo.finished == []


def test_the_same_event_twice_settles_once(wired):
    client, repo, events, _ = wired
    body = _body()
    raw, headers = _signed(body)

    first = client.post(PATH, content=raw, headers=headers)
    second = client.post(PATH, content=raw, headers=headers)  # the PSP retrying

    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["applied"] is True
    assert second.json() == {"received": True, "duplicate": True, "applied": False, "status": None, "reason": None}
    assert len(repo.finished) == 1  # the ledger moved once
    assert len(events.seen) == 1


def test_a_resigned_replay_of_the_same_event_is_still_a_duplicate(wired):
    """An attacker who captures a payload can re-sign nothing — but the event id must still deduplicate."""
    client, repo, _, _ = wired
    body = _body()
    raw1, headers1 = _signed(body)
    raw2, headers2 = _signed(body, timestamp=int(time.time()) + 1)  # fresh stamp, same event

    assert client.post(PATH, content=raw1, headers=headers1).json()["applied"] is True
    assert client.post(PATH, content=raw2, headers=headers2).json()["duplicate"] is True
    assert len(repo.finished) == 1


def test_an_unknown_payment_is_acknowledged_without_moving_anything(wired):
    """Signed and fresh, but not ours: 200 so the PSP stops retrying, and no state change."""
    client, repo, _, _ = wired
    raw, headers = _signed(_body(psp_transaction_id="psp_stranger"))

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 200
    assert r.json()["applied"] is False and r.json()["reason"] == "unknown transaction"
    assert repo.finished == []


def test_a_failure_webhook_marks_the_payment_failed(wired):
    client, repo, _, _ = wired
    raw, headers = _signed(_body(status="FAILURE", reason="INSUFFICIENT_FUNDS"))

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 200 and r.json()["status"] == "FAILED"
    assert repo.finished[0]["result"].error["error_category"] == "HARD_DECLINE"


def test_a_body_that_is_not_json_is_400():
    """Signed bytes that do not parse: the signature is valid over garbage, so this is a provider bug."""
    repo, events = FakeTransactions(), FakeEvents()
    adapter = UpiMethodAdapter(FakePsp(), webhook_secret=SECRET)
    app = FastAPI()
    app.state.upi_webhooks = UpiWebhookHandler(adapter, repo, events)
    app.include_router(webhook_api.router)
    client = TestClient(app)

    raw = b"not json"
    timestamp = int(time.time())
    signature = hmac.new(SECRET.encode(), f"{timestamp}.".encode() + raw, hashlib.sha256).hexdigest()
    r = client.post(PATH, content=raw, headers={"X-UPI-Timestamp": str(timestamp), "X-UPI-Signature": signature})

    assert r.status_code == 400 and r.json()["error_code"] == "INVALID_JSON"


def test_an_unconfigured_secret_fails_closed():
    """A deployment with no secret must refuse everything, not accept unsigned callbacks."""
    repo, events = FakeTransactions(), FakeEvents()
    adapter = UpiMethodAdapter(FakePsp(), webhook_secret=None)
    app = FastAPI()
    app.state.upi_webhooks = UpiWebhookHandler(adapter, repo, events)
    app.include_router(webhook_api.router)
    client = TestClient(app)

    raw, headers = _signed(_body())
    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 503 and r.json()["error_code"] == "WEBHOOK_NOT_CONFIGURED"
    assert repo.finished == []


def test_the_raw_bytes_are_what_is_signed(wired):
    """Re-serialising the body changes the bytes and must fail: this is the HMAC trap the step is about."""
    client, repo, _, _ = wired
    body = _body()
    raw, headers = _signed(body)
    reserialised = json.dumps(body, indent=2).encode()  # same object, different bytes

    r = client.post(PATH, content=reserialised, headers=headers)

    assert r.status_code == 401
    assert repo.finished == []
