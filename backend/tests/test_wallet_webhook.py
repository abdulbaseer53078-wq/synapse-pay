"""Step 12b: the wallet webhook, and the one verifier both providers share."""
import hashlib
import hmac
import json
import time
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import upi_webhooks as webhook_api
from app.application.methods import WebhookRejected
from app.application.upi_webhooks import WebhookHandler
from app.infrastructure.methods.wallet import WalletMethodAdapter
from app.infrastructure.webhook_signature import verify_signature

SECRET = "whsec_wallet"
PATH = "/api/v1/webhooks/wallet"
TRANSACTION, TERMINAL = uuid4(), uuid4()


class FakeProvider:
    def pay(self, **_kwargs):
        raise AssertionError("a webhook must never start a payment")

    def debit(self, **_kwargs):
        raise AssertionError("a webhook must never debit")


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
        self.finished = []

    def by_method_reference(self, reference, method=None):
        return (TRANSACTION, TERMINAL, "PENDING") if reference == "wal_known" else None

    def finish(self, transaction_id, terminal_id, result, status, error, store_response):
        self.finished.append({"status": status, "result": result, "stored": store_response})
        return {"transaction_id": f"txn_{transaction_id.hex}", "status": status}


def _signed(body: dict, *, secret: str = SECRET, timestamp: int | None = None) -> tuple[bytes, dict]:
    raw = json.dumps(body).encode()
    sent_at = int(time.time()) if timestamp is None else timestamp
    signature = hmac.new(secret.encode(), f"{sent_at}.".encode() + raw, hashlib.sha256).hexdigest()
    return raw, {"X-Wallet-Timestamp": str(sent_at), "X-Wallet-Signature": signature}


def _body(**overrides) -> dict:
    return {"event_id": f"wevt_{uuid4().hex}", "wallet_transaction_id": "wal_known", "status": "SUCCESS",
            **overrides}


@pytest.fixture
def wired():
    repo, events = FakeTransactions(), FakeEvents()
    adapter = WalletMethodAdapter(FakeProvider(), webhook_secret=SECRET)
    app = FastAPI()
    app.state.wallet_webhooks = WebhookHandler(adapter, repo, events, provider="wallet")
    app.include_router(webhook_api.router)
    return TestClient(app), repo, events


def test_a_valid_wallet_webhook_settles(wired):
    client, repo, _ = wired
    raw, headers = _signed(_body())

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 200, r.text
    assert r.json()["applied"] is True and r.json()["status"] == "SETTLED"
    assert repo.finished[0]["status"] == "SETTLED"


def test_a_bad_wallet_signature_changes_nothing(wired):
    client, repo, _ = wired
    raw, headers = _signed(_body(), secret="wrong")

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 401 and r.json()["error_code"] == "BAD_SIGNATURE"
    assert repo.finished == []


def test_a_stale_wallet_timestamp_is_rejected(wired):
    client, repo, _ = wired
    raw, headers = _signed(_body(), timestamp=int(time.time()) - 400)

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 400 and r.json()["error_code"] == "STALE_TIMESTAMP"
    assert repo.finished == []


def test_a_duplicate_wallet_delivery_is_acknowledged_once(wired):
    client, repo, events = wired
    body = _body()
    raw, headers = _signed(body)

    first = client.post(PATH, content=raw, headers=headers)
    second = client.post(PATH, content=raw, headers=headers)

    assert first.json()["applied"] is True and second.json()["duplicate"] is True
    assert len(repo.finished) == 1
    assert events.seen == {("wallet", body["event_id"])}  # namespaced per provider


def test_a_wallet_failure_webhook_marks_the_payment_failed(wired):
    client, repo, _ = wired
    raw, headers = _signed(_body(status="FAILURE", reason="WALLET_BLOCKED"))

    r = client.post(PATH, content=raw, headers=headers)

    assert r.status_code == 200
    assert repo.finished[0]["result"].error["error_code"] == "WALLET_DECLINED"


# --- the shared verifier ---------------------------------------------------------------------------------

@pytest.mark.parametrize("timestamp_header, signature_header, label", [
    ("X-UPI-Timestamp", "X-UPI-Signature", "UPI"),
    ("X-Wallet-Timestamp", "X-Wallet-Signature", "wallet"),
])
def test_one_verifier_serves_both_providers(timestamp_header, signature_header, label):
    """The generalisation, as an assertion: only the header names differ."""
    raw = b'{"event_id":"e1"}'
    sent_at = int(time.time())
    signature = hmac.new(b"s", f"{sent_at}.".encode() + raw, hashlib.sha256).hexdigest()

    verify_signature(raw, {timestamp_header.lower(): str(sent_at), signature_header.lower(): signature},
                     "s", timestamp_header=timestamp_header, signature_header=signature_header, label=label)

    with pytest.raises(WebhookRejected) as raised:
        verify_signature(raw, {timestamp_header.lower(): str(sent_at), signature_header.lower(): "0" * 64},
                         "s", timestamp_header=timestamp_header, signature_header=signature_header, label=label)
    assert raised.value.code == "BAD_SIGNATURE"


def test_an_unconfigured_secret_fails_closed_for_every_provider():
    with pytest.raises(WebhookRejected) as raised:
        verify_signature(b"{}", {}, "", timestamp_header="X-Wallet-Timestamp",
                         signature_header="X-Wallet-Signature", label="wallet")
    assert raised.value.code == "WEBHOOK_NOT_CONFIGURED"
