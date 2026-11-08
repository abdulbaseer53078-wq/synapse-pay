"""A fake cloud with the real contracts: signed rules (Step 20) and the offline sync endpoint (Step 13), which
verifies every item's signature against the edge's key, replays by idempotency_key and counts charges."""
import base64
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from edge_node import crypto
from edge_node.config import EdgeConfig

DECLINED_AMOUNT = 5100  # the fake cloud refuses this amount for good


def pem_private(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def pem_public(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 7, 6, 0, tzinfo=UTC)  # 11:30 in India

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw) -> None:
        self.t += timedelta(**kw)


class FakeCloud:
    def __init__(self, rules_key, edge_public_pem: str, edge_id: str, merchant_id: str, clock: Clock):
        self.rules_key, self.edge_public_pem, self.clock = rules_key, edge_public_pem, clock
        self.edge_id, self.merchant_id = edge_id, merchant_id
        self.version = 1
        self.limits = {"per_transaction": 200_000, "per_day": 1_000_000, "max_age_minutes": 4320}
        self.terminals = ["TERM-1", "TERM-2"]
        self.reachable = True
        self.status = 200  # what the sync endpoint answers with when not 200-processing
        self.die_after: int | None = None  # process this many items of the next batch, then drop the connection
        self.still_processing: set[str] = set()  # offline_references answered "retryable" once
        self.answers: dict[str, dict] = {}  # idempotency_key -> stored result (the cloud's idempotency)
        self.charges: list[str] = []  # idempotency keys sent to the acquirer, once each
        self.batches: list[list[str]] = []  # offline_references per request, in order

    def signed_rules(self, **override) -> dict:
        issued = self.clock()
        body = {"edge_node_id": self.edge_id, "merchant_id": self.merchant_id, "rules_version": self.version,
                "issued_at": issued.isoformat().replace("+00:00", "Z"),
                "expires_at": (issued + timedelta(hours=72)).isoformat().replace("+00:00", "Z"),
                "offline_limits": self.limits, "terminals": self.terminals, "routing_rules": {},
                "fraud_thresholds": {}, "token_index": {"entries": [], "revocations": []}, **override}
        sig = self.rules_key.sign(crypto.canonical(body), ec.ECDSA(hashes.SHA256()))
        return {**body, "signature": base64.b64encode(sig).decode()}

    def fetch_rules(self) -> dict:
        if not self.reachable:
            raise ConnectionError("cloud unreachable")
        return self.signed_rules()

    def sync(self, items: list[dict]) -> tuple[int, dict | None]:
        if not self.reachable:
            raise ConnectionError("cloud unreachable")
        self.batches.append([i["offline_reference"] for i in items])
        if self.status != 200:
            return self.status, {"error_code": "UNAVAILABLE", "retryable": True}
        results = []
        for n, item in enumerate(items):
            if self.die_after is not None and n == self.die_after:
                self.die_after = None
                raise ConnectionError("connection dropped mid-response")  # the first n were processed
            results.append(self._one(item))
        return 200, {"results": results}

    def _one(self, item: dict) -> dict:
        ref = item["offline_reference"]
        if not crypto.verify(self.edge_public_pem, item) or item.get("edge_node_id") != self.edge_id:
            return {"offline_reference": ref, "status": "FAILED",
                    "error": {"error_code": "INVALID_SIGNATURE", "retryable": False}}
        if ref in self.still_processing:
            self.still_processing.discard(ref)
            return {"offline_reference": ref, "status": "PENDING",
                    "error": {"error_code": "IDEMPOTENCY_KEY_CONFLICT", "retryable": True}}
        key = item["idempotency_key"]
        if key not in self.answers:
            if item["amount"] == DECLINED_AMOUNT:
                self.answers[key] = {"status": "FAILED", "error": {"error_code": "INSUFFICIENT_FUNDS",
                                                                   "error_category": "HARD_DECLINE", "retryable": False}}
            else:
                self.charges.append(key)
                self.answers[key] = {"status": "CAPTURED", "transaction_id": f"txn_{uuid.uuid4().hex}"}
        return {"offline_reference": ref, **self.answers[key]}


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture(scope="session")
def keys():
    return {"rules": ec.generate_private_key(ec.SECP256R1()), "edge": ec.generate_private_key(ec.SECP256R1())}


@pytest.fixture
def cfg(tmp_path, keys):
    return EdgeConfig(edge_node_id=str(uuid.uuid4()), merchant_id=str(uuid.uuid4()), db_path=tmp_path / "edge.db",
                      cloud_url="https://cloud.test", rules_public_key_pem=pem_public(keys["rules"]),
                      signing_key_pem=pem_private(keys["edge"]), merchant_webhook_url="https://merchant.test/hook",
                      merchant_webhook_secret="whsec_test")


@pytest.fixture
def cloud(keys, cfg, clock):
    return FakeCloud(keys["rules"], pem_public(keys["edge"]), cfg.edge_node_id, cfg.merchant_id, clock)
