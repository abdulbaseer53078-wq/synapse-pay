"""Step 13 gate: a mixed offline batch is judged per item, and only the valid one becomes a transaction."""
import base64
import json
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import errors as errors_module
from app.api import transactions as transactions_api
from app.application.edge import EdgeNode, OfflineLimits
from app.application.offline_sync import canonical_item
from app.application.registration import RegistrationError
from app.application.transaction_sync import OfflineSyncService
from app.application.methods import MethodRegistry
from app.infrastructure.methods.offline import OFFLINE_CAPABILITIES, OfflineMethodAdapter

TERMINAL = uuid4()


def _key():
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return private, pem


def _verify(pem, message, signature):
    try:
        serialization.load_pem_public_key(pem.encode()).verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _item(private, amount=250_000, age_hours=0.0) -> dict:
    accepted = datetime.now(UTC) - timedelta(hours=age_hours)
    item = {"offline_reference": str(uuid4()), "idempotency_key": str(uuid4()), "amount": amount,
            "currency": "INR", "payment_method": "OFFLINE", "underlying_rail": "UPI",
            "method_details": {"vpa": "asha@okhdfcbank", "flow_type": "COLLECT"},
            "terminal_id": str(TERMINAL), "merchant_id": str(uuid4()),
            "local_timestamp": accepted.isoformat().replace("+00:00", "Z")}
    signature = private.sign(canonical_item(item), ec.ECDSA(hashes.SHA256()))
    return {**item, "signature": base64.b64encode(signature).decode()}


class FakeRepo:
    def __init__(self, pem):
        self.pem = pem

    def terminal_public_key(self, terminal_id):
        return self.pem if terminal_id == TERMINAL else None


class FakeEngine:
    def __init__(self):
        self.created = []

    def create(self, caller_terminal, body):
        self.created.append(body)
        return {"transaction_id": f"txn_{uuid4().hex}", "status": "PENDING"}


def _service():
    private, pem = _key()
    engine = FakeEngine()
    service = OfflineSyncService(MethodRegistry([OfflineMethodAdapter()]), FakeRepo(pem), engine, _verify)
    return service, engine, private


def test_a_mixed_batch_is_judged_item_by_item():
    service, engine, private = _service()
    valid = _item(private)
    tampered = {**_item(private), "amount": 25_000_000}  # signature still describes the original amount
    over_limit = _item(private, amount=999_999_999)
    expired = _item(private, age_hours=25)

    results = service.sync(TERMINAL, [valid, tampered, over_limit, expired])

    assert [r["offline_reference"] for r in results] == [
        valid["offline_reference"], tampered["offline_reference"], over_limit["offline_reference"],
        expired["offline_reference"]]
    assert results[0]["status"] == "PENDING" and "transaction_id" in results[0]
    assert results[1]["reason"] == "SIGNATURE_INVALID"
    assert results[2]["reason"] == "OFFLINE_LIMIT_EXCEEDED"
    assert results[3]["reason"] == "OFFLINE_TRANSACTION_EXPIRED"
    assert len(engine.created) == 1  # only the valid item reached a rail
    assert engine.created[0]["payment_method"] == "UPI"  # dispatched, not stored as OFFLINE


def test_the_offline_descriptor_publishes_the_limits_the_sdk_enforces():
    limits = OFFLINE_CAPABILITIES.to_dict()["offline_limits"]
    assert limits == {"max_per_txn": 500_000, "currency": "INR", "max_age_minutes": 1440}
    assert OFFLINE_CAPABILITIES.is_synchronous is True  # the terminal answers without waiting for the cloud


def test_an_item_signed_by_another_key_is_refused():
    service, engine, _ = _service()
    other_private, _ = _key()
    forged = _item(other_private)

    results = service.sync(TERMINAL, [forged])

    assert results[0]["reason"] == "SIGNATURE_INVALID" and engine.created == []


def test_a_rail_refusal_is_this_items_outcome_not_the_batch_failure():
    from app.application.registration import InvalidInput

    service, engine, private = _service()

    class Refusing(FakeEngine):
        def create(self, caller_terminal, body):
            raise InvalidInput("the rail said no")

    service.engine = Refusing()
    results = service.sync(TERMINAL, [_item(private), _item(private)])

    assert [r["status"] for r in results] == ["FAILED", "FAILED"]
    assert results[0]["reason"] == "INVALID_REQUEST"


# --- the route -------------------------------------------------------------------------------------------

class FakeService:
    def __init__(self):
        self.calls = []

    def sync(self, terminal_id, items):
        self.calls.append(len(items))
        return [{"offline_reference": i["offline_reference"], "status": "PENDING"} for i in items]

    def sync_edge(self, edge_node_id, items):
        self.calls.append(("edge", str(edge_node_id), len(items)))
        return []


@pytest.fixture
def client():
    app = FastAPI()
    app.state.offline_sync = FakeService()
    app.include_router(transactions_api.router)
    errors_module.install(app)
    return TestClient(app), app


def _body(count: int) -> dict:
    return {"transactions": [{"offline_reference": f"r{i}"} for i in range(count)]}


def test_the_route_returns_per_item_results(client):
    http, app = client
    r = http.post("/api/v1/transactions/sync", json=_body(2), headers={"x-terminal-id": str(TERMINAL)})

    assert r.status_code == 200
    assert len(r.json()["results"]) == 2
    assert app.state.offline_sync.calls == [2]


def test_the_route_caps_the_batch_at_100(client):
    http, _ = client
    r = http.post("/api/v1/transactions/sync", json=_body(101), headers={"x-terminal-id": str(TERMINAL)})
    assert r.status_code == 400 and "at most 100" in r.json()["error_message"]


def test_the_route_requires_a_terminal_certificate(client):
    http, _ = client
    assert http.post("/api/v1/transactions/sync", json=_body(1)).status_code == 401


def test_the_route_takes_an_edge_nodes_batch_and_ignores_the_gateways_placeholder(client):
    http, app = client
    edge = str(uuid4())
    r = http.post("/api/v1/transactions/sync", json=_body(3), headers={"x-terminal-id": "-", "x-edge-node-id": edge})
    assert r.status_code == 200
    assert app.state.offline_sync.calls == [("edge", edge, 3)]
    both_placeholders = {"x-terminal-id": "-", "x-edge-node-id": "-"}
    assert http.post("/api/v1/transactions/sync", json=_body(1), headers=both_placeholders).status_code == 401


# --- an edge node's batch (Step 21) ------------------------------------------------------------------------

EDGE, MERCHANT = uuid4(), uuid4()


class FakeEdges:
    def __init__(self, pem, status="ACTIVE"):
        self.pem, self.status = pem, status

    def get(self, edge_node_id):
        if edge_node_id != EDGE:
            return None
        return EdgeNode(EDGE, MERCHANT, self.status, 3,
                        OfflineLimits(per_transaction=100_000, per_day=500_000, max_age_minutes=60))

    def public_key(self, edge_node_id):
        return self.pem if edge_node_id == EDGE and self.status == "ACTIVE" else None


def _edge_item(private, terminal=None, **fields) -> dict:
    accepted = datetime.now(UTC) - timedelta(minutes=fields.pop("age_minutes", 0))
    item = {"offline_reference": str(uuid4()), "idempotency_key": str(uuid4()), "amount": 50_000,
            "currency": "INR", "payment_method": "OFFLINE", "underlying_rail": "CARD",
            "method_details": {"encrypted_card_data": "x"}, "terminal_id": str(terminal or uuid4()),
            "merchant_id": str(MERCHANT), "edge_node_id": str(EDGE),
            "local_timestamp": accepted.isoformat().replace("+00:00", "Z"), **fields}
    signature = private.sign(canonical_item(item), ec.ECDSA(hashes.SHA256()))
    return {**item, "signature": base64.b64encode(signature).decode()}


class FakeChain:
    """The cloud's chain memory (PR 6), in memory: hashes accepted per edge, edges flagged, offline spend."""

    def __init__(self):
        self.links: dict[int, str] = {}
        self.flagged_reason = None
        self.spent = 0

    def exclusive(self, edge_node_id):
        import contextlib
        return contextlib.nullcontext()

    def flagged(self, edge_node_id):
        return self.flagged_reason

    def head(self, edge_node_id, seqs):
        last = max(self.links, default=0)
        return last, {q: h for q, h in self.links.items() if q in (*seqs, last)}

    def record(self, edge_node_id, links):
        self.links.update(links)

    def flag(self, edge_node_id, reason):
        self.flagged_reason = reason

    def offline_total(self, terminal_id, since, until, excluding_key):
        return self.spent


def _edge_service(status="ACTIVE", chain=None):
    private, pem = _key()
    engine = FakeEngine()
    service = OfflineSyncService(MethodRegistry([OfflineMethodAdapter()]), FakeRepo(None), engine, _verify,
                                 edges=FakeEdges(pem, status), chain=chain or FakeChain())
    return service, engine, private


def test_an_edge_batch_is_verified_with_the_edges_key_and_limits():
    service, engine, edge_key = _edge_service()
    till = uuid4()
    terminal_key, _ = _key()
    good = _edge_item(edge_key, till)
    forged = {**_edge_item(edge_key), "amount": 90_000}  # edited after signing
    by_terminal = _edge_item(terminal_key)  # a terminal's key is not the edge's
    other_edge = _edge_item(edge_key, edge_node_id=str(uuid4()))
    other_merchant = _edge_item(edge_key, merchant_id=str(uuid4()))
    over_limit = _edge_item(edge_key, amount=100_001)  # the edge's own limit, not the method's
    stale = _edge_item(edge_key, age_minutes=61)

    results = service.sync_edge(EDGE, [good, forged, by_terminal, other_edge, other_merchant, over_limit, stale])

    assert [r.get("reason") for r in results] == [None, "SIGNATURE_INVALID", "SIGNATURE_INVALID", "EDGE_MISMATCH",
                                                  "EDGE_MISMATCH", "OFFLINE_LIMIT_EXCEEDED",
                                                  "OFFLINE_TRANSACTION_EXPIRED"]
    [created] = engine.created
    # Submitted as the till that took the sale, on its real rail; the engine checks that till is the merchant's.
    assert (created["terminal_id"], created["merchant_id"], created["payment_method"]) == (str(till), str(MERCHANT),
                                                                                          "CARD")


def test_a_revoked_or_unknown_edge_is_refused_outright():
    service, _, edge_key = _edge_service(status="REVOKED")
    with pytest.raises(RegistrationError):
        service.sync_edge(EDGE, [_edge_item(edge_key)])
    service, _, edge_key = _edge_service()
    with pytest.raises(RegistrationError):
        service.sync_edge(uuid4(), [_edge_item(edge_key)])
