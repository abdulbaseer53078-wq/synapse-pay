"""Step 21: the local engine enforces the cached rules, signs and queues, and answers PENDING_OFFLINE."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from edge_node import crypto, db
from edge_node.engine import create_app
from edge_node.rules import accept
from tests.conftest import pem_public

URL = "/local/v1/transactions"


@pytest.fixture
def api(cfg, cloud, clock):
    app = create_app(cfg, now=clock)
    conn = db.connect(cfg.db_path)
    accept(conn, cloud.signed_rules(), cfg, clock())
    conn.close()
    with TestClient(app) as client:
        yield client


def request(cfg, amount=50_000, terminal="TERM-1", method="CARD", **extra):
    return {"idempotency_key": str(uuid.uuid4()), "amount": amount, "currency": "INR", "payment_method": method,
            "method_details": {"encrypted_card_data": "c2VhbGVk", "card_expiry": "08/28", "card_network": "VISA"},
            "terminal_id": terminal, "merchant_id": cfg.merchant_id, **extra}


def queued(cfg):
    conn = db.connect(cfg.db_path)
    try:
        return conn.execute("SELECT * FROM offline_queue ORDER BY id").fetchall()
    finally:
        conn.close()


def test_accepts_signs_and_queues(api, cfg, keys):
    r = api.post(URL, json=request(cfg, metadata={"till": "3"}))  # same payload the cloud takes; extras ignored
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["status"] == "PENDING_OFFLINE" and out["receipt_note"] == "OFFLINE - AWAITING BANK APPROVAL"
    [row] = queued(cfg)
    assert (row["status"], row["offline_reference"]) == ("PENDING_OFFLINE", out["offline_reference"])
    item = json.loads(row["payload_json"])
    assert (item["payment_method"], item["underlying_rail"], item["edge_node_id"]) == ("OFFLINE", "CARD", cfg.edge_node_id)
    assert crypto.verify(pem_public(keys["edge"]), item), "signed with the edge's key"
    assert not crypto.verify(pem_public(keys["edge"]), {**item, "amount": item["amount"] * 100}), "tampering shows"


def test_every_rail_is_accepted_offline(api, cfg):
    for method in ("UPI", "WALLET", "QR"):
        assert api.post(URL, json=request(cfg, method=method)).status_code == 201
    assert api.post(URL, json=request(cfg, method="OFFLINE")).status_code == 400


def test_per_transaction_and_per_day_limits(api, cfg, clock):
    over = api.post(URL, json=request(cfg, amount=200_001))
    assert (over.status_code, over.json()["error_code"]) == (422, "OFFLINE_LIMIT_EXCEEDED")
    for _ in range(5):  # 5 x 200,000 = the 1,000,000 daily limit
        assert api.post(URL, json=request(cfg, amount=200_000)).status_code == 201
    assert api.post(URL, json=request(cfg, amount=1)).json()["error_code"] == "OFFLINE_LIMIT_EXCEEDED"
    assert api.post(URL, json=request(cfg, amount=1, terminal="TERM-2")).status_code == 201, "the limit is per terminal"
    clock.advance(hours=13)  # past midnight in India: a calendar day would hand out a fresh 1,000,000 here
    assert api.post(URL, json=request(cfg, amount=1)).json()["error_code"] == "OFFLINE_LIMIT_EXCEEDED", "rolling 24 h"


def test_unsynced_sales_count_however_far_the_clock_moves(api, cfg, clock):
    """F-06: the window frees only what the cloud has seen. Unsynced exposure counts whatever its timestamp."""
    for _ in range(5):
        assert api.post(URL, json=request(cfg, amount=200_000)).status_code == 201
    clock.advance(hours=25)  # out of the window, but still unsynced
    assert api.post(URL, json=request(cfg, amount=1)).json()["error_code"] == "OFFLINE_LIMIT_EXCEEDED"
    conn = db.connect(cfg.db_path)
    conn.execute("UPDATE offline_queue SET status = 'SYNCED'")
    conn.close()
    assert api.post(URL, json=request(cfg, amount=200_000)).status_code == 201, "synced and 24 h old: freed"


def test_queued_items_form_a_signed_hash_chain(api, cfg, keys):
    """F-06: each item quotes the one before it, so the cloud can see one dropped, reordered or replaced."""
    for _ in range(3):
        assert api.post(URL, json=request(cfg)).status_code == 201
    items = [json.loads(row["payload_json"]) for row in queued(cfg)]
    assert [i["edge_seq"] for i in items] == [1, 2, 3]
    assert items[0]["prev_hash"] == ""
    assert [i["prev_hash"] for i in items[1:]] == [crypto.chain_hash(i) for i in items[:2]]
    assert all(crypto.verify(pem_public(keys["edge"]), i) for i in items)
    assert not crypto.verify(pem_public(keys["edge"]), {**items[2], "edge_seq": 2}), "the chain fields are signed"


def test_purging_synced_rows_never_breaks_the_chain(api, cfg):
    assert api.post(URL, json=request(cfg)).status_code == 201
    [first] = queued(cfg)
    conn = db.connect(cfg.db_path)
    conn.execute("DELETE FROM offline_queue")  # what the 30-day purge does to synced rows
    conn.close()
    assert api.post(URL, json=request(cfg)).status_code == 201
    [second] = queued(cfg)
    item = json.loads(second["payload_json"])
    assert (item["edge_seq"], item["prev_hash"]) == (2, crypto.chain_hash(json.loads(first["payload_json"])))


def test_idempotent_replay_and_conflict(api, cfg):
    body = request(cfg)
    first = api.post(URL, json=body)
    again = api.post(URL, json=body)
    assert (again.status_code, again.json()["offline_reference"]) == (200, first.json()["offline_reference"])
    clash = api.post(URL, json={**body, "amount": body["amount"] + 1})
    assert (clash.status_code, clash.json()["error_code"]) == (409, "IDEMPOTENCY_KEY_CONFLICT")
    assert len(queued(cfg)) == 1


def test_expired_rules_refuse_offline_payments(api, cfg, clock):
    clock.advance(hours=73)
    r = api.post(URL, json=request(cfg))
    assert (r.status_code, r.json()["error_code"]) == (503, "RULES_EXPIRED")
    assert queued(cfg) == []


def test_only_this_merchants_terminals(api, cfg):
    assert api.post(URL, json=request(cfg, terminal="TERM-9")).status_code == 403
    assert api.post(URL, json={**request(cfg), "merchant_id": "other"}).status_code == 403


def test_invalid_requests_never_echo_card_data(api, cfg):
    r = api.post(URL, json={**request(cfg), "amount": "lots"})
    assert r.status_code == 400 and "c2VhbGVk" not in r.text
