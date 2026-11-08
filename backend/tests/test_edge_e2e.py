"""Steps 20, 21 and 24 end to end: the real Edge Node (edge-node/) against the real cloud.

An admin registers the edge; the edge fetches its signed rules, takes payments with the internet "down", and its
sync worker delivers them to the real POST /api/v1/transactions/sync, which verifies each item's signature with
the edge's registered key. The card service is scripted (it approves); everything else is the production code.
"""
import json
import sys
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.application.transactions import CardResult
from app.main import create_app
from card_sim import encrypted_card

sys.path.insert(0, str(Path(__file__).parents[2] / "edge-node"))
from edge_node import db as edge_db  # noqa: E402
from edge_node.config import EdgeConfig  # noqa: E402
from edge_node.engine import create_app as create_edge  # noqa: E402
from edge_node.sync import SyncWorker  # noqa: E402

PEM = serialization.Encoding.PEM


class Approves:
    def __init__(self):
        self.seen = 0

    def process(self, request):
        self.seen += 1
        return CardResult(status="CAPTURED", method_reference=f"ref_{self.seen}", auth_code="A1", error=None,
                          reversal="NOT_NEEDED", card_bin="411111", card_last4="1111")


@pytest.fixture
def ready(db, active):
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', 1000000, 2000000) RETURNING profile_id").fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now() WHERE terminal_id = %s",
               (profile_id, active["terminal_id"]))
    return active


@pytest.fixture
def stack(settings, db, ready, merchant, auth, tmp_path):
    rules_key, edge_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    private = lambda k: k.private_bytes(PEM, serialization.PrivateFormat.PKCS8,  # noqa: E731
                                        serialization.NoEncryption()).decode()
    cards = Approves()
    cloud = TestClient(create_app(replace(settings, edge_rules_signing_key=private(rules_key)), cards=cards))
    cloud.__enter__()
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e")]))
           .sign(edge_key, hashes.SHA256()).public_bytes(PEM).decode())
    r = cloud.post("/api/v1/edge-nodes", headers=auth(sub="admin-ops-1", scope="registry:admin"), json={
        "merchant_id": str(merchant), "csr_pem": csr,
        "offline_limits": {"per_transaction": 200_000, "per_day": 1_000_000}})
    assert r.status_code == 201, r.text
    edge_id = r.json()["edge_node_id"]
    cfg = EdgeConfig(edge_node_id=edge_id, merchant_id=str(merchant), db_path=tmp_path / "edge.db",
                     cloud_url="https://unused", rules_public_key_pem=r.json()["rules_public_key_pem"],
                     signing_key_pem=private(edge_key))
    identity = {"x-edge-node-id": edge_id, "x-terminal-id": "-"}  # what the gateway sets from the edge's cert
    online = {"up": True}

    def fetch_rules():
        if not online["up"]:
            raise ConnectionError("internet down")
        return cloud.get("/internal/v1/edge/rules", headers=identity).raise_for_status().json()

    def send(items):
        if not online["up"]:
            raise ConnectionError("internet down")
        r = cloud.post("/api/v1/transactions/sync", json={"transactions": items}, headers=identity)
        return r.status_code, r.json()

    worker = SyncWorker(cfg, fetch_rules, send, post=lambda *a: 200)
    assert worker.run_once() == "idle", "rules fetched while online"
    yield {"cfg": cfg, "edge": TestClient(create_edge(cfg)), "worker": worker, "online": online, "cards": cards,
           "terminal_id": ready["terminal_id"]}
    cloud.__exit__(None, None, None)


def queue_status(cfg) -> dict:
    conn = edge_db.connect(cfg.db_path)
    try:
        return {r["offline_reference"]: (r["status"], r["transaction_id"])
                for r in conn.execute("SELECT * FROM offline_queue ORDER BY id")}
    finally:
        conn.close()


def pay(stack, amount=50_000):
    r = stack["edge"].post("/local/v1/transactions", json={
        "idempotency_key": str(uuid.uuid4()), "amount": amount, "currency": "INR", "payment_method": "CARD",
        "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA"},
        "terminal_id": stack["terminal_id"], "merchant_id": stack["cfg"].merchant_id})
    assert r.status_code == 201, r.text
    return r.json()["offline_reference"]


def test_offline_payments_sync_to_the_real_cloud_exactly_once(stack, db):
    stack["online"]["up"] = False
    refs = [pay(stack) for _ in range(3)]
    assert stack["worker"].run_once() == "offline"

    stack["online"]["up"] = True
    assert stack["worker"].run_once() == "synced"
    done = queue_status(stack["cfg"])
    assert [done[r][0] for r in refs] == ["SYNCED"] * 3, done
    assert db.execute("SELECT count(*) FROM transactions WHERE status = 'CAPTURED'").fetchone()[0] == 3
    assert stack["cards"].seen == 3

    # A crash after the cloud answered but before the edge recorded it: the batch goes again, and the cloud
    # replays its answers from the idempotency keys instead of charging again.
    conn = edge_db.connect(stack["cfg"].db_path)
    conn.execute("UPDATE offline_queue SET status = 'PENDING_OFFLINE'")
    conn.close()
    assert stack["worker"].run_once() == "synced"
    assert queue_status(stack["cfg"]) == done, "same transaction ids: answers were replayed"
    assert stack["cards"].seen == 3 and db.execute("SELECT count(*) FROM transactions").fetchone()[0] == 3


def test_a_payment_edited_in_the_edges_database_is_refused_by_the_cloud(stack, db):
    ref = pay(stack, amount=50_000)
    conn = edge_db.connect(stack["cfg"].db_path)
    item = json.loads(conn.execute("SELECT payload_json FROM offline_queue").fetchone()[0])
    item["amount"] = 5_000_000  # someone with the box's disk inflates the sale
    conn.execute("UPDATE offline_queue SET payload_json = ?", (json.dumps(item),))
    conn.close()
    stack["worker"].run_once()
    assert queue_status(stack["cfg"])[ref][0] == "FAILED"
    assert stack["cards"].seen == 0 and db.execute("SELECT count(*) FROM transactions").fetchone()[0] == 0
