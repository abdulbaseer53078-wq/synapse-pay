"""PR 6, cloud side: the cloud verifies each edge's hash chain at sync, so a sale deleted, reordered or edited in the
edge's SQLite is caught even by an attacker who has the edge's signing key; and it re-enforces the rolling 24-hour
offline limit itself (F-07) instead of trusting the box in the shop."""
import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from psycopg_pool import ConnectionPool

from app.application.methods import MethodRegistry
from app.application.offline_sync import canonical_item
from app.application.registration import Forbidden
from app.application.transaction_sync import OfflineSyncService
from app.domain.edge_chain import chain_hash
from app.infrastructure.methods.offline import OfflineMethodAdapter
from app.infrastructure.postgres_edge import PostgresEdgeNodes
from app.infrastructure.postgres_edge_chain import PostgresEdgeChain

PER_DAY = 300_000


class Engine:
    def __init__(self):
        self.created = []

    def create(self, caller_terminal, body):
        self.created.append(body)
        return {"transaction_id": f"txn_{uuid4().hex}", "status": "PENDING"}


class Alerts:
    def __init__(self):
        self.raised = []

    def ops_alert(self, summary, severity, details):
        self.raised.append((severity, summary, details))


def _verify(pem, message, signature):
    try:
        serialization.load_pem_public_key(pem.encode()).verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=4) as connections:
        yield connections


@pytest.fixture
def edge(db, pool):
    """A registered edge whose key the test holds, as an attacker who owns the box would."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    merchant_id, terminal_id, edge_node_id = uuid4(), uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model) VALUES (%s, %s, %s, %s)",
               (terminal_id, merchant_id, f"SN-{terminal_id.hex[:8]}", "PAX A920 Pro"))
    db.execute("INSERT INTO edge_nodes (edge_node_id, merchant_id, public_key_pem, offline_per_transaction,"
               " offline_per_day) VALUES (%s, %s, %s, 200000, %s)", (edge_node_id, merchant_id, pem, PER_DAY))
    engine, alerts = Engine(), Alerts()
    service = OfflineSyncService(MethodRegistry([OfflineMethodAdapter()]), None, engine, _verify,
                                 edges=PostgresEdgeNodes(pool), chain=PostgresEdgeChain(pool), alerts=alerts)
    return {"key": key, "merchant_id": merchant_id, "terminal_id": terminal_id, "edge_node_id": edge_node_id,
            "service": service, "engine": engine, "alerts": alerts}


def _sign(edge, item):
    signature = edge["key"].sign(canonical_item(item), ec.ECDSA(hashes.SHA256()))
    return {**item, "signature": base64.b64encode(signature).decode()}


def _chain(edge, count, start=1, prev="", amount=50_000, at=None):
    """`count` signed, chained items, as the edge queues them."""
    items = []
    for seq in range(start, start + count):
        item = _sign(edge, {
            "offline_reference": str(uuid4()), "idempotency_key": str(uuid4()), "amount": amount, "currency": "INR",
            "payment_method": "OFFLINE", "underlying_rail": "CARD", "method_details": {"encrypted_card_data": "x"},
            "terminal_id": str(edge["terminal_id"]), "merchant_id": str(edge["merchant_id"]),
            "edge_node_id": str(edge["edge_node_id"]),
            "local_timestamp": (at or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
            "edge_seq": seq, "prev_hash": prev})
        prev = chain_hash(item)
        items.append(item)
    return items


def _flag(db, edge):
    return db.execute("SELECT flagged_reason FROM edge_nodes WHERE edge_node_id = %s", (edge["edge_node_id"],)).fetchone()[0]


def test_an_unbroken_chain_is_accepted_and_a_resent_batch_is_a_replay(edge, db):
    batch = _chain(edge, 3)
    assert [r["status"] for r in edge["service"].sync_edge(edge["edge_node_id"], batch)] == ["PENDING"] * 3
    # The edge timed out waiting for the answer and sends the same batch again, then the next item.
    assert len(edge["service"].sync_edge(edge["edge_node_id"], batch)) == 3
    assert edge["service"].sync_edge(edge["edge_node_id"], _chain(edge, 1, start=4, prev=chain_hash(batch[-1])))
    assert _flag(db, edge) is None
    assert db.execute("SELECT max(edge_seq) FROM edge_sync_items WHERE edge_node_id = %s",
                      (edge["edge_node_id"],)).fetchone()[0] == 4


def test_a_deleted_sale_is_a_gap_the_edge_is_flagged_and_alerted(edge, db):
    a, _deleted, c = _chain(edge, 3)
    edge["service"].sync_edge(edge["edge_node_id"], [a])
    with pytest.raises(Forbidden, match="gap"):
        edge["service"].sync_edge(edge["edge_node_id"], [c])
    assert "gap" in _flag(db, edge)
    assert edge["alerts"].raised and edge["alerts"].raised[0][0] == "critical"
    assert db.execute("SELECT action FROM audit_log WHERE entity_id = %s", (edge["edge_node_id"],)).fetchone() \
        == ("edge.chain_broken",)
    # Flagged: even a perfectly good batch waits for an operator now.
    with pytest.raises(Forbidden, match="on hold"):
        edge["service"].sync_edge(edge["edge_node_id"], _chain(edge, 1, start=2, prev=chain_hash(a)))
    assert len(edge["engine"].created) == 1, "nothing after the gap became a payment"


def test_an_edited_sale_is_a_fork_even_when_re_signed_with_the_edges_key(edge, db):
    first, second = _chain(edge, 2)
    edge["service"].sync_edge(edge["edge_node_id"], [first, second])
    lowered = {k: v for k, v in second.items() if k != "signature"} | {"amount": 1}
    with pytest.raises(Forbidden, match="different content"):
        edge["service"].sync_edge(edge["edge_node_id"], [_sign(edge, lowered)])
    assert _flag(db, edge)


def test_an_edge_that_chains_cannot_go_back_to_unchained_items(edge, db):
    edge["service"].sync_edge(edge["edge_node_id"], _chain(edge, 1))
    unchained = {k: v for k, v in _chain(edge, 1, start=2)[0].items() if k not in ("edge_seq", "prev_hash", "signature")}
    with pytest.raises(Forbidden, match="unchained"):
        edge["service"].sync_edge(edge["edge_node_id"], [_sign(edge, unchained)])


def test_the_cloud_re_enforces_the_rolling_24_hour_limit(edge, db):
    """The edge says it checked; the cloud checks again, over a rolling 24 hours by the edge's own clock."""
    now = datetime.now(UTC)
    for hours_ago, amount in ((30, 250_000), (20, 250_000)):  # 30 h ago is outside the window, 20 h ago inside it
        db.execute(
            "INSERT INTO transactions (idempotency_key, merchant_id, terminal_id, amount, currency, payment_method,"
            " capture_mode, status, metadata) VALUES (%s, %s, %s, %s, 'INR', 'CARD', 'AUTO', 'CAPTURED', %s)",
            (uuid4(), edge["merchant_id"], edge["terminal_id"], amount,
             f'{{"offline_local_timestamp": "{(now - timedelta(hours=hours_ago)).isoformat()}"}}'))
    fits, = _chain(edge, 1, amount=50_000, at=now)  # 250,000 + 50,000 = the 300,000 cap exactly
    assert edge["service"].sync_edge(edge["edge_node_id"], [fits])[0]["status"] == "PENDING"
    assert edge["engine"].created[-1]["metadata"]["offline_reference"] == fits["offline_reference"]
    over, = _chain(edge, 1, start=2, prev=chain_hash(fits), amount=50_001, at=now)
    result = edge["service"].sync_edge(edge["edge_node_id"], [over])
    assert result[0]["reason"] == "OFFLINE_DAILY_LIMIT_EXCEEDED", result
