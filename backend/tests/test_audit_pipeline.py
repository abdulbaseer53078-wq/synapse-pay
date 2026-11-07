"""The audit pipeline end to end against Postgres: ingest, chain, WORM, query API, verification."""
import json
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from psycopg_pool import ConnectionPool

from app.application.audit import AuditVerifier
from app.infrastructure.audit_worm import LocalWormSink
from app.infrastructure.postgres_audit import PostgresAuditStore


class RecordingAlerter:
    def __init__(self):
        self.calls = []

    def tamper_detected(self, detail, checked, sequence):
        self.calls.append((detail, checked, sequence))


@pytest.fixture
def audit_pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=2) as pool:
        yield pool


@pytest.fixture
def clean_chain(db):
    """The chain tables are not in conftest's TRUNCATE list; a stale head would collide on sequence."""
    db.execute("TRUNCATE audit_events, audit_verification_runs")
    db.execute("UPDATE audit_chain_head SET last_sequence = 0, last_hash = repeat('0', 64), last_audit_id = 0,"
               " epoch = 1")
    db.execute("UPDATE audit_publish_cursor SET last_sequence = 0")
    return db


@pytest.fixture
def worm(tmp_path):
    return LocalWormSink(tmp_path / "worm")


def seed_payment(db, payload: dict | None = None) -> str:
    """Three audit_log rows for one payment, as Step 5's transaction repository writes them."""
    transaction_id, terminal_id = uuid4(), uuid4()
    rows = [
        ("transaction.create", None, "INITIATED", {"amount": 49999, "currency": "INR"}),
        ("transaction.send", "INITIATED", "PENDING", {}),
        ("transaction.finish", "PENDING", "AUTHORIZED",
         payload if payload is not None else {"response_code": "00", "pan": "4111111111111111", "cvv": "123"}),
    ]
    for action, from_status, to_status, body in rows:
        db.execute(
            "INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action, from_status, to_status,"
            " correlation_id, payload) VALUES ('TERMINAL', %s, 'transaction', %s, %s, %s, %s, %s, %s)",
            (str(terminal_id), transaction_id, action, from_status, to_status, str(transaction_id),
             json.dumps(body)))
    return str(transaction_id)


def test_ingest_chains_and_masks_pan(clean_chain, audit_pool, worm):
    correlation_id = seed_payment(clean_chain)
    store = PostgresAuditStore(audit_pool)

    assert store.ingest(worm, limit=500) == 3
    assert store.ingest(worm, limit=500) == 0  # cursor advanced; nothing left

    head, digest = store.chain_head()
    assert head == 3 and len(digest) == 64

    records = [data for _, data in worm.records()]
    assert [r["sequence"] for r in records] == [1, 2, 3]
    assert records[0]["prev_hash"] == "0" * 64
    assert records[1]["prev_hash"] == records[0]["hash"]
    assert records[0]["correlation_id"] == correlation_id

    # 7.5: the PAN and CVV never reached the immutable copy.
    body = json.dumps(records[2])
    assert "4111111111111111" not in body and "123" not in body
    assert records[2]["payload"]["pan"] == "[redacted]"
    assert records[2]["payload"]["cvv"] == "[redacted]"


def test_events_carry_the_universal_shape(clean_chain, audit_pool, worm):
    seed_payment(clean_chain)
    store = PostgresAuditStore(audit_pool)
    store.ingest(worm)
    data, _ = store.search(limit=10)
    types = [e["event_type"] for e in data]
    assert types == ["TRANSACTION_INITIATED", "TRANSACTION_SUBMITTED", "TRANSACTION_AUTHORIZED"]
    assert data[0]["actor"].startswith("terminal:")
    assert {"event_id", "timestamp", "event_type", "actor", "entity_id", "correlation_id", "payload"} <= set(data[0])


def test_query_api_timeline(clean_chain, audit_pool, worm, client, auth):
    correlation_id = seed_payment(clean_chain)
    PostgresAuditStore(audit_pool).ingest(worm)

    r = client.get(f"/api/v1/audit/events?correlation_id={correlation_id}", headers=auth(scope="audit:read"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert [e["event_type"] for e in body["data"]] == [
        "TRANSACTION_INITIATED", "TRANSACTION_SUBMITTED", "TRANSACTION_AUTHORIZED"]
    assert body["next_cursor"] is None
    assert body["data"][0]["sequence"] == 1


def test_query_api_pages_with_cursor(clean_chain, audit_pool, worm, client, auth):
    seed_payment(clean_chain)
    PostgresAuditStore(audit_pool).ingest(worm)
    headers = auth(scope="audit:read")

    first = client.get("/api/v1/audit/events?limit=2", headers=headers).json()
    assert len(first["data"]) == 2 and first["next_cursor"] == 2
    second = client.get(f"/api/v1/audit/events?limit=2&cursor={first['next_cursor']}", headers=headers).json()
    assert [e["sequence"] for e in second["data"]] == [3] and second["next_cursor"] is None


def test_query_api_requires_the_audit_scope(clean_chain, client, auth):
    assert client.get("/api/v1/audit/events").status_code == 401
    assert client.get("/api/v1/audit/events", headers=auth(scope="registry:read")).status_code == 403


def test_verifier_accepts_an_intact_chain(clean_chain, audit_pool, worm):
    seed_payment(clean_chain)
    store = PostgresAuditStore(audit_pool)
    store.ingest(worm)

    result = AuditVerifier(worm, store, RecordingAlerter()).run()
    assert result.ok and result.checked == 3 and result.first_bad_sequence is None


def test_verifier_detects_an_edited_worm_object(clean_chain, audit_pool, worm):
    seed_payment(clean_chain)
    store = PostgresAuditStore(audit_pool)
    store.ingest(worm)

    target = sorted((worm.root).rglob("*.json"))[1]
    os.chmod(target, 0o644)
    record = json.loads(target.read_text())
    record["payload"]["amount"] = 1  # "the payment was only ₹1"
    target.write_text(json.dumps(record))

    alerter = RecordingAlerter()
    result = AuditVerifier(worm, store, alerter).run()
    assert not result.ok
    assert result.first_bad_sequence == 2
    assert "hash mismatch" in (result.detail or "")
    assert alerter.calls and "TAMPERED" not in alerter.calls[0][0]


def test_verifier_detects_a_deleted_worm_object(clean_chain, audit_pool, worm):
    seed_payment(clean_chain)
    store = PostgresAuditStore(audit_pool)
    store.ingest(worm)

    victim = sorted(worm.root.rglob("*.json"))[1]
    os.chmod(victim, 0o644)  # objects are written 0o444; Windows refuses to delete a read-only file
    victim.unlink()
    result = AuditVerifier(worm, store, RecordingAlerter()).run()
    assert not result.ok and "sequence gap" in (result.detail or "")


def test_verification_is_recorded(clean_chain, audit_pool, worm):
    seed_payment(clean_chain)
    store = PostgresAuditStore(audit_pool)
    store.ingest(worm)
    AuditVerifier(worm, store, RecordingAlerter()).run()

    run = clean_chain.execute("SELECT status, events_checked, chain_head, finished_at FROM audit_verification_runs"
                              ).fetchone()
    assert run[0] == "OK" and run[1] == 3 and run[2] == 3 and run[3] is not None


def test_publish_cursor_walks_the_chain(clean_chain, audit_pool, worm):
    seed_payment(clean_chain)
    store = PostgresAuditStore(audit_pool)
    store.ingest(worm)

    batch = store.pending_publish()
    assert [r["sequence"] for r in batch] == [1, 2, 3]
    store.mark_published(batch[-1]["sequence"])
    assert store.pending_publish() == []


def test_registry_events_are_chained_too(clean_chain, audit_pool, worm, created):
    """A terminal created through the API is audited by Step 3 already; Step 7 chains it unchanged."""
    store = PostgresAuditStore(audit_pool)
    store.ingest(worm)
    data, _ = store.search(entity_id=created["terminal_id"], limit=10)
    assert data and data[0]["event_type"] == "TERMINAL_CREATED"
    assert data[0]["payload"]["new_state"] == "PENDING"
