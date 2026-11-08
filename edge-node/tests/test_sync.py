"""Step 24: the sync worker survives dropped networks, crashes and refusals, and never charges twice.
Includes the Step 21 gate (queue offline, reboot, sync) and the Step 24 gate (drop mid-sync, resume)."""
import hashlib
import hmac
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from edge_node import db
from edge_node.engine import create_app
from edge_node.rules import accept
from edge_node.sync import BACKOFF_MAX, SyncWorker, next_backoff
from tests.conftest import DECLINED_AMOUNT


class Webhook:
    def __init__(self):
        self.up = True
        self.received: list[tuple[bytes, dict]] = []

    def __call__(self, url, raw, headers):
        if not self.up:
            raise ConnectionError("merchant app offline")
        self.received.append((raw, headers))
        return 200


@pytest.fixture
def webhook():
    return Webhook()


def boot(cfg, cloud, clock, webhook):
    """A fresh Edge Node process: new app, new worker, the same SQLite file."""
    app = create_app(cfg, now=clock)
    sleeps = []
    worker = SyncWorker(cfg, cloud.fetch_rules, cloud.sync, webhook, now=clock, sleep=sleeps.append)
    return TestClient(app), worker, sleeps


@pytest.fixture
def edge(cfg, cloud, clock, webhook):
    conn = db.connect(cfg.db_path)
    db.migrate(conn)
    accept(conn, cloud.signed_rules(), cfg, clock())
    conn.close()
    return boot(cfg, cloud, clock, webhook)


def take(api, cfg, n, amount=10_000):
    refs = []
    for _ in range(n):
        r = api.post("/local/v1/transactions", json={
            "idempotency_key": str(uuid.uuid4()), "amount": amount, "currency": "INR", "payment_method": "CARD",
            "method_details": {"encrypted_card_data": "c2VhbGVk", "card_expiry": "08/28"},
            "terminal_id": "TERM-1", "merchant_id": cfg.merchant_id})
        assert r.status_code == 201, r.text
        refs.append(r.json()["offline_reference"])
    return refs


def statuses(cfg) -> dict:
    conn = db.connect(cfg.db_path)
    try:
        return {r["offline_reference"]: r["status"] for r in conn.execute("SELECT * FROM offline_queue ORDER BY id")}
    finally:
        conn.close()


def test_sqlite_runs_in_wal_mode(cfg, edge):
    conn = db.connect(cfg.db_path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()


def test_step_21_gate_offline_reboot_then_sync(cfg, cloud, clock, webhook, edge):
    api, _, _ = edge
    cloud.reachable = False  # the internet is unplugged
    refs = take(api, cfg, 5)
    _, worker, _ = boot(cfg, cloud, clock, webhook)  # the edge reboots
    assert worker.run_once() == "offline"
    assert set(statuses(cfg).values()) == {"PENDING_OFFLINE"}, "the queue survived the reboot"
    cloud.reachable = True  # plugged back in
    assert worker.run_once() == "synced"
    assert statuses(cfg) == {r: "SYNCED" for r in refs}
    assert len(cloud.charges) == 5, "five signatures verified, five charges"


def test_step_24_gate_network_drops_mid_sync_then_resumes_without_duplicates(cfg, cloud, clock, webhook, edge):
    api, worker, sleeps = edge
    refs = take(api, cfg, 20)
    cloud.die_after = 10  # the cloud processes 10, then the connection dies
    worker.run_forever(stop=iter([False, False, True]).__next__)
    assert sleeps == [2.0], "backed off once after the drop"
    assert statuses(cfg) == {r: "SYNCED" for r in refs}
    assert len(cloud.charges) == 20 and len(set(cloud.charges)) == 20, "all 20 settled, none twice"
    assert [len(b) for b in cloud.batches] == [20, 20], "the whole batch again; the first 10 came back as replays"


def test_batches_of_50_in_fifo_order(cfg, cloud, edge):
    api, worker, _ = edge
    refs = take(api, cfg, 120, amount=5_000)
    while worker.run_once() == "synced":
        pass
    assert [len(b) for b in cloud.batches] == [50, 50, 20]
    assert [r for b in cloud.batches for r in b] == refs, "oldest first, never reordered"


def test_a_crash_mid_sync_is_recovered_after_two_minutes(cfg, cloud, clock, webhook, edge):
    api, worker, _ = edge
    refs = take(api, cfg, 3)
    conn = db.connect(cfg.db_path)
    rows = worker.claim(conn)  # marked SYNCING, sent ...
    cloud.sync([json.loads(r["payload_json"]) for r in rows])  # ... the cloud processed it ... power cut
    conn.close()
    _, rebooted, _ = boot(cfg, cloud, clock, webhook)
    assert rebooted.run_once() == "idle" and set(statuses(cfg).values()) == {"SYNCING"}, "too early to assume dead"
    clock.advance(minutes=2, seconds=1)
    assert rebooted.run_once() == "synced"
    assert statuses(cfg) == {r: "SYNCED" for r in refs}
    assert len(cloud.charges) == 3, "the resend was answered from the cloud's idempotency, not charged again"


def test_still_processing_goes_round_again(cfg, cloud, edge):
    api, worker, _ = edge
    [ref] = take(api, cfg, 1)
    cloud.still_processing.add(ref)
    worker.run_once()
    assert statuses(cfg)[ref] == "PENDING_OFFLINE", "a retryable answer isn't a failure"
    worker.run_once()
    assert statuses(cfg)[ref] == "SYNCED"


def test_a_refused_payment_fails_and_alerts_the_merchant(cfg, cloud, edge, webhook):
    api, worker, _ = edge
    [ref] = take(api, cfg, 1, amount=DECLINED_AMOUNT)
    webhook.up = False
    worker.run_once()
    assert statuses(cfg)[ref] == "FAILED" and webhook.received == []
    webhook.up = True
    worker.run_once()  # the alert outbox is retried until delivered
    [(raw, headers)] = webhook.received
    alert = json.loads(raw)
    assert (alert["event"], alert["offline_reference"], alert["error"]["error_code"]) == \
        ("offline_payment.failed", ref, "INSUFFICIENT_FUNDS")
    assert headers["X-Signature"] == hmac.new(b"whsec_test", raw, hashlib.sha256).hexdigest()
    assert "c2VhbGVk" not in raw.decode(), "no card data in alerts"
    worker.run_once()
    assert len(webhook.received) == 1, "delivered once"


def test_cloud_unavailable_backs_off_exponentially(cfg, cloud, edge):
    api, worker, _ = edge
    take(api, cfg, 2)
    cloud.status = 503
    assert worker.run_once() == "failed"
    assert set(statuses(cfg).values()) == {"PENDING_OFFLINE"}, "released, not lost"
    waits, wait = [], 0.0
    for _ in range(7):
        wait = next_backoff(wait)
        waits.append(wait)
    assert waits == [2, 4, 8, 16, 32, BACKOFF_MAX, BACKOFF_MAX]


def test_synced_payloads_are_purged_after_30_days(cfg, clock, edge):
    api, worker, _ = edge
    take(api, cfg, 2)
    worker.run_once()
    clock.advance(days=29)
    assert worker.purge() == 0
    clock.advance(days=2)
    assert worker.purge() == 2


def test_the_worker_can_start_first_on_a_fresh_box(cfg, cloud, clock, webhook):
    worker = SyncWorker(cfg, cloud.fetch_rules, cloud.sync, webhook, now=clock, sleep=lambda s: None)
    assert worker.run_once() == "idle", "migrated its own database; rules fetched"
