"""Step 17.3: chain epochs. After an unplanned region failover the new region continues the audit chain in a new
WORM key space, so the old region's lost-window records and the new region's records never collide, and the
verifier accepts the fork while reporting the lost window."""
import json
from pathlib import Path

from app.application.audit import AuditVerifier
from app.infrastructure.audit_worm import epoch_of_key
from app.infrastructure.postgres_audit import PostgresAuditStore
from test_audit_pipeline import RecordingAlerter, audit_pool, clean_chain, seed_payment, worm  # noqa: F401 (fixtures)


def lose_after(db, sequence: int) -> None:
    """Make this database look like the replica that never received anything chained after `sequence`:
    the chained rows, their audit_log sources and the head all roll back. (The WORM objects stay, as they would
    in the replicated bucket.)"""
    digest, audit_id = db.execute("SELECT hash, (SELECT max(audit_id) FROM audit_log)"
                                  " FROM audit_events WHERE sequence = %s", (sequence,)).fetchone()
    lost = db.execute("SELECT event_id FROM audit_events WHERE sequence > %s", (sequence,)).fetchall()
    for table in ("audit_events", "audit_log"):
        db.execute(f"ALTER TABLE {table} DISABLE TRIGGER {table}_append_only")
    db.execute("DELETE FROM audit_events WHERE sequence > %s", (sequence,))
    db.execute("DELETE FROM audit_log WHERE event_id = ANY(%s)", ([e for (e,) in lost],))
    for table in ("audit_events", "audit_log"):
        db.execute(f"ALTER TABLE {table} ENABLE TRIGGER {table}_append_only")
    last_kept = db.execute("SELECT max(audit_id) FROM audit_log").fetchone()[0] or 0
    assert last_kept <= audit_id
    db.execute("UPDATE audit_chain_head SET last_sequence = %s, last_hash = %s, last_audit_id = %s",
               (sequence, digest, last_kept))


def failover(db, audit_pool, worm):
    """Mumbai chains 1-6 (two payments); Hyderabad only received up to 3, starts epoch 2 and chains on."""
    store = PostgresAuditStore(audit_pool)
    seed_payment(db, {})
    seed_payment(db, {})
    assert store.ingest(worm) == 6
    lose_after(db, 3)
    epoch, inherited, _ = store.start_epoch("region failover")
    assert (epoch, inherited) == (2, 3)
    seed_payment(db, {})  # Hyderabad keeps taking payments
    assert store.ingest(worm) == 4  # the epoch marker + 3 new events
    return store


def epoch_records(worm, epoch):
    return [(k, d) for k, d in worm.records() if epoch_of_key(k) == epoch]


def test_failover_continues_the_chain_in_a_new_epoch(clean_chain, audit_pool, worm):
    failover(clean_chain, audit_pool, worm)
    first, second = epoch_records(worm, 1), epoch_records(worm, 2)
    assert [d["sequence"] for _, d in first] == [1, 2, 3, 4, 5, 6]  # Mumbai's, including its lost window
    assert [d["sequence"] for _, d in second] == [4, 5, 6, 7]
    assert all(k.startswith("audit/epoch-0002/") for k, _ in second)
    marker = second[0][1]
    assert marker["event_type"] == "AUDIT_CHAIN_EPOCH_STARTED"
    assert (marker["payload"]["epoch"], marker["payload"]["inherited_sequence"]) == (2, 3)
    assert marker["prev_hash"] == first[2][1]["hash"], "epoch 2 links to the head Hyderabad inherited"


def test_verifier_accepts_the_fork_and_reports_the_lost_window(clean_chain, audit_pool, worm):
    store = failover(clean_chain, audit_pool, worm)
    alerter = RecordingAlerter()
    result = AuditVerifier(worm, store, alerter).run()
    assert result.ok, result.detail
    assert result.chain_head == 7 and result.checked == 10
    assert "epoch 1 holds 3 record(s) after sequence 3" in result.detail
    assert alerter.calls == []


def test_tampering_in_either_epoch_is_still_detected(clean_chain, audit_pool, worm):
    store = failover(clean_chain, audit_pool, worm)
    for epoch in (1, 2):
        key, data = epoch_records(worm, epoch)[1]
        path = Path(worm.root) / key
        path.chmod(0o644)
        original = path.read_bytes()
        path.write_text(json.dumps({**data, "actor": "system:forged"}))
        result = AuditVerifier(worm, store, RecordingAlerter()).run()
        assert not result.ok and "hash mismatch" in result.detail, (epoch, result.detail)
        path.write_bytes(original)


def test_an_epoch_that_does_not_link_to_the_chain_is_rejected(clean_chain, audit_pool, worm):
    store = failover(clean_chain, audit_pool, worm)
    key, data = epoch_records(worm, 2)[0]
    path = Path(worm.root) / key
    path.chmod(0o644)
    path.write_text(json.dumps({**data, "prev_hash": "f" * 64}))
    result = AuditVerifier(worm, store, RecordingAlerter()).run()
    assert not result.ok and "broken link at sequence 4" in result.detail


def test_epoch_keys():
    assert epoch_of_key("audit/2026/11/07/00000000000000000042-ab.json") == 1
    assert epoch_of_key("audit/epoch-0002/2026/11/07/00000000000000000042-ab.json") == 2
    assert epoch_of_key("custom/epoch-0012/2026/x.json", prefix="custom") == 12
