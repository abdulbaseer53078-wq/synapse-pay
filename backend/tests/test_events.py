"""Task 2.9 acceptance: every registry change is emitted to Kafka, consumable, and ordered per terminal.

Needs Kafka: `docker compose up -d kafka` from the repo root, or set KAFKA_BOOTSTRAP_SERVERS.
"""
import json
import os
import threading
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from psycopg_pool import ConnectionPool

from app import jobs
from app.application.events import EventPublishFailed, EventRelay
from app.infrastructure.postgres_terminals import _OUTBOX_LOCK, PostgresTerminalRepository
from terminal_sim import ADMIN, change, url
from test_heartbeat import heartbeat_body, send

confluent_kafka = pytest.importorskip("confluent_kafka")
from confluent_kafka.admin import AdminClient, NewTopic  # noqa: E402
BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


@pytest.fixture(scope="module")
def topic():
    """A fresh 3-partition topic per module, so earlier runs' events don't interfere."""
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    try:
        admin.list_topics(timeout=5)
    except confluent_kafka.KafkaException:
        pytest.skip(f"Kafka not reachable at {BOOTSTRAP}")
    name = f"terminal.registry.events.test-{uuid4().hex[:8]}"
    admin.create_topics([NewTopic(name, num_partitions=3, replication_factor=1)])[name].result()
    yield name
    admin.delete_topics([name])


@pytest.fixture
def relay(database_url, topic, db):
    from app.infrastructure.kafka_events import KafkaEventPublisher
    with ConnectionPool(database_url, min_size=1, max_size=2) as pool:
        yield EventRelay(PostgresTerminalRepository(pool), KafkaEventPublisher(BOOTSTRAP, topic))


def consume(topic, terminal_id, expected: int) -> list[tuple[int, dict]]:
    """(partition, event) for terminal_id, in topic order, once `expected` of them have arrived."""
    consumer = confluent_kafka.Consumer({"bootstrap.servers": BOOTSTRAP, "group.id": uuid4().hex,
                                         "auto.offset.reset": "earliest"})
    consumer.subscribe([topic])
    found, deadline = [], datetime.now() + timedelta(seconds=30)
    try:
        while len(found) < expected and datetime.now() < deadline:
            msg = consumer.poll(1)
            if msg is not None and not msg.error() and msg.key() == str(terminal_id).encode():
                found.append((msg.partition(), json.loads(msg.value())))
    finally:
        consumer.close()
    return found


def test_every_registry_change_is_emitted_in_order(client, db, active, terminal, auth, merchant, relay, topic,
                                                   database_url, monkeypatch):
    tid = active["terminal_id"]
    send(client, active, heartbeat_body(), terminal)                                    # UNREACHABLE → HEALTHY
    send(client, active, heartbeat_body(firmware="2.5.0",
                                        sent_at=datetime.now(UTC) + timedelta(seconds=1)), terminal)
    change(client, active, "suspend", auth(), "investigating")
    client.get(f"/api/v1/terminals/{tid}", headers=auth(sub=ADMIN, scope="registry:admin"))  # not an event
    change(client, active, "reinstate", auth(sub=ADMIN, scope="registry:admin"))
    db.execute("UPDATE terminals SET last_heartbeat_at = now() - interval '10 minutes' WHERE terminal_id = %s",
               (tid,))
    monkeypatch.setenv("DATABASE_URL", database_url)
    jobs.main(["refresh-health"])                                                       # HEALTHY → UNREACHABLE
    change(client, active, "decommission", auth())

    expected = [
        ("TERMINAL_CREATED", None, "PENDING", f"merchant:{merchant}"),
        ("TERMINAL_REGISTERED", "PENDING", "PENDING_ACTIVATION", f"terminal:{tid}"),
        ("TERMINAL_ACTIVATED", "PENDING_ACTIVATION", "ACTIVE", f"terminal:{tid}"),
        ("TERMINAL_HEALTH_CHANGED", "UNREACHABLE", "HEALTHY", "system"),
        ("TERMINAL_FIRMWARE_CHANGED", "2.4.1", "2.5.0", f"terminal:{tid}"),
        ("TERMINAL_SUSPENDED", "ACTIVE", "SUSPENDED", f"merchant:{merchant}"),
        ("TERMINAL_REINSTATED", "SUSPENDED", "ACTIVE", f"admin:{ADMIN}"),
        ("TERMINAL_HEALTH_CHANGED", "HEALTHY", "UNREACHABLE", "system"),
        ("TERMINAL_DECOMMISSIONED", "ACTIVE", "DECOMMISSIONED", f"merchant:{merchant}"),
    ]
    assert relay.run_once() == len(expected)
    assert relay.run_once() == 0  # nothing published twice

    events = consume(topic, tid, len(expected))
    assert [(e["event_type"], e["previous_state"], e["new_state"], e["actor"]) for _, e in events] == expected
    assert len({p for p, _ in events}) == 1  # one partition per terminal, so consumers see this order
    suspended = events[5][1]
    assert suspended["terminal_id"] == tid and suspended["merchant_id"] == str(merchant)
    assert suspended["reason"] == "investigating" and suspended["metadata"] == {}
    assert datetime.fromisoformat(suspended["timestamp"]).tzinfo is not None
    assert len({e["event_id"] for _, e in events}) == len(expected)


def test_relay_waits_for_uncommitted_audit_rows(database_url, db, active, relay, topic):
    """An audit row that commits after a later one must still be published, not skipped by the cursor."""
    relay.run_once()
    with psycopg.connect(database_url) as writer:  # an in-flight registry change
        writer.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))
        writer.execute("INSERT INTO audit_log (actor_type, entity_type, entity_id, action, from_status, to_status)"
                       " VALUES ('SYSTEM', 'terminal', %s, 'suspend', 'ACTIVE', 'SUSPENDED')",
                       (active["terminal_id"],))
        published = []
        t = threading.Thread(target=lambda: published.append(relay.run_once()))
        t.start()
        t.join(timeout=1)
        assert t.is_alive(), "relay must wait for the in-flight writer"
        writer.commit()
    t.join(timeout=30)
    assert published == [1]


def test_failed_publish_leaves_the_cursor(database_url, db, active, relay, topic):
    class Down:
        def publish(self, events):
            raise EventPublishFailed("broker down")

    with ConnectionPool(database_url, min_size=1, max_size=1) as pool:
        with pytest.raises(EventPublishFailed):
            EventRelay(PostgresTerminalRepository(pool), Down()).run_once()
    assert relay.run_once() == 3  # create, register, activate: all retried
