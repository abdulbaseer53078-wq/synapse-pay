"""Kafka fan-out for audit events (Step 7.2).

Keyed by `correlation_id`, so every event of one payment lands in the same partition and external consumers
(SIEM, fraud, reconciliation) read that transaction's story in order. Publishing happens *after* chaining, so
the records on the wire carry their sequence and hashes — a downstream system can verify what it received.

The payment path never waits on this: it writes its outbox row inside its own transaction, and this job tails
the chained index. Kafka is the fan-out, not the write path.
"""
from confluent_kafka import KafkaException, Producer

from app.audit.chain import canonical

TOPIC = "audit.events"


class AuditPublishFailed(RuntimeError): ...


class KafkaAuditPublisher:
    def __init__(self, bootstrap_servers: str, topic: str = TOPIC, timeout: float = 30):
        self._producer = Producer({"bootstrap.servers": bootstrap_servers, "enable.idempotence": True})
        self.topic = topic
        self.timeout = timeout

    def publish(self, records: list[dict]) -> None:
        failures = []

        def delivered(err, _msg):
            if err is not None:
                failures.append(err)

        try:
            for record in records:
                self._producer.produce(self.topic, key=record["correlation_id"],
                                       value=canonical(record), on_delivery=delivered)
            unsent = self._producer.flush(self.timeout)
        except (KafkaException, BufferError) as exc:
            raise AuditPublishFailed(f"kafka produce failed: {exc}") from exc
        if unsent or failures:
            raise AuditPublishFailed(f"{unsent} undelivered, {len(failures)} failed: {failures[:1]}")
