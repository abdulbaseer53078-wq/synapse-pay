from confluent_kafka import KafkaException, Producer

from app.application.events import TOPIC, EventPublishFailed, RegistryEvent


class KafkaEventPublisher:
    """Keyed by terminal_id, so a terminal's events share a partition and keep their order."""

    def __init__(self, bootstrap_servers: str, topic: str = TOPIC, timeout: float = 30):
        # Idempotence implies acks=all and keeps per-partition order across retries.
        self._producer = Producer({"bootstrap.servers": bootstrap_servers, "enable.idempotence": True})
        self.topic = topic
        self.timeout = timeout

    def publish(self, events: list[RegistryEvent]) -> None:
        failures = []

        def delivered(err, _msg):
            if err is not None:
                failures.append(err)

        try:
            for e in events:
                self._producer.produce(self.topic, key=str(e.terminal_id), value=e.to_json(), on_delivery=delivered)
            unsent = self._producer.flush(self.timeout)
        except (KafkaException, BufferError) as exc:
            raise EventPublishFailed(f"kafka produce failed: {exc}") from exc
        if unsent or failures:
            raise EventPublishFailed(f"{unsent} undelivered, {len(failures)} failed: {failures[:1]}")
