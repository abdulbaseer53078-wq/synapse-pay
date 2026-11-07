"""Scheduled and long-running jobs. Run: python -m app.jobs <job>   (env: DATABASE_URL, KAFKA_BOOTSTRAP_SERVERS)

refresh-health moves terminals that stopped sending heartbeats to DEGRADED / UNREACHABLE.
Schedule it at least every 30 seconds (cron, or Celery beat once the queue exists).

relay-events runs forever, publishing registry events from the audit log to Kafka. Run one or more
instances; the outbox cursor lock lets only one publish at a time.
"""
import os
import sys
import time

from psycopg_pool import ConnectionPool

from app.application.events import EventRelay
from app.infrastructure.postgres_terminals import PostgresTerminalRepository

USAGE = "usage: python -m app.jobs refresh-health | relay-events"


def main(argv: list[str]) -> None:
    if argv not in (["refresh-health"], ["relay-events"]):
        sys.exit(USAGE)
    with ConnectionPool(os.environ["DATABASE_URL"], min_size=1, max_size=1) as pool:
        repo = PostgresTerminalRepository(pool)
        if argv == ["refresh-health"]:
            print(f"health_state changed for {repo.refresh_health()} terminal(s)")
            return
        from app.infrastructure.kafka_events import KafkaEventPublisher  # only this job needs the Kafka client
        relay = EventRelay(repo, KafkaEventPublisher(os.environ["KAFKA_BOOTSTRAP_SERVERS"]))
        while True:
            try:
                if relay.run_once() == 0:
                    time.sleep(0.2)
            except Exception as exc:  # keep relaying; the cursor didn't move, so the batch is retried
                print(f"relay failed, retrying: {exc}", file=sys.stderr)
                time.sleep(1)


if __name__ == "__main__":
    main(sys.argv[1:])
