"""Scheduled and long-running jobs. Run: python -m app.jobs <job>   (env: DATABASE_URL, KAFKA_BOOTSTRAP_SERVERS)

refresh-health moves terminals that stopped sending heartbeats to DEGRADED / UNREACHABLE.
Schedule it at least every 30 seconds (cron, or Celery beat once the queue exists).

relay-events runs forever, publishing registry events from the audit log to Kafka. Run one or more
instances; the outbox cursor lock lets only one publish at a time.

audit-ingest runs forever, chaining new audit_log rows into audit_events and WORM storage (Step 7.3/7.4).
Exactly one instance; it holds the chain head lock.

audit-publish runs forever, fanning the chained events out to audit.events for external consumers (Step 7.2).

audit-new-epoch runs once, in the new region after an unplanned failover and before audit-ingest starts there
(docs/step17.md): it moves the chain to a new key space so it can't fork inside the WORM bucket (Step 17.3).

verify-audit runs once: it recomputes the whole chain from WORM storage and exits non-zero on a mismatch.
Schedule it hourly (Step 7.7) — a chain nobody checks is a decoration.

audit-seed writes a synthetic payment timeline to audit_log, so the pipeline can be demonstrated and tested
before the SDK and terminal producers exist.

upi-poll runs forever, asking the PSP for the authoritative status of UPI payments a lost webhook left PENDING
(Step 10A). Webhooks are primary; this is the fallback.

sweep runs forever (PR 3), every 2 minutes: fails requests that died before reaching the network and frees their
idempotency keys, resolves card payments whose reversal the card service's queue has since sent, and re-sends
refunds left PENDING. Needs CARD_SERVICE_URL, UPI_PSP_URL and WALLET_URL like the API.
"""
import os
import sys
import time
from uuid import uuid4

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.audit import AuditVerifier
from app.application.events import EventRelay
from app.application.fees import ConfigFeePolicy
from app.application.recovery import sweep_async_pending
from app.config import fee_bps_from_env
from app.infrastructure.audit_alerts import NullAlerter, WebhookAlerter
from app.infrastructure.audit_worm import worm_from_env
from app.infrastructure.postgres_audit import PostgresAuditStore
from app.infrastructure.postgres_terminals import PostgresTerminalRepository
from app.infrastructure.postgres_transactions import PostgresTransactionRepository

JOBS = ("refresh-health", "relay-events", "audit-ingest", "audit-publish", "verify-audit", "audit-seed", "upi-poll",
        "audit-new-epoch", "sweep")
USAGE = f"usage: python -m app.jobs {' | '.join(JOBS)}"


def _alerter():
    url = os.environ.get("AUDIT_ALERT_WEBHOOK_URL")
    return WebhookAlerter(url) if url else NullAlerter()


def main(argv: list[str]) -> None:
    if len(argv) != 1 or argv[0] not in JOBS:
        sys.exit(USAGE)
    job = argv[0]
    with ConnectionPool(os.environ["DATABASE_URL"], min_size=1, max_size=1) as pool:
        if job == "refresh-health":
            print(f"health_state changed for {PostgresTerminalRepository(pool).refresh_health()} terminal(s)")
            return
        if job == "relay-events":
            _relay(pool)
            return
        if job == "upi-poll":
            _upi_poll(pool)
            return
        if job == "sweep":
            _sweep(pool)
            return
        store = PostgresAuditStore(pool)
        if job == "audit-ingest":
            _forever(lambda: store.ingest(worm_from_env(), limit=500), idle=0.5,
                     done=lambda n: print(f"chained {n} event(s)"))
        elif job == "audit-publish":
            _publish(store)
        elif job == "verify-audit":
            result = AuditVerifier(worm_from_env(), store, _alerter()).run()
            print(f"checked {result.checked} event(s), head {result.chain_head}: "
                  f"{'OK' if result.ok else 'TAMPERED'}{' — ' + result.detail if result.detail else ''}")
            sys.exit(0 if result.ok else 1)
        elif job == "audit-seed":
            _seed(pool)
        elif job == "audit-new-epoch":
            epoch, sequence, head = store.start_epoch(os.environ.get("AUDIT_EPOCH_REASON", "region failover"))
            print(f"audit chain now in epoch {epoch}, continuing from sequence {sequence} ({head[:12]}…)")


def _relay(pool: ConnectionPool) -> None:
    from app.infrastructure.kafka_events import KafkaEventPublisher  # only this job needs the Kafka client
    relay = EventRelay(PostgresTerminalRepository(pool), KafkaEventPublisher(os.environ["KAFKA_BOOTSTRAP_SERVERS"]))
    _forever(lambda: relay.run_once(), idle=0.2)


def _upi_poll(pool: ConnectionPool) -> None:
    """The polling fallback (Steps 10A and 12b): resolve payments a lost webhook left PENDING.

    Webhooks are primary; this exists because they get lost. It asks the provider for the authoritative status
    and hands the answer to `apply_method_result`, the same path the synchronous engine uses — the adapter never
    writes state. Both asynchronous rails are swept, because a lost wallet callback is the same problem.
    """
    from app.infrastructure.methods.upi import UpiMethodAdapter
    from app.infrastructure.methods.wallet import HttpWallet, WalletMethodAdapter
    from app.infrastructure.upi_client import HttpUpiPsp

    sweeps = [
        ("UPI", UpiMethodAdapter(HttpUpiPsp(os.environ["UPI_PSP_URL"]))),
        ("WALLET", WalletMethodAdapter(HttpWallet(os.environ.get("WALLET_URL", "http://127.0.0.1:8090")))),
    ]
    # The poller settles payments too, so it posts them to the ledger with the same fee rates as the API.
    repo = PostgresTransactionRepository(pool, ConfigFeePolicy(fee_bps_from_env()))
    stale_after = int(os.environ.get("UPI_POLL_STALE_SECONDS", "300"))

    _forever(lambda: sweep_async_pending(repo, sweeps, stale_after), idle=5.0,
             done=lambda n: print(f"polled {n} pending transaction(s)"))


def _sweep(pool: ConnectionPool) -> None:
    """PR 3's recovery sweeps (app/application/recovery.py), plus PR 4's PENDING refunds."""
    from app.application.methods import MethodRegistry
    from app.application.recovery import sweep_card_pending, sweep_stuck_keys
    from app.application.refunds import RefundService
    from app.infrastructure.card_service_client import HttpCardProcessor
    from app.infrastructure.methods.card import CardMethodAdapter
    from app.infrastructure.methods.qr import QrMethodAdapter
    from app.infrastructure.methods.upi import UpiMethodAdapter
    from app.infrastructure.methods.wallet import HttpWallet, WalletMethodAdapter
    from app.infrastructure.postgres_refunds import PostgresRefunds
    from app.infrastructure.upi_client import HttpUpiPsp

    fees = ConfigFeePolicy(fee_bps_from_env())
    repo = PostgresTransactionRepository(pool, fees)
    cards = HttpCardProcessor(os.environ.get("CARD_SERVICE_URL", "http://127.0.0.1:7070"))
    rails = MethodRegistry([CardMethodAdapter(cards), UpiMethodAdapter(HttpUpiPsp(os.environ["UPI_PSP_URL"])),
                            WalletMethodAdapter(HttpWallet(os.environ.get("WALLET_URL", "http://127.0.0.1:8090")))])
    refunds = RefundService(PostgresRefunds(pool, fees), MethodRegistry([*rails.adapters(), QrMethodAdapter(rails)]))

    def once() -> int:
        return (sweep_stuck_keys(repo) + sweep_card_pending(repo, cards)
                + refunds.resolve_pending(older_than_seconds=60))

    _forever(once, idle=120.0, done=lambda n: print(f"swept {n} stuck payment(s) and refund(s)"))


def _publish(store: PostgresAuditStore) -> None:
    from app.infrastructure.kafka_audit import KafkaAuditPublisher
    publisher = KafkaAuditPublisher(os.environ["KAFKA_BOOTSTRAP_SERVERS"])

    def once() -> int:
        records = store.pending_publish()
        if records:
            publisher.publish(records)
            store.mark_published(records[-1]["sequence"])
        return len(records)

    _forever(once, idle=0.2)


def _forever(step, idle: float, done=None) -> None:
    while True:
        try:
            count = step()
            if count and done:
                done(count)
            if not count:
                time.sleep(idle)
        except Exception as exc:  # keep the loop alive; the cursor did not move, so the batch is retried
            print(f"job step failed, retrying: {type(exc).__name__}: {exc}", file=sys.stderr)
            time.sleep(1)


def _seed(pool: ConnectionPool) -> None:
    """A three-event payment, including a PAN, to prove masking end to end without a card service."""
    transaction_id, terminal_id = uuid4(), uuid4()
    timeline = [
        ("transaction.create", None, "INITIATED",
         {"amount": 49999, "currency": "INR", "note": "customer paid with 4111111111111111"}),
        ("transaction.send", "INITIATED", "PENDING", {}),
        ("transaction.finish", "PENDING", "AUTHORIZED",
         {"response_code": "00", "pan": "4111111111111111", "cvv": "123"}),
    ]
    with pool.connection() as conn, conn.transaction():
        for action, from_status, to_status, payload in timeline:
            conn.execute(
                "INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action, from_status, to_status,"
                " correlation_id, payload) VALUES ('TERMINAL', %s, 'transaction', %s, %s, %s, %s, %s, %s)",
                (str(terminal_id), transaction_id, action, from_status, to_status, str(transaction_id),
                 Jsonb(payload)))
    print(f"seeded {len(timeline)} audit event(s); correlation_id={transaction_id}")
