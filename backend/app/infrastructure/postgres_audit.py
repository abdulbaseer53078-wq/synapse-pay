"""Postgres side of the audit log: ingest (Step 7.3), query (7.6), publication cursor (7.2), run ledger (7.7).

Ingestion is the only writer of the chain, and it holds `audit_chain_head` FOR UPDATE for the whole batch:
one chain, no interleaved sequence numbers, no two ingesters racing to compute the same hash. The WORM write
happens inside that transaction, so the cursor never advances past an object that was not durably stored.
"""
from collections.abc import Iterator
from dataclasses import replace
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.audit.chain import Chain, StoredEvent
from app.audit.event import from_audit_row
from app.audit.sanitize import sanitize
from app.infrastructure.postgres_terminals import _OUTBOX_LOCK

_ROW = ("audit_id, event_id, occurred_at, actor_type, actor_id, entity_type, entity_id, action, from_status,"
        " to_status, reason, correlation_id, payload")
# The audit_log entity the chain's own events (epoch starts) are recorded against.
AUDIT_CHAIN_ENTITY = uuid5(NAMESPACE_URL, "urn:synapsepay:audit-chain")

_VIEW = ("sequence, event_id, occurred_at, event_type, actor, entity_id, correlation_id, payload, prev_hash, hash")


def _view(row) -> dict:
    sequence, event_id, occurred_at, event_type, actor, entity_id, correlation_id, payload, prev_hash, digest = row
    return {
        "sequence": sequence, "event_id": str(event_id),
        "timestamp": occurred_at.isoformat().replace("+00:00", "Z"),
        "event_type": event_type, "actor": actor, "entity_id": entity_id,
        "correlation_id": correlation_id, "payload": payload, "prev_hash": prev_hash, "hash": digest,
    }


class PostgresAuditStore:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    # --- 7.3 ingest -------------------------------------------------------------------------------------

    def ingest(self, worm, limit: int = 500) -> int:
        """Chain the next batch of audit_log rows into audit_events + WORM. Returns how many were ingested."""
        if limit <= 0:
            return 0
        with self.pool.connection() as conn, conn.transaction():
            sequence, head, last_audit_id, epoch = conn.execute(
                "SELECT last_sequence, last_hash, last_audit_id, epoch FROM audit_chain_head FOR UPDATE").fetchone()
            # Same ordering rule as the registry relay: audit ids are assigned at INSERT but rows commit out of
            # order, so a batch read without this lock could pass a row that commits later with a lower id.
            # Writers hold it shared until commit; taking it exclusively waits them out. It is released before
            # the WORM writes, so a slow object store never blocks the payment path.
            conn.execute("SELECT pg_advisory_lock(%s)", (_OUTBOX_LOCK,))
            try:
                rows = conn.execute(
                    f"SELECT {_ROW} FROM audit_log WHERE audit_id > %s ORDER BY audit_id LIMIT %s",
                    (last_audit_id, limit)).fetchall()
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (_OUTBOX_LOCK,))
            if not rows:
                return 0
            chain = Chain(sequence, head)
            for row in rows:
                # Sanitise before hashing: a masked value is part of the immutable record, not a view of it.
                event = from_audit_row(row[1:])
                stored = chain.append(replace(event, payload=sanitize(event.payload)))
                worm_key = worm.put(stored, epoch)
                self._insert(conn, stored, worm_key)
            conn.execute("UPDATE audit_chain_head SET last_sequence = %s, last_hash = %s, last_audit_id = %s",
                         (chain.sequence, chain.head, rows[-1][0]))
            return len(rows)

    @staticmethod
    def _insert(conn, stored: StoredEvent, worm_key: str) -> None:
        event = stored.event
        conn.execute(
            "INSERT INTO audit_events (sequence, event_id, occurred_at, event_type, actor, entity_id,"
            " correlation_id, payload, prev_hash, hash, worm_key) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (stored.sequence, event.event_id, event.timestamp, event.event_type, event.actor, event.entity_id,
             event.correlation_id, Jsonb(event.payload), stored.prev_hash, stored.hash, worm_key))

    def start_epoch(self, reason: str) -> tuple[int, int, str]:
        """Starts the next chain epoch (Step 17.3); run once in the new region after a failover, before ingest.

        Records the head this region inherited as an AUDIT_CHAIN_EPOCH_STARTED event, which ingest then chains
        as the new epoch's record of where it forked. Returns (epoch, inherited sequence, inherited hash).
        """
        with self.pool.connection() as conn, conn.transaction():
            sequence, head, epoch = conn.execute(
                "SELECT last_sequence, last_hash, epoch FROM audit_chain_head FOR UPDATE").fetchone()
            new_epoch = epoch + 1
            conn.execute("UPDATE audit_chain_head SET epoch = %s", (new_epoch,))
            conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))  # same rule as every audit writer
            conn.execute(
                "INSERT INTO audit_log (actor_type, entity_type, entity_id, action, from_status, to_status, reason,"
                " correlation_id, payload) VALUES ('SYSTEM', 'audit_chain', %s, 'epoch_started', %s, %s, %s, %s, %s)",
                (AUDIT_CHAIN_ENTITY, f"EPOCH_{epoch}", f"EPOCH_{new_epoch}", reason, "audit-chain",
                 Jsonb({"epoch": new_epoch, "inherited_sequence": sequence, "inherited_hash": head})))
            return new_epoch, sequence, head

    def chain_head(self) -> tuple[int, str]:
        with self.pool.connection() as conn:
            return conn.execute("SELECT last_sequence, last_hash FROM audit_chain_head").fetchone()

    # --- 7.6 query --------------------------------------------------------------------------------------

    def search(self, correlation_id: str | None = None, entity_id: str | None = None,
               event_type: str | None = None, start: datetime | None = None, end: datetime | None = None,
               after_sequence: int | None = None, limit: int = 100) -> tuple[list[dict], int | None]:
        """A page of chained events and the cursor for the next page (None on the last page)."""
        with self.pool.connection() as conn:
            rows = conn.execute(
                f"SELECT {_VIEW} FROM audit_events"
                " WHERE (%(corr)s::text IS NULL OR correlation_id = %(corr)s)"
                "   AND (%(entity)s::text IS NULL OR entity_id = %(entity)s)"
                "   AND (%(type)s::text IS NULL OR event_type = %(type)s)"
                "   AND (%(start)s::timestamptz IS NULL OR occurred_at >= %(start)s)"
                "   AND (%(end)s::timestamptz IS NULL OR occurred_at <= %(end)s)"
                "   AND (%(after)s::bigint IS NULL OR sequence > %(after)s)"
                " ORDER BY sequence LIMIT %(limit)s",
                {"corr": correlation_id, "entity": entity_id, "type": event_type, "start": start, "end": end,
                 "after": after_sequence, "limit": limit + 1}).fetchall()
            page = rows[:limit]
            return [_view(r) for r in page], (page[-1][0] if len(rows) > limit else None)

    # --- 7.2 publication --------------------------------------------------------------------------------

    def pending_publish(self, limit: int = 500) -> list[dict]:
        with self.pool.connection() as conn:
            (cursor,) = conn.execute("SELECT last_sequence FROM audit_publish_cursor").fetchone()
            rows = conn.execute(f"SELECT {_VIEW} FROM audit_events WHERE sequence > %s"
                                " ORDER BY sequence LIMIT %s", (cursor, limit)).fetchall()
            return [_view(r) for r in rows]

    def mark_published(self, sequence: int) -> None:
        with self.pool.connection() as conn:
            conn.execute("UPDATE audit_publish_cursor SET last_sequence = %s WHERE last_sequence < %s",
                         (sequence, sequence))

    # --- 7.7 verification ledger ------------------------------------------------------------------------

    def record_verification(self, started_at: datetime, events_checked: int, chain_head: int, status: str,
                            detail: str | None = None) -> UUID:
        with self.pool.connection() as conn:
            (run_id,) = conn.execute(
                "INSERT INTO audit_verification_runs (started_at, finished_at, events_checked, chain_head, status,"
                " detail) VALUES (%s, now(), %s, %s, %s, %s) RETURNING run_id",
                (started_at, events_checked, chain_head, status, detail)).fetchone()
        return run_id

    def stored_hashes(self) -> Iterator[tuple[int, str, str]]:
        """(sequence, prev_hash, hash) in chain order — the database's claim, for the verifier to check."""
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT sequence, prev_hash, hash FROM audit_events ORDER BY sequence").fetchall()
        for row in rows:
            yield row[0], row[1], row[2]
