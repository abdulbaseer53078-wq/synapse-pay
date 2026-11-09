"""The cloud's memory of each edge node's hash chain (PR 6), and the offline spend it has accepted per terminal."""
from contextlib import contextmanager
from datetime import datetime
from uuid import UUID

from psycopg_pool import ConnectionPool

from app.infrastructure.postgres_terminals import _OUTBOX_LOCK


class PostgresEdgeChain:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    @contextmanager
    def exclusive(self, edge_node_id: UUID):
        """One sync batch per edge at a time: the chain check and the rolling total must not interleave."""
        with self.pool.connection() as conn:
            conn.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))", (f"edge-sync:{edge_node_id}",))
            try:
                yield
            finally:
                conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (f"edge-sync:{edge_node_id}",))

    def flagged(self, edge_node_id: UUID) -> str | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT flagged_reason FROM edge_nodes WHERE edge_node_id = %s AND flagged_at IS NOT NULL",
                               (edge_node_id,)).fetchone()
        return row[0] if row else None

    def head(self, edge_node_id: UUID, seqs: list[int]) -> tuple[int, dict[int, str]]:
        """(highest accepted seq, {seq: hash} for the given seqs and that highest one)."""
        with self.pool.connection() as conn:
            (last,) = conn.execute("SELECT coalesce(max(edge_seq), 0) FROM edge_sync_items WHERE edge_node_id = %s",
                                   (edge_node_id,)).fetchone()
            rows = conn.execute("SELECT edge_seq, item_hash FROM edge_sync_items WHERE edge_node_id = %s"
                                " AND edge_seq = ANY(%s)", (edge_node_id, [*seqs, last])).fetchall()
        return int(last), {int(s): h for s, h in rows}

    def record(self, edge_node_id: UUID, links: list[tuple[int, str]]) -> None:
        if not links:
            return
        with self.pool.connection() as conn, conn.transaction():
            conn.cursor().executemany("INSERT INTO edge_sync_items (edge_node_id, edge_seq, item_hash) VALUES (%s, %s, %s)"
                                      " ON CONFLICT DO NOTHING", [(edge_node_id, s, h) for s, h in links])

    def flag(self, edge_node_id: UUID, reason: str) -> None:
        """Stop trusting this edge's offline sales until an operator has looked at it. Audited."""
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("UPDATE edge_nodes SET flagged_at = now(), flagged_reason = %s WHERE edge_node_id = %s"
                         " AND flagged_at IS NULL", (reason[:255], edge_node_id))
            conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))
            conn.execute(
                "INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action, from_status, to_status,"
                " reason) VALUES ('SYSTEM', NULL, 'edge_node', %s, 'edge.chain_broken', 'ACTIVE', 'FLAGGED', %s)",
                (edge_node_id, reason[:255]))

    def offline_total(self, terminal_id: UUID, since: datetime, until: datetime, excluding_key: str) -> int:
        """Offline sales this terminal made between `since` and `until` (by the edge's clock) that the cloud accepted
        and that didn't fail. The sale being checked is excluded, so a resent batch isn't counted against itself."""
        with self.pool.connection() as conn:
            (total,) = conn.execute(
                "SELECT coalesce(sum(amount), 0) FROM transactions WHERE terminal_id = %s AND status <> 'FAILED'"
                " AND metadata ? 'offline_local_timestamp' AND idempotency_key::text <> %s"
                " AND (metadata->>'offline_local_timestamp')::timestamptz BETWEEN %s AND %s",
                (terminal_id, excluding_key, since, until)).fetchone()
        return int(total)
