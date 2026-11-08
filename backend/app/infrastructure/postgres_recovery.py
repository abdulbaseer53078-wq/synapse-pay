"""Merchant recovery stats (Step 18): payments a backup acquirer saved, counted from the audit trail.

The cascade's attempt trail is written with the transaction's final state (transaction.finish), so a payment
counts as cascaded exactly when that row lists more than one attempt.
"""
from datetime import datetime
from uuid import UUID

from psycopg_pool import ConnectionPool

_APPROVED = ("AUTHORIZED", "CAPTURED", "SETTLED")


class PostgresRecoveryStats:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def for_merchant(self, merchant_id: UUID, since: datetime) -> dict:
        with self.pool.connection() as conn:
            # Via the merchant's terminals so the (terminal_id, created_at) index does the work; audit rows are
            # found by audit_log_entity_idx. Amounts are summed per currency: they can't be added across them.
            rows = conn.execute(
                "SELECT t.currency, count(*), count(*) FILTER (WHERE t.status = ANY(%s)),"
                " coalesce(sum(t.amount) FILTER (WHERE t.status = ANY(%s)), 0)::bigint"
                " FROM transactions t JOIN audit_log a ON a.entity_type = 'transaction'"
                "  AND a.entity_id = t.transaction_id AND a.action = 'transaction.finish'"
                " WHERE t.terminal_id IN (SELECT terminal_id FROM terminals WHERE merchant_id = %s)"
                "  AND t.merchant_id = %s AND t.created_at >= %s"
                "  AND jsonb_array_length(coalesce(a.payload->'attempts', '[]')) > 1"
                " GROUP BY t.currency ORDER BY t.currency",
                (list(_APPROVED), list(_APPROVED), merchant_id, merchant_id, since)).fetchall()
        return {
            "since": since.isoformat().replace("+00:00", "Z"),
            "cascaded": sum(r[1] for r in rows),
            "recovered": sum(r[2] for r in rows),
            "recovered_amount": [{"currency": r[0], "amount": r[3]} for r in rows if r[3]],
        }
