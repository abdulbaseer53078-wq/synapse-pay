"""Read-only view over the merchant_settlements SQL view (migration 025).

The view is authoritative because it derives from the same double-entry ledger the platform uses
for its own books. net_amount = net_amount_ledger - gst_on_fee; the subtraction is done here
because net_amount_ledger is the MERCHANT_PAYABLE credit which does not yet deduct GST.
"""
from uuid import UUID

from psycopg_pool import ConnectionPool


class PostgresSettlements:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def list_for_merchant(
        self,
        merchant_id: UUID,
        limit: int = 100,
        after: str | None = None,  # cursor: settled_at ISO string of last row seen
    ) -> dict:
        with self.pool.connection() as conn:
            rows = conn.execute(
                """SELECT settlement_id, transaction_id, currency, settled_at,
                          gross_amount, mdr_fee, gst_on_fee,
                          net_amount_ledger - gst_on_fee AS net_amount
                   FROM merchant_settlements
                   WHERE merchant_id = %s
                     AND (%s::timestamptz IS NULL OR settled_at < %s::timestamptz)
                   ORDER BY settled_at DESC
                   LIMIT %s""",
                (merchant_id, after, after, limit + 1),
            ).fetchall()

        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]

        next_cursor = rows[-1][3].isoformat() if has_more and rows else None
        return {
            "items": [
                {
                    "settlement_id": str(r[0]),
                    "transaction_id": str(r[1]),
                    "currency": r[2],
                    "settled_at": r[3].isoformat(),
                    "gross_amount": r[4],
                    "mdr_fee": r[5],
                    "gst_on_fee": r[6],
                    "net_amount": r[7],
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
