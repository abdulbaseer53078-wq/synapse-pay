"""Read-only view of the settlements table (written by the nightly settlement job, not by requests)."""
from uuid import UUID

from psycopg_pool import ConnectionPool


class PostgresSettlements:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def list_for_merchant(self, merchant_id: UUID, limit: int) -> list[dict]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                """SELECT settlement_id, period_start, period_end,
                          gross_amount_minor, mdr_amount_minor, gst_amount_minor, net_amount_minor,
                          currency, status, settled_at
                   FROM settlements WHERE merchant_id = %s
                   ORDER BY created_at DESC LIMIT %s""",
                (merchant_id, limit),
            ).fetchall()
        return [
            {
                "settlement_id": f"stl_{r[0].hex}",
                "period_start": r[1].isoformat(),
                "period_end": r[2].isoformat(),
                "gross_amount_minor": r[3],
                "mdr_amount_minor": r[4],
                "gst_amount_minor": r[5],
                "net_amount_minor": r[6],
                "currency": r[7],
                "status": r[8],
                "settled_at": r[9].isoformat() if r[9] else None,
            }
            for r in rows
        ]
