"""Read-only view of risk holds (written by the risk engine, resolved by compliance ops)."""
from uuid import UUID

from psycopg_pool import ConnectionPool


class PostgresRisk:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def holds_for_merchant(self, merchant_id: UUID) -> list[dict]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                """SELECT hold_id, transaction_id, hold_reason, required_documents, created_at
                   FROM risk_holds
                   WHERE merchant_id = %s AND resolved_at IS NULL
                   ORDER BY created_at DESC""",
                (merchant_id,),
            ).fetchall()
        return [
            {
                "hold_id": f"hold_{r[0].hex}",
                "transaction_id": str(r[1]),
                "hold_reason": r[2],
                "required_documents": r[3] or [],
                "created_at": r[4].isoformat(),
            }
            for r in rows
        ]
