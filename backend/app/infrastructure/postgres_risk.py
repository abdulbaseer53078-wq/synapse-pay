"""Risk hold queries (migration 026). internal_notes is never returned."""
from uuid import UUID

from psycopg_pool import ConnectionPool

_COLS = "hold_id, transaction_id, reason, required_documents, status, created_at, resolved_at"


def _row(r) -> dict:
    return {
        "hold_id": str(r[0]),
        "transaction_id": str(r[1]) if r[1] else None,
        "reason": r[2],
        "required_documents": r[3] or [],
        "status": r[4],
        "created_at": r[5].isoformat(),
        "resolved_at": r[6].isoformat() if r[6] else None,
    }


class PostgresRisk:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def holds_for_merchant(self, merchant_id: UUID, status_filter: str = "open") -> list[dict]:
        where = (
            "merchant_id = %s AND status IN ('OPEN', 'REVIEWING')"
            if status_filter == "open"
            else "merchant_id = %s"
        )
        with self.pool.connection() as conn:
            rows = conn.execute(
                f"SELECT {_COLS} FROM risk_holds WHERE {where} ORDER BY created_at DESC",
                (merchant_id,),
            ).fetchall()
        return [_row(r) for r in rows]

    def hold_for_merchant(self, hold_id: UUID, merchant_id: UUID) -> dict | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                f"SELECT {_COLS} FROM risk_holds WHERE hold_id = %s AND merchant_id = %s",
                (hold_id, merchant_id),
            ).fetchone()
        return _row(row) if row else None
