from uuid import UUID

from psycopg_pool import ConnectionPool


class PostgresKyc:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def submit(self, merchant_id: UUID, pan: str, gst: str) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                "INSERT INTO merchant_kyc (merchant_id, pan_number, gst_number)"
                " VALUES (%s, %s, %s)"
                " ON CONFLICT (merchant_id) DO UPDATE"
                " SET pan_number = EXCLUDED.pan_number, gst_number = EXCLUDED.gst_number,"
                "     status = 'PENDING', updated_at = now()",
                (merchant_id, pan, gst),
            )

    def status_for(self, merchant_id: UUID) -> str | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT status FROM merchant_kyc WHERE merchant_id = %s",
                (merchant_id,),
            ).fetchone()
        return row[0] if row else None
