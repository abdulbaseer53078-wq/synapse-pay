"""Database-backed deduplication for inbound webhooks (Step 10B).

At-least-once delivery means the PSP will resend. The unique key is the deduplication: `INSERT ... ON CONFLICT
DO NOTHING RETURNING 1` answers "new" or "seen" atomically, so two workers handling the same retry cannot both
win. A read-then-write would leave a window where both see "not seen".
"""
from psycopg_pool import ConnectionPool


class PostgresWebhookEvents:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def claim(self, provider: str, event_id: str) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO webhook_events (provider, event_id) VALUES (%s, %s)"
                " ON CONFLICT DO NOTHING RETURNING 1", (provider, event_id)).fetchone()
        return row is not None
