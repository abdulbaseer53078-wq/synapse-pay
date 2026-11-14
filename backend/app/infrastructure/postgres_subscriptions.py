"""Merchant subscriptions in Postgres. Every change is audited in the same transaction, like every admin action."""
from uuid import UUID

from psycopg import errors
from psycopg_pool import ConnectionPool

from app.application.registration import UnknownReference
from app.application.subscriptions import Subscription
from app.infrastructure.postgres_transactions import _audit_entity


class PostgresSubscriptions:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def get(self, merchant_id: UUID) -> Subscription | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT tier, status, current_period_end FROM merchant_subscriptions"
                               " WHERE merchant_id = %s", (merchant_id,)).fetchone()
        return Subscription(merchant_id, *row) if row else None

    def save(self, subscription: Subscription, previous: Subscription, actor_id: str) -> None:
        with self.pool.connection() as conn, conn.transaction():
            try:
                conn.execute(
                    "INSERT INTO merchant_subscriptions (merchant_id, tier, status, current_period_end)"
                    " VALUES (%s, %s, %s, %s) ON CONFLICT (merchant_id) DO UPDATE SET tier = excluded.tier,"
                    " status = excluded.status, current_period_end = excluded.current_period_end, updated_at = now()",
                    (subscription.merchant_id, subscription.tier, subscription.status,
                     subscription.current_period_end))
            except errors.ForeignKeyViolation:
                raise UnknownReference("merchant not found", code="MERCHANT_NOT_FOUND")
            _audit_entity(conn, "ADMIN", actor_id, "merchant_subscription", subscription.merchant_id,
                          "subscription.upgrade", f"{previous.tier}/{previous.status}",
                          f"{subscription.tier}/{subscription.status}",
                          payload={"current_period_end": subscription.current_period_end.isoformat()})
