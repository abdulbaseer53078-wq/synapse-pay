"""Merchant subscriptions in Postgres. Every change is audited in the same transaction, like every admin action."""
from datetime import datetime, timedelta
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
            row = conn.execute("SELECT tier, status, current_period_end, renewal_count FROM merchant_subscriptions"
                               " WHERE merchant_id = %s", (merchant_id,)).fetchone()
        return Subscription(merchant_id, *row) if row else None

    def save(self, subscription: Subscription, previous: Subscription, actor_id: str) -> None:
        renewal = subscription.renewal_count > previous.renewal_count
        with self.pool.connection() as conn, conn.transaction():
            try:
                conn.execute(
                    "INSERT INTO merchant_subscriptions (merchant_id, tier, status, current_period_end, renewal_count)"
                    " VALUES (%s, %s, %s, %s, %s) ON CONFLICT (merchant_id) DO UPDATE SET tier = excluded.tier,"
                    " status = excluded.status, current_period_end = excluded.current_period_end,"
                    " renewal_count = excluded.renewal_count, updated_at = now()",
                    (subscription.merchant_id, subscription.tier, subscription.status,
                     subscription.current_period_end, subscription.renewal_count))
            except errors.ForeignKeyViolation:
                raise UnknownReference("merchant not found", code="MERCHANT_NOT_FOUND")
            _audit_entity(conn, "ADMIN", actor_id, "merchant_subscription", subscription.merchant_id,
                          "subscription.renew" if renewal else "subscription.upgrade",
                          f"{previous.tier}/{previous.status}", f"{subscription.tier}/{subscription.status}",
                          payload={"current_period_end": subscription.current_period_end.isoformat(),
                                   "renewal_count": subscription.renewal_count})

    def list_active_expiring(self, now: datetime, within: timedelta) -> list[Subscription]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT merchant_id, tier, status, current_period_end, renewal_count FROM merchant_subscriptions"
                " WHERE status = 'ACTIVE' AND tier IN ('PRO', 'ENTERPRISE') AND current_period_end <= %s",
                (now + within,)).fetchall()
        return [Subscription(*row) for row in rows]
