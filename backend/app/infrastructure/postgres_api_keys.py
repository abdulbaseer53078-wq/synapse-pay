import hashlib
import secrets
from uuid import UUID

from psycopg_pool import ConnectionPool


def _hash(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()


class PostgresApiKeys:
    """Secret API keys (sk_test_...). Only their SHA-256 is stored: a key is shown once, at creation."""

    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def create(self, merchant_id: UUID, mode: str = "test") -> str:
        key = f"sk_{mode}_{secrets.token_urlsafe(32)}"
        with self.pool.connection() as conn:
            conn.execute("INSERT INTO api_keys (merchant_id, key_hash, key_prefix) VALUES (%s, %s, %s)",
                         (merchant_id, _hash(key), key[:12]))
        return key

    def merchant_for(self, key: str) -> UUID | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT merchant_id FROM api_keys WHERE key_hash = %s AND revoked_at IS NULL",
                               (_hash(key),)).fetchone()
            return row[0] if row else None


def create_merchant(pool: ConnectionPool) -> dict:
    """A merchant with a secret API key and a webhook signing secret (sandbox onboarding)."""
    webhook_secret = f"whsec_{secrets.token_urlsafe(32)}"
    with pool.connection() as conn:
        (merchant_id,) = conn.execute("INSERT INTO merchants (webhook_secret) VALUES (%s) RETURNING merchant_id",
                                      (webhook_secret,)).fetchone()
    return {"merchant_id": str(merchant_id), "secret_key": PostgresApiKeys(pool).create(merchant_id),
            "webhook_secret": webhook_secret}
