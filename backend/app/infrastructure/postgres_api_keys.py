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

    def create(self, merchant_id: UUID, mode: str = "test") -> tuple[str, UUID]:
        key = f"sk_{mode}_{secrets.token_urlsafe(32)}"
        with self.pool.connection() as conn:
            (key_id,) = conn.execute(
                "INSERT INTO api_keys (merchant_id, key_hash, key_prefix) VALUES (%s, %s, %s) RETURNING key_id",
                (merchant_id, _hash(key), key[:12]),
            ).fetchone()
        return key, key_id

    def merchant_for(self, key: str) -> UUID | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT merchant_id FROM api_keys WHERE key_hash = %s AND revoked_at IS NULL",
                               (_hash(key),)).fetchone()
            return row[0] if row else None

    def list_for_merchant(self, merchant_id: UUID) -> list[dict]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT key_id, key_prefix, created_at, revoked_at FROM api_keys"
                " WHERE merchant_id = %s ORDER BY created_at DESC",
                (merchant_id,),
            ).fetchall()
        return [{"key_id": str(r[0]), "prefix": r[1], "created_at": r[2].isoformat(),
                 "revoked_at": r[3].isoformat() if r[3] else None} for r in rows]

    def revoke(self, key_id: UUID, merchant_id: UUID) -> bool:
        """Returns True if a key was revoked, False if not found or already revoked."""
        with self.pool.connection() as conn:
            row = conn.execute(
                "UPDATE api_keys SET revoked_at = now()"
                " WHERE key_id = %s AND merchant_id = %s AND revoked_at IS NULL RETURNING key_id",
                (key_id, merchant_id),
            ).fetchone()
        return row is not None


def create_merchant(pool: ConnectionPool) -> dict:
    """A merchant with a secret API key and a webhook signing secret (sandbox onboarding)."""
    webhook_secret = f"whsec_{secrets.token_urlsafe(32)}"
    with pool.connection() as conn:
        (merchant_id,) = conn.execute("INSERT INTO merchants (webhook_secret) VALUES (%s) RETURNING merchant_id",
                                      (webhook_secret,)).fetchone()
    key, _ = PostgresApiKeys(pool).create(merchant_id)
    return {"merchant_id": str(merchant_id), "secret_key": key, "webhook_secret": webhook_secret}
