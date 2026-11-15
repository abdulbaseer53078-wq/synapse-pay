"""Checkout sessions (migration 027): short-lived hosted payment pages for browser-based e-commerce."""
import os
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool


def _base_url() -> str:
    return os.environ.get("CHECKOUT_BASE_URL", "http://localhost:3000")


class PostgresCheckoutSessions:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def create(self, merchant_id: UUID, amount: int, currency: str, description: str | None,
               success_url: str, cancel_url: str, metadata: dict) -> dict:
        with self.pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO checkout_sessions"
                " (merchant_id, amount, currency, description, success_url, cancel_url, metadata)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " RETURNING session_id, url_token, status, expires_at, created_at",
                (merchant_id, amount, currency, description, success_url, cancel_url, Jsonb(metadata)),
            ).fetchone()
        session_id, url_token, status, expires_at, created_at = row
        return {
            "session_id": f"cs_{session_id.hex}",
            "checkout_url": f"{_base_url()}/pay/{url_token}",
            "amount": amount,
            "currency": currency,
            "description": description,
            "status": status,
            "intent_id": None,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata": metadata,
            "expires_at": expires_at.isoformat(),
            "created_at": created_at.isoformat(),
        }

    def get(self, session_id_str: str, merchant_id: UUID) -> dict | None:
        try:
            session_id = UUID(session_id_str.removeprefix("cs_"))
        except ValueError:
            return None
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT session_id, amount, currency, description, success_url, cancel_url,"
                "       status, intent_id, metadata, expires_at, created_at"
                " FROM checkout_sessions WHERE session_id = %s AND merchant_id = %s",
                (session_id, merchant_id),
            ).fetchone()
        if row is None:
            return None
        sid, amount, currency, description, success_url, cancel_url, status, intent_id, metadata, expires_at, created_at = row
        return {
            "session_id": f"cs_{sid.hex}",
            "amount": amount,
            "currency": currency,
            "description": description,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "status": status,
            "intent_id": f"pi_{intent_id.hex}" if intent_id else None,
            "metadata": metadata,
            "expires_at": expires_at.isoformat(),
            "created_at": created_at.isoformat(),
        }
