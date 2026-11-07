import json
from datetime import UTC, datetime
from uuid import UUID

import httpx
from psycopg import Connection
from psycopg_pool import ConnectionPool

from app.application.webhooks import MAX_ATTEMPTS, backoff, sign


def enqueue(conn: Connection, merchant_id: UUID, url: str | None, payload: dict) -> None:
    """Adds a webhook to the outbox inside the caller's database transaction. No URL, no webhook."""
    if not url:
        return
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    conn.execute("INSERT INTO webhook_deliveries (merchant_id, url, body) VALUES (%s, %s, %s)",
                 (merchant_id, url, body))


class WebhookDispatcher:
    def __init__(self, pool: ConnectionPool, allow_insecure: bool = False, timeout: float = 5.0):
        self.pool = pool
        self.allow_insecure = allow_insecure  # http:// URLs, for local development and tests only
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)

    def deliver_due(self, limit: int = 50) -> int:
        """Tries every due webhook once; returns how many were delivered."""
        delivered = 0
        for _ in range(limit):
            with self.pool.connection() as conn, conn.transaction():
                row = conn.execute(
                    "SELECT d.delivery_id, d.url, d.body, d.attempts, m.webhook_secret FROM webhook_deliveries d"
                    " JOIN merchants m USING (merchant_id)"
                    " WHERE d.delivered_at IS NULL AND d.gave_up_at IS NULL AND d.next_attempt_at <= now()"
                    " ORDER BY d.next_attempt_at FOR UPDATE OF d SKIP LOCKED LIMIT 1").fetchone()
                if row is None:
                    break
                delivery_id, url, body, attempts, secret = row
                error = self._send(url, body, secret)
                attempts += 1
                if error is None:
                    conn.execute("UPDATE webhook_deliveries SET attempts = %s, delivered_at = now(), last_error = NULL"
                                 " WHERE delivery_id = %s", (attempts, delivery_id))
                    delivered += 1
                elif attempts >= MAX_ATTEMPTS:
                    conn.execute("UPDATE webhook_deliveries SET attempts = %s, gave_up_at = now(), last_error = %s"
                                 " WHERE delivery_id = %s", (attempts, error, delivery_id))
                else:
                    conn.execute("UPDATE webhook_deliveries SET attempts = %s, last_error = %s, next_attempt_at = %s"
                                 " WHERE delivery_id = %s",
                                 (attempts, error, datetime.now(UTC) + backoff(attempts), delivery_id))
        return delivered

    def _send(self, url: str, body: str, secret: str | None) -> str | None:
        if secret is None:
            return "merchant has no webhook secret"
        if not url.startswith("https://") and not self.allow_insecure:
            return "webhook_url must be https"
        raw = body.encode()
        try:
            response = self.client.post(url, content=raw, headers={
                "content-type": "application/json", "x-signature": sign(secret, raw),
                "user-agent": "SynapsePay-Webhooks/1"})
        except httpx.HTTPError as e:
            return f"{type(e).__name__}"
        return None if 200 <= response.status_code < 300 else f"HTTP {response.status_code}"
