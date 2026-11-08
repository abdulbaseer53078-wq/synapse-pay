"""Step 24.5: tell the merchant app when a payment it accepted offline was refused at sync.

The alert is written in the same SQLite transaction that marks the payment FAILED, then POSTed to the merchant's
webhook until it answers 2xx: a power cut between the two can't lose it. Signed like the cloud's webhooks:
X-Signature is the lowercase hex HMAC-SHA256 of the raw body. No card data, ever.
"""
import hashlib
import hmac
import json
import logging
import sqlite3
from datetime import datetime
from typing import Callable

log = logging.getLogger("edge_node.alerts")

# post(url, body bytes, headers) -> HTTP status; raises on network errors.
Post = Callable[[str, bytes, dict], int]


def enqueue(conn: sqlite3.Connection, row: sqlite3.Row, result: dict, at: str) -> None:
    """Called inside the transaction that marks `row` FAILED."""
    item = json.loads(row["payload_json"])
    body = {"event": "offline_payment.failed", "offline_reference": row["offline_reference"],
            "idempotency_key": item["idempotency_key"], "terminal_id": item["terminal_id"],
            "amount": item["amount"], "currency": item["currency"], "rail": item["underlying_rail"],
            "accepted_at": item["local_timestamp"], "error": result.get("error"), "occurred_at": at}
    conn.execute("INSERT OR IGNORE INTO merchant_alerts (offline_reference, body_json, created_at) VALUES (?, ?, ?)",
                 (row["offline_reference"], json.dumps(body, sort_keys=True), at))


def deliver_pending(conn: sqlite3.Connection, url: str, secret: str, post: Post, at: datetime) -> int:
    """POSTs undelivered alerts, oldest first; stops at the first failure so order is kept. Returns how many went."""
    if not url:
        return 0
    sent = 0
    pending = conn.execute("SELECT id, body_json FROM merchant_alerts WHERE delivered_at IS NULL ORDER BY id").fetchall()
    for alert in pending:
        raw = alert["body_json"].encode()
        signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        conn.execute("UPDATE merchant_alerts SET attempts = attempts + 1 WHERE id = ?", (alert["id"],))
        try:
            status = post(url, raw, {"Content-Type": "application/json", "X-Signature": signature})
        except Exception as exc:
            log.warning("merchant alert not delivered (%s); will retry", type(exc).__name__)
            return sent
        if not 200 <= status < 300:
            log.warning("merchant webhook answered %s; will retry", status)
            return sent
        conn.execute("UPDATE merchant_alerts SET delivered_at = ? WHERE id = ?", (at.isoformat(), alert["id"]))
        sent += 1
    return sent
