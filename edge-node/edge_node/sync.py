"""Step 24: the sync worker. Delivers the offline queue to the cloud, oldest first, one batch at a time.

    recover   SYNCING rows older than 2 minutes go back to PENDING_OFFLINE (the process died mid-send)
    connect   fetch the rules: proves the cloud is reachable and keeps them fresh (Step 20)
    claim     the oldest 50 PENDING_OFFLINE rows become SYNCING, in one transaction
    send      POST /api/v1/transactions/sync with the signed items, byte for byte as queued
    apply     per item: accepted → SYNCED; refused for good → FAILED + merchant alert; retryable or missing →
              back to PENDING_OFFLINE

Re-sending is always safe: every item carries its idempotency_key, so the cloud replays its earlier answer instead
of charging again. That is what makes "the network died after the cloud processed half the batch" harmless: the
whole batch goes again and the processed half comes back as replays.
"""
import json
import logging
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from typing import Callable

from edge_node import alerts, db, rules
from edge_node.config import EdgeConfig

log = logging.getLogger("edge_node.sync")

BATCH = 50
STUCK_AFTER = timedelta(minutes=2)
INTERVAL = 10.0  # seconds between passes while healthy
BACKOFF_FIRST, BACKOFF_MAX = 2.0, 60.0
KEEP_SYNCED = timedelta(days=30)

# send(items) -> (HTTP status, parsed JSON body or None). Raises on network errors and timeouts.
Send = Callable[[list[dict]], tuple[int, dict | None]]


def next_backoff(previous: float) -> float:
    return BACKOFF_FIRST if previous <= 0 else min(previous * 2, BACKOFF_MAX)


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")


class SyncWorker:
    def __init__(self, cfg: EdgeConfig, fetch_rules: Callable[[], dict], send: Send, post: alerts.Post,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC), sleep: Callable[[float], None] = time.sleep):
        self.cfg, self.fetch_rules, self.send, self.post, self.now, self.sleep = cfg, fetch_rules, send, post, now, sleep
        conn = db.connect(cfg.db_path)  # the worker may start before the API on a fresh box
        db.migrate(conn)
        conn.close()

    def recover(self, conn: sqlite3.Connection) -> int:
        """Rows a crashed pass left SYNCING go back to the queue. Safe: re-sending is idempotent."""
        cutoff = _iso(self.now() - STUCK_AFTER)
        return conn.execute("UPDATE offline_queue SET status = 'PENDING_OFFLINE', updated_at = ?"
                            " WHERE status = 'SYNCING' AND claimed_at < ?", (_iso(self.now()), cutoff)).rowcount

    def claim(self, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        at = _iso(self.now())
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute("SELECT * FROM offline_queue WHERE status = 'PENDING_OFFLINE' ORDER BY id LIMIT ?",
                                (BATCH,)).fetchall()
            conn.executemany("UPDATE offline_queue SET status = 'SYNCING', claimed_at = ?, updated_at = ?,"
                             " sync_attempts = sync_attempts + 1 WHERE id = ?", [(at, at, r["id"]) for r in rows])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return rows

    def release(self, conn: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
        conn.executemany("UPDATE offline_queue SET status = 'PENDING_OFFLINE', updated_at = ? WHERE id = ?",
                         [(_iso(self.now()), r["id"]) for r in rows])

    def apply(self, conn: sqlite3.Connection, rows: list[sqlite3.Row], results: list[dict]) -> dict:
        by_reference = {r.get("offline_reference"): r for r in results}
        at = _iso(self.now())
        counts = {"SYNCED": 0, "FAILED": 0, "RETRY": 0}
        conn.execute("BEGIN IMMEDIATE")
        try:
            for row in rows:
                result = by_reference.get(row["offline_reference"])
                error = (result or {}).get("error") or {}
                if result is None or error.get("retryable"):
                    # Not answered, or "still processing" / a transient failure: it goes again next pass.
                    conn.execute("UPDATE offline_queue SET status = 'PENDING_OFFLINE', updated_at = ? WHERE id = ?",
                                 (at, row["id"]))
                    counts["RETRY"] += 1
                elif result.get("status") == "FAILED":
                    conn.execute("UPDATE offline_queue SET status = 'FAILED', result_json = ?, updated_at = ?"
                                 " WHERE id = ?", (json.dumps(result), at, row["id"]))
                    alerts.enqueue(conn, row, result, at)
                    counts["FAILED"] += 1
                else:
                    conn.execute("UPDATE offline_queue SET status = 'SYNCED', transaction_id = ?, result_json = ?,"
                                 " updated_at = ? WHERE id = ?",
                                 (result.get("transaction_id"), json.dumps(result), at, row["id"]))
                    counts["SYNCED"] += 1
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return counts

    def run_once(self) -> str:
        """One pass. Returns 'idle', 'synced', 'offline' or 'failed' ('offline'/'failed' mean back off)."""
        conn = db.connect(self.cfg.db_path)
        try:
            recovered = self.recover(conn)
            if recovered:
                log.info("recovered %d payment(s) left SYNCING by an interrupted pass", recovered)
            if rules.refresh(conn, self.cfg, self.fetch_rules, self.now()) is None:
                return "offline"
            alerts.deliver_pending(conn, self.cfg.merchant_webhook_url, self.cfg.merchant_webhook_secret,
                                   self.post, self.now())
            rows = self.claim(conn)
            if not rows:
                return "idle"
            try:
                status, body = self.send([json.loads(r["payload_json"]) for r in rows])
            except Exception as exc:
                self.release(conn, rows)
                log.warning("sync batch not delivered (%s); will retry", type(exc).__name__)
                return "failed"
            if status != 200 or not isinstance(body, dict) or not isinstance(body.get("results"), list):
                self.release(conn, rows)
                log.warning("cloud answered the sync batch with %s; will retry", status)
                return "failed"
            counts = self.apply(conn, rows, body["results"])
            log.info("synced batch: %s", counts)
            alerts.deliver_pending(conn, self.cfg.merchant_webhook_url, self.cfg.merchant_webhook_secret,
                                   self.post, self.now())
            return "synced"
        finally:
            conn.close()

    def purge(self) -> int:
        """SYNCED payloads older than 30 days: the cloud's audit log holds them now."""
        conn = db.connect(self.cfg.db_path)
        try:
            return conn.execute("DELETE FROM offline_queue WHERE status = 'SYNCED' AND updated_at < ?",
                                (_iso(self.now() - KEEP_SYNCED),)).rowcount
        finally:
            conn.close()

    def run_forever(self, stop: Callable[[], bool] = lambda: False) -> None:
        backoff, last_purge = 0.0, None
        while not stop():
            try:
                outcome = self.run_once()
            except Exception:
                log.exception("sync pass crashed")
                outcome = "failed"
            if outcome in ("offline", "failed"):
                backoff = next_backoff(backoff)
                self.sleep(backoff)
                continue
            backoff = 0.0
            today = self.now().date()
            if last_purge != today:
                self.purge()
                last_purge = today
            if outcome == "idle":
                self.sleep(INTERVAL)  # 'synced' goes straight round: there may be more queued
