"""The Edge Node's one SQLite file: rules cache, offline queue, merchant alert outbox.

WAL lets the local engine write new payments while the sync worker reads and updates the queue (Step 24.1);
synchronous=FULL makes a committed payment survive a power cut, which is the whole point of queueing it.
A connection per unit of work keeps threads (FastAPI's pool, the sync worker) from sharing one.
"""
import sqlite3
from pathlib import Path

# Append-only: entry N is applied once, in order, and recorded in PRAGMA user_version. Never edit a shipped entry.
MIGRATIONS: list[str] = [
    # 1. Step 20: signed rule sets, newest wins; the clock high-water mark.
    """
    CREATE TABLE rules_cache (
        rules_version INTEGER PRIMARY KEY,
        issued_at     TEXT NOT NULL,
        body_json     TEXT NOT NULL,          -- the signed body exactly as the cloud sent it
        fetched_at    TEXT NOT NULL
    );
    CREATE TABLE clock_guard (
        singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
        high_water TEXT NOT NULL             -- latest time ever seen, from our clock or the cloud's
    );
    """,
    # 2. Step 21: payments accepted offline, FIFO by id.
    """
    CREATE TABLE offline_queue (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        offline_reference TEXT NOT NULL UNIQUE,
        idempotency_key   TEXT NOT NULL UNIQUE,
        request_hash      TEXT NOT NULL,
        terminal_id       TEXT NOT NULL,
        amount            INTEGER NOT NULL CHECK (amount > 0),
        payload_json      TEXT NOT NULL,      -- the signed sync item, exactly as it will be sent
        status            TEXT NOT NULL DEFAULT 'PENDING_OFFLINE'
                          CHECK (status IN ('PENDING_OFFLINE', 'SYNCING', 'SYNCED', 'FAILED')),
        created_at        TEXT NOT NULL,
        updated_at        TEXT NOT NULL,
        claimed_at        TEXT,
        sync_attempts     INTEGER NOT NULL DEFAULT 0,
        transaction_id    TEXT,
        result_json       TEXT,
        card_ref_hash     TEXT,               -- Step 22: HMAC of the card under the merchant's blocklist key
        token_reference   TEXT,               -- Step 23: card-on-file payments carry a reference, never a token
        customer_ref      TEXT
    );
    CREATE INDEX offline_queue_status_idx ON offline_queue (status, id);
    CREATE INDEX offline_queue_terminal_day_idx ON offline_queue (terminal_id, created_at);
    """,
    # 3. Step 24.5: alerts to the merchant app, delivered until acknowledged.
    """
    CREATE TABLE merchant_alerts (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        offline_reference TEXT NOT NULL UNIQUE,
        body_json         TEXT NOT NULL,
        created_at        TEXT NOT NULL,
        attempts          INTEGER NOT NULL DEFAULT 0,
        delivered_at      TEXT
    );
    """,
]


def connect(path: Path | str) -> sqlite3.Connection:
    """Autocommit mode: write paths open their own `BEGIN IMMEDIATE` so check-then-write is atomic."""
    conn = sqlite3.connect(str(path), timeout=5, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    (applied,) = conn.execute("PRAGMA user_version").fetchone()
    for number, sql in enumerate(MIGRATIONS[applied:], start=applied + 1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in filter(str.strip, sql.split(";")):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {number}")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
