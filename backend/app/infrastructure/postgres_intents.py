from uuid import UUID

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.fees import ConfigFeePolicy, FeePolicy
from app.application.payment_intents import Intent, NewIntent, public_intent_id
from app.application.transactions import CardResult
from app.domain.ledger import SALE_STATUSES
from app.domain.state_machine import transition
from app.infrastructure.postgres_ledger import post_sale_once
from app.infrastructure.postgres_transactions import _audit_entity, _response, settle_intent
from app.infrastructure.webhook_outbox import enqueue

_COLUMNS = ("intent_id, merchant_id, amount, currency, capture_mode, description, metadata, webhook_url, terminal_id,"
            " status, client_secret, expires_at, pending_card, transaction_id, last_payment_error, card_bin,"
            " card_last4, created_at, updated_at")


def _intent(row: dict | None) -> Intent | None:
    return Intent(**row) if row else None


class PostgresIntentRepository:
    def __init__(self, pool: ConnectionPool, fees: FeePolicy | None = None):
        self.pool = pool
        self.fees = fees or ConfigFeePolicy({})  # no rates configured: no fee

    def create(self, new: NewIntent) -> tuple[Intent, bool]:
        """Returns (intent, created). An existing intent with the same key is returned with created=False; the
        caller compares request hashes."""
        with self.pool.connection() as conn, conn.transaction():
            cur = conn.cursor(row_factory=dict_row)
            row = cur.execute(
                f"INSERT INTO payment_intents (intent_id, merchant_id, idempotency_key, request_hash, amount, currency,"
                f" capture_mode, description, metadata, webhook_url, terminal_id, status, client_secret, expires_at)"
                f" VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'REQUIRES_PAYMENT_METHOD', %s, %s)"
                f" ON CONFLICT (merchant_id, idempotency_key) DO NOTHING RETURNING {_COLUMNS}",
                (new.intent_id, new.merchant_id, new.idempotency_key, new.request_hash, new.amount, new.currency, new.capture_mode,
                 new.description, Jsonb(new.metadata), new.webhook_url, new.terminal_id, new.client_secret,
                 new.expires_at)).fetchone()
            if row is not None:
                _audit_entity(conn, "MERCHANT", str(new.merchant_id), "payment_intent", row["intent_id"],
                              "payment_intent.create", None, "REQUIRES_PAYMENT_METHOD")
                return Intent(**row), True
            existing = cur.execute(
                f"SELECT {_COLUMNS}, request_hash FROM payment_intents WHERE merchant_id = %s AND idempotency_key = %s",
                (new.merchant_id, new.idempotency_key)).fetchone()
            request_hash = bytes(existing.pop("request_hash"))
            intent = Intent(**existing)
            return (intent if request_hash == new.request_hash else None), False

    def get(self, intent_id: UUID) -> Intent | None:
        with self.pool.connection() as conn:
            cur = conn.cursor(row_factory=dict_row)
            return _intent(cur.execute(f"SELECT {_COLUMNS} FROM payment_intents WHERE intent_id = %s",
                                        (intent_id,)).fetchone())

    def by_client_secret(self, client_secret: str) -> Intent | None:
        with self.pool.connection() as conn:
            cur = conn.cursor(row_factory=dict_row)
            return _intent(cur.execute(f"SELECT {_COLUMNS} FROM payment_intents WHERE client_secret = %s",
                                        (client_secret,)).fetchone())

    def begin_confirm(self, intent_id: UUID) -> Intent | None:
        """REQUIRES_PAYMENT_METHOD → PROCESSING, atomically. None if it wasn't in that state (or has expired)."""
        with self.pool.connection() as conn, conn.transaction():
            cur = conn.cursor(row_factory=dict_row)
            row = cur.execute(
                f"UPDATE payment_intents SET status = 'PROCESSING', last_payment_error = NULL, updated_at = now()"
                f" WHERE intent_id = %s AND status = 'REQUIRES_PAYMENT_METHOD' AND expires_at > now()"
                f" RETURNING {_COLUMNS}", (intent_id,)).fetchone()
            if row:
                _audit_entity(conn, "SYSTEM", "client", "payment_intent", intent_id, "payment_intent.confirm",
                              "REQUIRES_PAYMENT_METHOD", "PROCESSING")
            return _intent(row)

    def require_action(self, intent_id: UUID, pending_card: dict, card_bin: str, card_last4: str) -> None:
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("UPDATE payment_intents SET status = 'REQUIRES_ACTION', pending_card = %s, card_bin = %s,"
                         " card_last4 = %s, updated_at = now() WHERE intent_id = %s",
                         (Jsonb(pending_card), card_bin, card_last4, intent_id))
            _audit_entity(conn, "SYSTEM", "client", "payment_intent", intent_id, "payment_intent.require_action",
                          "PROCESSING", "REQUIRES_ACTION")

    def take_pending_card(self, intent_id: UUID) -> dict | None:
        """REQUIRES_ACTION → PROCESSING, returning (and deleting) the card waiting for the challenge."""
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "UPDATE payment_intents i SET status = 'PROCESSING', pending_card = NULL, updated_at = now()"
                " FROM (SELECT intent_id, pending_card FROM payment_intents WHERE intent_id = %s FOR UPDATE) old"
                " WHERE i.intent_id = old.intent_id AND i.status = 'REQUIRES_ACTION' RETURNING old.pending_card",
                (intent_id,)).fetchone()
            return row[0] if row else None

    def fail_attempt(self, intent_id: UUID, error: dict) -> None:
        """Back to the customer without a transaction (authentication failed, unreadable card)."""
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("UPDATE payment_intents SET status = 'REQUIRES_PAYMENT_METHOD', pending_card = NULL,"
                         " last_payment_error = %s, updated_at = now() WHERE intent_id = %s",
                         (Jsonb(error), intent_id))
            _audit_entity(conn, "SYSTEM", "client", "payment_intent", intent_id, "payment_intent.attempt_failed",
                          None, "REQUIRES_PAYMENT_METHOD", error["error_code"])

    def start_online_transaction(self, intent: Intent) -> UUID:
        with self.pool.connection() as conn, conn.transaction():
            (transaction_id,) = conn.execute(
                "INSERT INTO transactions (idempotency_key, merchant_id, terminal_id, channel, payment_intent_id,"
                " amount, currency, payment_method, capture_mode, status, metadata, webhook_url)"
                " VALUES (gen_random_uuid(), %s, NULL, 'ONLINE', %s, %s, %s, 'CARD', %s, 'PENDING', %s, %s)"
                " RETURNING transaction_id",
                (intent.merchant_id, intent.intent_id, intent.amount, intent.currency, intent.capture_mode,
                 Jsonb(intent.metadata), intent.webhook_url)).fetchone()
            conn.execute("UPDATE payment_intents SET transaction_id = %s WHERE intent_id = %s",
                         (transaction_id, intent.intent_id))
            _audit_entity(conn, "SYSTEM", "client", "transaction", transaction_id, "transaction.send", None, "PENDING")
            return transaction_id

    def finish_online_transaction(self, intent: Intent, transaction_id: UUID, result: CardResult | None,
                                  status: str, error: dict | None) -> None:
        with self.pool.connection() as conn, conn.transaction():
            (previous,) = conn.execute("SELECT status FROM transactions WHERE transaction_id = %s FOR UPDATE",
                                       (transaction_id,)).fetchone()
            verdict = transition(previous, status)  # same rule as finish(): never overwrite a final answer
            if verdict != "apply":
                if verdict == "reject":
                    _audit_entity(conn, "SYSTEM", None, "transaction", transaction_id, "transaction.discrepancy",
                                  previous, previous, f"illegal transition {previous} -> {status}",
                                  {"current": previous, "attempted": status})
                return
            row = conn.execute(
                "UPDATE transactions SET status = %s, error = %s, method_reference = %s, auth_code = %s,"
                " card_bin = %s, card_last4 = %s, reversal = %s, updated_at = now()"
                " WHERE transaction_id = %s AND status = %s"
                " RETURNING transaction_id, idempotency_key, status, amount, currency, payment_method,"
                " method_reference, auth_code, error, metadata, created_at, updated_at",
                (status, Jsonb(error) if error else None, result and result.method_reference,
                 result and result.auth_code, result and result.card_bin, result and result.card_last4,
                 result and result.reversal, transaction_id, previous)).fetchone()
            settle_intent(conn, intent.intent_id, status, error, result and result.card_bin,
                          result and result.card_last4)
            if status in SALE_STATUSES:  # the ledger, in this same transaction, as finish() does for terminals
                amount, currency, method = row[3], row[4], row[5]
                post_sale_once(conn, transaction_id, intent.merchant_id, currency, method, amount,
                               self.fees.fee(intent.merchant_id, method, amount))
            _audit_entity(conn, "SYSTEM", None, "transaction", transaction_id, "transaction.finish", previous, status,
                          error["error_code"] if error else None)
            if status != "PENDING":
                payload = _response(row)
                payload["payment_intent_id"] = public_intent_id(intent.intent_id)
                enqueue(conn, intent.merchant_id, intent.webhook_url, payload)

    def cancel(self, intent_id: UUID, merchant_id: UUID) -> Intent | None:
        with self.pool.connection() as conn, conn.transaction():
            cur = conn.cursor(row_factory=dict_row)
            row = cur.execute(
                f"UPDATE payment_intents SET status = 'CANCELED', pending_card = NULL, updated_at = now()"
                f" WHERE intent_id = %s AND merchant_id = %s AND status IN ('REQUIRES_PAYMENT_METHOD', 'REQUIRES_ACTION')"
                f" RETURNING {_COLUMNS}", (intent_id, merchant_id)).fetchone()
            if row:
                _audit_entity(conn, "MERCHANT", str(merchant_id), "payment_intent", intent_id,
                              "payment_intent.cancel", None, "CANCELED")
            return _intent(row)

    def next_for_terminal(self, terminal_id: UUID) -> Intent | None:
        with self.pool.connection() as conn:
            cur = conn.cursor(row_factory=dict_row)
            return _intent(cur.execute(
                f"SELECT {_COLUMNS} FROM payment_intents WHERE terminal_id = %s"
                f" AND status = 'REQUIRES_PAYMENT_METHOD' AND expires_at > now() ORDER BY created_at LIMIT 1",
                (terminal_id,)).fetchone())

    def terminal_belongs(self, terminal_id: UUID, merchant_id: UUID) -> str | None:
        """The terminal's status if it belongs to this merchant, else None."""
        with self.pool.connection() as conn:
            row = conn.execute("SELECT status FROM terminals WHERE terminal_id = %s AND merchant_id = %s",
                               (terminal_id, merchant_id)).fetchone()
            return row[0] if row else None

