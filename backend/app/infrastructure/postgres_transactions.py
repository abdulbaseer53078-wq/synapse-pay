from datetime import datetime
from uuid import UUID

from psycopg import Connection
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.methods import MethodResult
from app.application.transactions import Claim, NewTransaction, public_id
from app.domain.terminal import Actor
from app.infrastructure.webhook_outbox import enqueue
from app.infrastructure.postgres_terminals import _OUTBOX_LOCK

# Statuses that count against a terminal's daily limit: money moved, or may have.
_SPENDING = ("PENDING", "AUTHORIZED", "CAPTURED", "SETTLED")


def _audit_entity(conn: Connection, actor: str, actor_id: str | None, entity_type: str, entity_id: UUID,
                  action: str, from_status: str | None, to_status: str, reason: str | None = None,
                  payload: dict | None = None) -> None:
    conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))
    conn.execute(
        "INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action, from_status, to_status,"
        " reason, payload) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (actor, actor_id, entity_type, entity_id, action, from_status, to_status, reason,
         Jsonb(payload or {})))


def _audit(conn: Connection, terminal_id: UUID, transaction_id: UUID, action: str, from_status: str | None,
           to_status: str, reason: str | None = None, payload: dict | None = None) -> None:
    _audit_entity(conn, Actor.TERMINAL, str(terminal_id), "transaction", transaction_id, action, from_status,
                  to_status, reason, payload)


def _response(row) -> dict:
    (transaction_id, idempotency_key, status, amount, currency, method, method_reference, auth_code, error,
     metadata, created_at, updated_at) = row
    body = {
        "transaction_id": public_id(transaction_id), "idempotency_key": str(idempotency_key), "status": status,
        "amount": amount, "currency": currency, "payment_method": method,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "updated_at": updated_at.isoformat().replace("+00:00", "Z"),
    }
    for key, value in (("method_reference", method_reference), ("auth_code", auth_code), ("error", error)):
        if value is not None:
            body[key] = value
    if metadata:
        body["metadata"] = metadata
    return body


def settle_intent(conn: Connection, intent_id: UUID, transaction_status: str, error: dict | None,
                  card_bin: str | None, card_last4: str | None) -> None:
    """Moves an intent on after one of its transactions ends: succeeded, still unknown, or back to the customer
    to try again (a declined card isn't the end of a checkout)."""
    if transaction_status in ("CAPTURED", "AUTHORIZED"):
        status, last_error = "SUCCEEDED", None
    elif transaction_status == "PENDING":
        status, last_error = "PROCESSING", None
    else:
        status, last_error = "REQUIRES_PAYMENT_METHOD", error
    conn.execute(
        "UPDATE payment_intents SET status = %s, last_payment_error = %s, card_bin = coalesce(%s, card_bin),"
        " card_last4 = coalesce(%s, card_last4), pending_card = NULL, updated_at = now() WHERE intent_id = %s",
        (status, Jsonb(last_error) if last_error else None, card_bin, card_last4, intent_id))


class _IntentRefused(Exception):
    def __init__(self, why: str):
        self.why = why


class PostgresTransactionRepository:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def terminal_merchant(self, terminal_id: UUID) -> UUID | None:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT merchant_id FROM terminals WHERE terminal_id = %s", (terminal_id,)).fetchone()
            return row[0] if row else None

    def spent_today(self, terminal_id: UUID, since: datetime) -> int:
        with self.pool.connection() as conn:
            return conn.execute(
                "SELECT coalesce(sum(amount), 0) FROM transactions"
                " WHERE terminal_id = %s AND created_at >= %s AND status = ANY(%s)",
                (terminal_id, since, list(_SPENDING))).fetchone()[0]

    def claim(self, txn: NewTransaction) -> Claim:
        try:
            return self._claim(txn)
        except _IntentRefused as refused:
            return Claim(intent_error=refused.why)

    def _claim(self, txn: NewTransaction) -> Claim:
        with self.pool.connection() as conn, conn.transaction():
            inserted = conn.execute(
                "INSERT INTO idempotency_keys (merchant_id, idempotency_key, request_hash, state)"
                " VALUES (%s, %s, %s, 'IN_FLIGHT') ON CONFLICT DO NOTHING RETURNING 1",
                (txn.merchant_id, txn.idempotency_key, txn.request_hash)).fetchone()
            if inserted is None:
                request_hash, state, response = conn.execute(
                    "SELECT request_hash, state, response FROM idempotency_keys"
                    " WHERE merchant_id = %s AND idempotency_key = %s",
                    (txn.merchant_id, txn.idempotency_key)).fetchone()
                if bytes(request_hash) != txn.request_hash:
                    return Claim(conflict=True)
                if state == "IN_FLIGHT":
                    return Claim(in_flight=True)
                return Claim(replay=response)
            if txn.payment_intent_id is not None:
                why = self._take_intent(conn, txn)
                if why is not None:
                    # Rolls back the whole claim, releasing the idempotency key: fix the request and resend.
                    raise _IntentRefused(why)
            (transaction_id,) = conn.execute(
                "INSERT INTO transactions (idempotency_key, merchant_id, terminal_id, amount, currency, payment_method,"
                " capture_mode, status, card_network, metadata, webhook_url, payment_intent_id, qr_encoded_rail)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, 'INITIATED', %s, %s, %s, %s, %s) RETURNING transaction_id",
                (txn.idempotency_key, txn.merchant_id, txn.terminal_id, txn.amount, txn.currency, txn.payment_method,
                 txn.capture_mode, txn.card_network, Jsonb(txn.metadata), txn.webhook_url,
                 txn.payment_intent_id, txn.qr_encoded_rail)).fetchone()
            if txn.payment_intent_id is not None:
                conn.execute("UPDATE payment_intents SET transaction_id = %s WHERE intent_id = %s",
                             (transaction_id, txn.payment_intent_id))
            conn.execute("UPDATE idempotency_keys SET transaction_id = %s WHERE merchant_id = %s AND idempotency_key = %s",
                         (transaction_id, txn.merchant_id, txn.idempotency_key))
            _audit(conn, txn.terminal_id, transaction_id, "transaction.create", None, "INITIATED",
                   payload={"qr_encoded_rail": txn.qr_encoded_rail} if txn.qr_encoded_rail else None)
            return Claim(transaction_id=transaction_id)

    @staticmethod
    def _take_intent(conn: Connection, txn: NewTransaction) -> str | None:
        """Locks the terminal checkout this payment completes and moves it to PROCESSING. Returns why not, if not."""
        row = conn.execute("SELECT terminal_id, merchant_id, amount, currency, status, expires_at > now()"
                           " FROM payment_intents WHERE intent_id = %s FOR UPDATE",
                           (txn.payment_intent_id,)).fetchone()
        if row is None or row[0] != txn.terminal_id or row[1] != txn.merchant_id:
            return "no such payment intent for this terminal"
        if (row[2], row[3]) != (txn.amount, txn.currency):
            return "amount and currency must match the payment intent"
        if row[4] != "REQUIRES_PAYMENT_METHOD" or not row[5]:
            return f"payment intent is {row[4] if row[5] else 'expired'}, not waiting for payment"
        conn.execute("UPDATE payment_intents SET status = 'PROCESSING', last_payment_error = NULL, updated_at = now()"
                     " WHERE intent_id = %s", (txn.payment_intent_id,))
        return None

    def by_method_reference(self, reference: str, method: str | None = None) -> tuple[UUID, UUID, str] | None:
        """(transaction_id, terminal_id, status) for a payment a network knows by its own id.

        `method` is optional on purpose: a QR payment is stored as QR but carries a UPI PSP reference, so
        filtering by method would make its own webhook unfindable. The network reference is unique.
        """
        if not reference:
            return None
        with self.pool.connection() as conn:
            return conn.execute(
                "SELECT transaction_id, terminal_id, status FROM transactions"
                " WHERE method_reference = %s AND (%s::text IS NULL OR payment_method = %s)",
                (reference, method, method)).fetchone()

    def stale_pending(self, method: str, older_than_seconds: int,
                      limit: int = 50) -> list[tuple[UUID, UUID, str | None]]:
        """(transaction_id, terminal_id, method_reference) for payments a rail left PENDING too long.

        The polling fallback's query: a UPI collect that never got its webhook. Indexed by
        transactions_pending_idx (status) plus the method filter.
        """
        with self.pool.connection() as conn:
            return conn.execute(
                "SELECT transaction_id, terminal_id, method_reference FROM transactions"
                " WHERE payment_method = %s AND status = 'PENDING'"
                " AND updated_at < now() - make_interval(secs => %s)"
                " ORDER BY updated_at LIMIT %s", (method, older_than_seconds, limit)).fetchall()

    def mark_pending(self, transaction_id: UUID, terminal_id: UUID) -> None:
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("UPDATE transactions SET status = 'PENDING', updated_at = now() WHERE transaction_id = %s",
                         (transaction_id,))
            _audit(conn, terminal_id, transaction_id, "transaction.send", "INITIATED", "PENDING")

    def finish(self, transaction_id: UUID, terminal_id: UUID, result: MethodResult | None, status: str,
               error: dict | None, store_response: bool, attempts: list[dict] | None = None) -> dict:
        with self.pool.connection() as conn, conn.transaction():
            (previous,) = conn.execute("SELECT status FROM transactions WHERE transaction_id = %s FOR UPDATE",
                                       (transaction_id,)).fetchone()
            row = conn.execute(
                "UPDATE transactions SET status = %s, error = %s, method_reference = %s, auth_code = %s,"
                " card_bin = %s, card_last4 = %s, reversal = %s, updated_at = now() WHERE transaction_id = %s"
                " RETURNING transaction_id, idempotency_key, status, amount, currency, payment_method,"
                " method_reference, auth_code, error, metadata, created_at, updated_at, merchant_id,"
                " payment_intent_id, webhook_url",
                (status, Jsonb(error) if error else None,
                 result.method_reference if result else None, result.auth_code if result else None,
                 result.bin if result else None, result.last4 if result else None,
                 result.reversal if result else None, transaction_id)).fetchone()
            response = _response(row[:12])
            if result and result.next_action:
                # The SDK opens this URL; it is part of the response, and therefore of the stored idempotent
                # replay, so a retry returns the same redirect instead of starting a second payment.
                response["next_action"] = result.next_action
            merchant_id, idempotency_key, intent_id, webhook_url = row[12], row[1], row[13], row[14]
            if intent_id is not None:
                response["payment_intent_id"] = f"pi_{intent_id.hex}"
                settle_intent(conn, intent_id, status, error, result.bin if result else None,
                              result.last4 if result else None)
            if status != "PENDING":
                enqueue(conn, merchant_id, webhook_url, response)
            if store_response:
                conn.execute("UPDATE idempotency_keys SET state = 'DONE', response = %s"
                             " WHERE merchant_id = %s AND idempotency_key = %s",
                             (Jsonb(response), merchant_id, idempotency_key))
            else:
                # Retryable: free the key so the client's retry is processed, not replayed.
                conn.execute("DELETE FROM idempotency_keys WHERE merchant_id = %s AND idempotency_key = %s",
                             (merchant_id, idempotency_key))
            reason = error["error_code"] if error else (f"reversal {result.reversal}" if result and
                                                         result.reversal != "NOT_NEEDED" else None)
            # The cascade's attempt trail is written in this same transaction as the final state, so a rollback
            # takes both: the log can never claim a host was tried for a transaction that never happened.
            _audit(conn, terminal_id, transaction_id, "transaction.finish", previous, status, reason,
                   payload={"attempts": attempts} if attempts else None)
            return response

