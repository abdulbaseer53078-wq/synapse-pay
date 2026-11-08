from datetime import datetime
from uuid import UUID

from psycopg import Connection
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.fees import ConfigFeePolicy, FeePolicy
from app.application.methods import MethodResult
from app.application.transactions import Claim, NewTransaction, TransactionSuperseded, public_id
from app.domain.ledger import SALE_STATUSES
from app.domain.state_machine import transition
from app.domain.terminal import Actor
from app.infrastructure.postgres_ledger import post_sale_once
from app.infrastructure.webhook_outbox import enqueue
from app.infrastructure.postgres_terminals import _OUTBOX_LOCK

# Statuses that count against a terminal's daily limit: money moved, or may have.
_SPENDING = ("PENDING", "AUTHORIZED", "CAPTURED", "SETTLED")
# The response columns (_response takes the first 12), then what finish() needs besides.
_RETURNING = ("transaction_id, idempotency_key, status, amount, currency, payment_method, method_reference,"
              " auth_code, error, metadata, created_at, updated_at, merchant_id, payment_intent_id, webhook_url")


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
    def __init__(self, pool: ConnectionPool, fees: FeePolicy | None = None):
        self.pool = pool
        self.fees = fees or ConfigFeePolicy({})  # no rates configured: no fee

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
        """INITIATED → PENDING, just before the network is asked. Raises TransactionSuperseded if the payment is no
        longer INITIATED (the stuck-key sweep failed it while this request stalled): then it must not be sent."""
        with self.pool.connection() as conn, conn.transaction():
            if conn.execute("UPDATE transactions SET status = 'PENDING', updated_at = now()"
                            " WHERE transaction_id = %s AND status = 'INITIATED' RETURNING 1",
                            (transaction_id,)).fetchone() is None:
                raise TransactionSuperseded(transaction_id)
            _audit(conn, terminal_id, transaction_id, "transaction.send", "INITIATED", "PENDING")

    def current(self, transaction_id: UUID) -> dict:
        """The stored truth, as a TransactionResponse."""
        with self.pool.connection() as conn:
            return _response(conn.execute(f"SELECT {_RETURNING} FROM transactions WHERE transaction_id = %s",
                                          (transaction_id,)).fetchone()[:12])

    def stuck_in_flight(self, older_than_seconds: int, limit: int = 50) -> list[tuple[UUID, UUID]]:
        """(transaction_id, terminal_id) of payments whose request died before reaching the network: the key is
        still IN_FLIGHT and the transaction still INITIATED. Never PENDING ones: those may have been sent."""
        with self.pool.connection() as conn:
            return conn.execute(
                "SELECT t.transaction_id, t.terminal_id FROM idempotency_keys k"
                " JOIN transactions t ON t.transaction_id = k.transaction_id"
                " WHERE k.state = 'IN_FLIGHT' AND t.status = 'INITIATED'"
                " AND k.created_at < now() - make_interval(secs => %s)"
                " ORDER BY k.created_at LIMIT %s", (older_than_seconds, limit)).fetchall()

    def finish(self, transaction_id: UUID, terminal_id: UUID, result: MethodResult | None, status: str,
               error: dict | None, store_response: bool, attempts: list[dict] | None = None,
               trace_id: str | None = None, expected: str | None = None) -> dict:
        """Moves the payment to `status` if the state machine allows it; otherwise changes nothing and returns
        the stored truth. A late or wrong answer (FAILED after SETTLED) is audited as a discrepancy, never
        written. With `expected`, it applies only from that status (the sweeps: the payment may have moved on)."""
        with self.pool.connection() as conn, conn.transaction():
            current = conn.execute(f"SELECT {_RETURNING} FROM transactions WHERE transaction_id = %s FOR UPDATE",
                                   (transaction_id,)).fetchone()
            previous = current[2]
            verdict = "stale" if expected is not None and previous != expected else transition(previous, status)
            if verdict != "apply":
                if verdict == "reject":
                    _audit(conn, terminal_id, transaction_id, "transaction.discrepancy", previous, previous,
                           f"illegal transition {previous} -> {status}",
                           payload={"current": previous, "attempted": status,
                                    **({"error_code": error["error_code"]} if error else {})})
                return _response(current[:12])
            # The row is locked, so the status can't move under us; the guard in WHERE says so anyway.
            row = conn.execute(
                # A later answer adds what it knows and never erases what an earlier one stored (BIN, references).
                "UPDATE transactions SET status = %s, error = %s, method_reference = coalesce(%s, method_reference),"
                " auth_code = coalesce(%s, auth_code), card_bin = coalesce(%s, card_bin),"
                " card_last4 = coalesce(%s, card_last4), reversal = coalesce(%s, reversal), updated_at = now()"
                f" WHERE transaction_id = %s AND status = %s RETURNING {_RETURNING}",
                (status, Jsonb(error) if error else None,
                 result.method_reference if result else None, result.auth_code if result else None,
                 result.bin if result else None, result.last4 if result else None,
                 result.reversal if result else None, transaction_id, previous)).fetchone()
            response = _response(row[:12])
            if result and result.next_action:
                # The SDK opens this URL; it is part of the response, and therefore of the stored idempotent
                # replay, so a retry returns the same redirect instead of starting a second payment.
                response["next_action"] = result.next_action
            merchant_id, idempotency_key, intent_id, webhook_url = row[12], row[1], row[13], row[14]
            # PR 1: the money, in this same transaction: if anything below fails, the status change rolls back too.
            # One SALE per payment, on its first move into a status where money really moved (CAPTURED -> SETTLED
            # later must not count it twice; the unique index in migration 016 enforces that as well).
            if status in SALE_STATUSES:
                amount, currency, method = row[3], row[4], row[5]
                post_sale_once(conn, transaction_id, merchant_id, currency, method, amount,
                               self.fees.fee(merchant_id, method, amount))
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
                   payload={k: v for k, v in (("attempts", attempts), ("trace_id", trace_id)) if v} or None)
            return response

