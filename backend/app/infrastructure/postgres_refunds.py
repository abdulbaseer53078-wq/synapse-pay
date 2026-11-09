"""Refunds in Postgres (PR 4): reserve before the network, complete with the status, audit and ledger together.

Every step locks the payment row first, so concurrent refunds of one payment run one after the other: two can't
both pass the "no more than what is left" check, and a double-clicked refund finds the first one's row.
"""
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from psycopg import Connection
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.fees import ConfigFeePolicy, FeePolicy
from app.application.registration import Conflict, InvalidInput, NotFound
from app.domain.ledger import FEE_REVENUE, SALE_STATUSES, refund_postings
from app.domain.state_machine import transition
from app.infrastructure.postgres_ledger import fee_history, post_sale_once, record_entry
from app.infrastructure.postgres_transactions import _audit_entity, _response
from app.infrastructure.webhook_outbox import enqueue

_COLUMNS = ("r.refund_id, r.transaction_id, r.amount, r.reason, r.status, r.network_reference, r.error,"
            " r.created_at, r.updated_at, t.payment_method, t.method_reference")


@dataclass(frozen=True)
class Refund:
    refund_id: UUID
    transaction_id: UUID
    amount: int
    reason: str | None
    status: str
    network_reference: str | None
    error: dict | None
    created_at: datetime
    updated_at: datetime
    payment_method: str  # what the adapter needs to send it
    payment_reference: str | None  # the original payment's network reference (UPI: the PSP's transaction id)


def request_hash(transaction_id: UUID, amount: int, reason: str | None) -> bytes:
    return hashlib.sha256(json.dumps([str(transaction_id), amount, reason]).encode()).digest()


def _select(conn: Connection, where: str, params: tuple) -> Refund | None:
    row = conn.execute(f"SELECT {_COLUMNS} FROM refunds r JOIN transactions t USING (transaction_id) WHERE {where}",
                       params).fetchone()
    return Refund(*row) if row else None


class PostgresRefunds:
    def __init__(self, pool: ConnectionPool, fees: FeePolicy | None = None):
        self.pool = pool
        self.fees = fees or ConfigFeePolicy({})

    def reserve(self, merchant_id: UUID, transaction_id: UUID, amount: int, reason: str | None,
                idempotency_key: UUID) -> tuple[Refund, bool]:
        """(refund, created). An existing refund under this key comes back with created=False; the same key for a
        different refund is a Conflict; a refund that would exceed what is left is InvalidInput."""
        digest = request_hash(transaction_id, amount, reason)
        with self.pool.connection() as conn, conn.transaction():
            payment = conn.execute(
                "SELECT status, amount, terminal_id FROM transactions WHERE transaction_id = %s AND merchant_id = %s"
                " FOR UPDATE", (transaction_id, merchant_id)).fetchone()
            existing = conn.execute("SELECT request_hash, refund_id FROM refunds WHERE merchant_id = %s"
                                    " AND idempotency_key = %s", (merchant_id, idempotency_key)).fetchone()
            if existing is not None:
                if bytes(existing[0]) != digest:
                    raise Conflict("idempotency_key was already used for a different refund",
                                   code="IDEMPOTENCY_KEY_CONFLICT")
                return _select(conn, "r.refund_id = %s", (existing[1],)), False
            if payment is None:
                raise NotFound("transaction not found", code="TRANSACTION_NOT_FOUND")
            status, total, terminal_id = payment
            if transition(status, "PARTIALLY_REFUNDED") == "reject":
                raise Conflict(f"a {status} transaction can't be refunded", code="TRANSACTION_NOT_REFUNDABLE")
            if fee_history(conn, transaction_id) is None:
                raise Conflict("this transaction has no ledger sale to reverse", code="TRANSACTION_NOT_REFUNDABLE")
            (claimed, disputed, open_disputes) = conn.execute(
                "SELECT (SELECT coalesce(sum(amount), 0) FROM refunds WHERE transaction_id = %s"
                " AND status IN ('PENDING', 'COMPLETED')),"
                " (SELECT coalesce(sum(amount), 0) FROM chargebacks WHERE transaction_id = %s AND status <> 'WON'),"
                " (SELECT count(*) FROM chargebacks WHERE transaction_id = %s AND status IN ('PENDING', 'UNDER_REVIEW'))",
                (transaction_id, transaction_id, transaction_id)).fetchone()
            if open_disputes:  # a refund now would pay the customer twice if the chargeback is lost
                raise Conflict("the transaction has an open chargeback; it can't be refunded until it is resolved",
                               code="TRANSACTION_IN_DISPUTE")
            claimed += disputed  # money a chargeback took back can't be refunded as well
            if claimed + amount > total:
                raise InvalidInput(f"refund exceeds what is left of the payment ({total - claimed} remaining)",
                                   code="REFUND_EXCEEDS_AMOUNT")
            (refund_id,) = conn.execute(
                "INSERT INTO refunds (transaction_id, merchant_id, amount, reason, idempotency_key, request_hash)"
                " VALUES (%s, %s, %s, %s, %s, %s) RETURNING refund_id",
                (transaction_id, merchant_id, amount, reason, idempotency_key, digest)).fetchone()
            _audit_entity(conn, "MERCHANT", str(merchant_id), "refund", refund_id, "refund.reserve", None,
                          "PENDING", payload={"transaction_id": str(transaction_id), "amount": amount})
            return _select(conn, "r.refund_id = %s", (refund_id,)), True

    def complete(self, refund_id: UUID, network_reference: str | None) -> Refund:
        """The network refunded it: refund, payment status, audit, ledger and merchant webhook, all or nothing."""
        with self.pool.connection() as conn, conn.transaction():
            (transaction_id,) = conn.execute("SELECT transaction_id FROM refunds WHERE refund_id = %s",
                                             (refund_id,)).fetchone()
            payment = conn.execute(
                "SELECT status, amount, refunded_amount, merchant_id, currency, webhook_url FROM transactions"
                " WHERE transaction_id = %s FOR UPDATE", (transaction_id,)).fetchone()
            refund = conn.execute("SELECT status, amount FROM refunds WHERE refund_id = %s FOR UPDATE",
                                  (refund_id,)).fetchone()
            if refund[0] != "PENDING":  # already settled by another worker: the same answer twice is a no-op
                return _select(conn, "r.refund_id = %s", (refund_id,))
            status, total, refunded, merchant_id, currency, webhook_url = payment
            amount = refund[1]
            new_status = "REFUNDED" if refunded + amount == total else "PARTIALLY_REFUNDED"
            if transition(status, new_status) == "reject":
                raise Conflict(f"can't move a {status} transaction to {new_status}")
            sale_fee, fee_reversed = fee_history(conn, transaction_id)
            postings = refund_postings(amount, total, sale_fee, fee_reversed, refunded)
            fee_back = sum(p.debit for p in postings if p.account == FEE_REVENUE)
            record_entry(conn, transaction_id, merchant_id, currency, "REFUND", f"refund {refund_id}", postings)
            conn.execute("UPDATE refunds SET status = 'COMPLETED', network_reference = %s, fee_reversed = %s,"
                         " updated_at = now() WHERE refund_id = %s", (network_reference, fee_back, refund_id))
            # The CHECK in migration 017 refuses refunded_amount > amount, so even a bug can't over-refund here.
            row = conn.execute(
                "UPDATE transactions SET refunded_amount = refunded_amount + %s, status = %s, updated_at = now()"
                " WHERE transaction_id = %s RETURNING transaction_id, idempotency_key, status, amount, currency,"
                " payment_method, method_reference, auth_code, error, metadata, created_at, updated_at",
                (amount, new_status, transaction_id)).fetchone()
            _audit_entity(conn, "SYSTEM", None, "refund", refund_id, "refund.complete", "PENDING", "COMPLETED")
            _audit_entity(conn, "SYSTEM", None, "transaction", transaction_id, "transaction.refund", status,
                          new_status, payload={"refund_id": str(refund_id), "amount": amount})
            enqueue(conn, merchant_id, webhook_url, _response(row))
            return _select(conn, "r.refund_id = %s", (refund_id,))

    def fail(self, refund_id: UUID, error: dict) -> Refund:
        """The network refused it (or the rail can't refund): releases the reserved amount. Nothing was refunded."""
        with self.pool.connection() as conn, conn.transaction():
            updated = conn.execute("UPDATE refunds SET status = 'FAILED', error = %s, updated_at = now()"
                                   " WHERE refund_id = %s AND status = 'PENDING' RETURNING 1",
                                   (Jsonb(error), refund_id)).fetchone()
            if updated:
                _audit_entity(conn, "SYSTEM", None, "refund", refund_id, "refund.fail", "PENDING", "FAILED",
                              reason=error.get("error_code"))
            return _select(conn, "r.refund_id = %s", (refund_id,))

    def stale_pending(self, older_than_seconds: int, limit: int = 50) -> list[Refund]:
        """PENDING refunds nobody finished: the process died, or the network's answer was lost."""
        with self.pool.connection() as conn:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM refunds r JOIN transactions t USING (transaction_id) WHERE r.status = 'PENDING'"
                " AND r.updated_at < now() - make_interval(secs => %s) ORDER BY r.updated_at LIMIT %s",
                (older_than_seconds, limit)).fetchall()
        return [Refund(*r) for r in rows]

    def get(self, merchant_id: UUID, refund_id: UUID) -> Refund | None:
        with self.pool.connection() as conn:
            return _select(conn, "r.refund_id = %s AND r.merchant_id = %s", (refund_id, merchant_id))

    def payment(self, merchant_id: UUID, transaction_id: UUID) -> tuple | None:
        """(status, amount, payment_method, method_reference, terminal_id) of the merchant's own payment only:
        another merchant's id answers like an unknown one."""
        with self.pool.connection() as conn:
            return conn.execute("SELECT status, amount, payment_method, method_reference, terminal_id FROM transactions"
                                " WHERE transaction_id = %s AND merchant_id = %s", (transaction_id, merchant_id)).fetchone()

    def settle_hold(self, merchant_id: UUID, transaction_id: UUID, target: str, network_reference: str | None) -> dict:
        """Capture (AUTHORIZED -> CAPTURED, which posts the SALE) or void (AUTHORIZED -> VOIDED, which posts nothing).

        Only the status changes: unlike finish(), the card details and network references the payment already
        has are kept. Raises Conflict if the payment moved on since the caller looked."""
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute("SELECT status, terminal_id FROM transactions WHERE transaction_id = %s"
                               " AND merchant_id = %s FOR UPDATE", (transaction_id, merchant_id)).fetchone()
            if row is None:
                raise NotFound("transaction not found", code="TRANSACTION_NOT_FOUND")
            previous, terminal_id = row
            if transition(previous, target) == "reject":
                raise Conflict(f"a {previous} transaction can't become {target}", code={"CAPTURED": "TRANSACTION_NOT_CAPTURABLE", "VOIDED": "TRANSACTION_NOT_VOIDABLE"}[target])
            updated = conn.execute(
                "UPDATE transactions SET status = %s, method_reference = coalesce(%s, method_reference),"
                " updated_at = now() WHERE transaction_id = %s RETURNING transaction_id, idempotency_key, status,"
                " amount, currency, payment_method, method_reference, auth_code, error, metadata, created_at,"
                " updated_at, webhook_url", (target, network_reference, transaction_id)).fetchone()
            amount, currency, method, webhook_url = updated[3], updated[4], updated[5], updated[12]
            if target in SALE_STATUSES:
                post_sale_once(conn, transaction_id, merchant_id, currency, method, amount,
                               self.fees.fee(merchant_id, method, amount))
            _audit_entity(conn, "MERCHANT", str(merchant_id), "transaction", transaction_id,
                          "transaction." + target.lower(), previous, target)
            response = _response(updated[:12])
            if previous != target:
                enqueue(conn, merchant_id, webhook_url, response)
            return response
