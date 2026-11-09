"""Chargebacks in Postgres (PR 8). Opening, resolving and evidence each happen in one database transaction with the
ledger entry, the audit row and the merchant's webhook. Notices are deduplicated twice over: by the acquirer's event id
(a re-sent delivery) and by its case id (the same dispute described again)."""
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.registration import Conflict, NotFound
from app.domain.chargebacks import OPEN_STATUSES, cash_account, opened_postings, resolution_postings
from app.infrastructure.postgres_ledger import record_entry
from app.infrastructure.postgres_transactions import _audit_entity
from app.infrastructure.webhook_outbox import enqueue

_COLUMNS = ("chargeback_id, transaction_id, merchant_id, acquirer_id, acquirer_case_id, network_reference, amount,"
            " currency, reason_code, status, evidence_deadline, evidence, evidence_submitted_at, resolved_at, created_at,"
            " updated_at, cash_account")


@dataclass(frozen=True)
class Chargeback:
    chargeback_id: UUID
    transaction_id: UUID | None
    merchant_id: UUID | None
    acquirer_id: str
    acquirer_case_id: str
    network_reference: str
    amount: int
    currency: str
    reason_code: str
    status: str
    evidence_deadline: datetime
    evidence: dict | None
    evidence_submitted_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    cash_account: str | None  # where the money left from at open; None for a payment we have no record of


def view(cb: Chargeback) -> dict:
    """What the merchant sees, in its API and its webhooks."""
    from app.application.transactions import public_id
    body = {"chargeback_id": f"cb_{cb.chargeback_id.hex}", "amount": cb.amount, "currency": cb.currency,
            "reason_code": cb.reason_code, "status": cb.status,
            "evidence_deadline": cb.evidence_deadline.isoformat().replace("+00:00", "Z"),
            "created_at": cb.created_at.isoformat().replace("+00:00", "Z")}
    if cb.transaction_id:
        body["transaction_id"] = public_id(cb.transaction_id)
    if cb.evidence:
        body["evidence"] = cb.evidence
    if cb.resolved_at:
        body["resolved_at"] = cb.resolved_at.isoformat().replace("+00:00", "Z")
    return body


def _row(conn, where: str, params: tuple, lock: bool = False) -> Chargeback | None:
    row = conn.execute(f"SELECT {_COLUMNS} FROM chargebacks WHERE {where}{' FOR UPDATE' if lock else ''}",
                       params).fetchone()
    return Chargeback(*row) if row else None


class PostgresChargebacks:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def open(self, event_id: str, acquirer_id: str, case_id: str, network_reference: str, amount: int,
             currency: str, reason_code: str, deadline: datetime) -> tuple[Chargeback, list[str], bool]:
        """(chargeback, problems for an operator, new). A notice delivered again changes nothing."""
        with self.pool.connection() as conn, conn.transaction():
            fresh_event = conn.execute("INSERT INTO chargeback_events (acquirer_id, event_id) VALUES (%s, %s)"
                                       " ON CONFLICT DO NOTHING RETURNING 1", (acquirer_id, event_id)).fetchone()
            existing = _row(conn, "acquirer_id = %s AND acquirer_case_id = %s", (acquirer_id, case_id))
            if existing or not fresh_event:
                if existing is None:  # the event was seen but its case wasn't recorded: can't happen in one transaction
                    raise Conflict("chargeback event already processed")
                return existing, [], False
            payment = conn.execute(
                "SELECT transaction_id, merchant_id, amount, currency, webhook_url FROM transactions"
                " WHERE method_reference = %s AND payment_method = 'CARD' FOR UPDATE", (network_reference,)).fetchone()
            transaction_id, merchant_id = (payment[0], payment[1]) if payment else (None, None)
            (chargeback_id,) = conn.execute(
                "INSERT INTO chargebacks (transaction_id, merchant_id, acquirer_id, acquirer_case_id, network_reference,"
                " amount, currency, reason_code, evidence_deadline) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " RETURNING chargeback_id", (transaction_id, merchant_id, acquirer_id, case_id, network_reference,
                                             amount, currency, reason_code, deadline)).fetchone()
            problems = []
            if payment is None:
                problems.append(f"chargeback {case_id} from {acquirer_id} names {network_reference}, which we have no "
                                f"record of")
            else:
                total, payment_currency, webhook_url = payment[2], payment[3], payment[4]
                if payment_currency != currency:
                    problems.append(f"chargeback {case_id} is in {currency}, the payment in {payment_currency}")
                (refunded, disputed) = conn.execute(
                    "SELECT (SELECT coalesce(sum(amount), 0) FROM refunds WHERE transaction_id = %s"
                    " AND status IN ('PENDING', 'COMPLETED')),"
                    " (SELECT coalesce(sum(amount), 0) FROM chargebacks WHERE transaction_id = %s AND status <> 'WON')",
                    (transaction_id, transaction_id)).fetchone()
                if refunded + disputed > total:  # recorded anyway: the network takes it whether or not we agree
                    problems.append(f"chargeback {case_id} plus refunds ({refunded}) exceed the payment ({total}):"
                                    f" the customer was refunded too")
                settled = conn.execute("SELECT 1 FROM journal_entries WHERE transaction_id = %s"
                                       " AND entry_type = 'SETTLEMENT'", (transaction_id,)).fetchone() is not None
                account = cash_account(settled)
                record_entry(conn, transaction_id, merchant_id, currency, "CHARGEBACK",
                             f"chargeback {case_id} ({reason_code})", opened_postings(amount, account))
                conn.execute("UPDATE chargebacks SET cash_account = %s WHERE chargeback_id = %s", (account, chargeback_id))
                _audit_entity(conn, "SYSTEM", None, "chargeback", chargeback_id, "chargeback.open", None, "PENDING",
                              reason=reason_code, payload={"transaction_id": str(transaction_id), "amount": amount,
                                                           "acquirer_case_id": case_id})
                cb = _row(conn, "chargeback_id = %s", (chargeback_id,))
                enqueue(conn, merchant_id, webhook_url, {"event": "chargeback.opened", **view(cb)})
                return cb, problems, True
            _audit_entity(conn, "SYSTEM", None, "chargeback", chargeback_id, "chargeback.open", None, "PENDING",
                          reason="UNKNOWN_PAYMENT", payload={"network_reference": network_reference, "amount": amount})
            return _row(conn, "chargeback_id = %s", (chargeback_id,)), problems, True

    def resolve(self, event_id: str, acquirer_id: str, case_id: str, outcome: str) -> tuple[Chargeback, list[str]]:
        with self.pool.connection() as conn, conn.transaction():
            fresh_event = conn.execute("INSERT INTO chargeback_events (acquirer_id, event_id) VALUES (%s, %s)"
                                       " ON CONFLICT DO NOTHING RETURNING 1", (acquirer_id, event_id)).fetchone()
            cb = _row(conn, "acquirer_id = %s AND acquirer_case_id = %s", (acquirer_id, case_id), lock=True)
            if cb is None:
                raise NotFound(f"no chargeback {case_id} from {acquirer_id}", code="CHARGEBACK_NOT_FOUND")
            if not fresh_event or cb.status not in OPEN_STATUSES:
                problems = [] if cb.status in (outcome, *OPEN_STATUSES) else [
                    f"chargeback {case_id} was {cb.status}, a later notice says {outcome}: needs a person"]
                return cb, problems
            postings = resolution_postings(cb.amount, outcome, cb.cash_account) if cb.transaction_id else []
            if postings:  # a WON returns the money to where it left from; a LOST has nothing left to move
                record_entry(conn, cb.transaction_id, cb.merchant_id, cb.currency, "CHARGEBACK_RESOLUTION",
                             f"chargeback {case_id} {outcome}", postings)
            conn.execute("UPDATE chargebacks SET status = %s, resolved_at = now(), updated_at = now()"
                         " WHERE chargeback_id = %s", (outcome, cb.chargeback_id))
            _audit_entity(conn, "SYSTEM", None, "chargeback", cb.chargeback_id, "chargeback.resolve", cb.status, outcome)
            resolved = _row(conn, "chargeback_id = %s", (cb.chargeback_id,))
            if cb.transaction_id is not None:
                (webhook_url,) = conn.execute("SELECT webhook_url FROM transactions WHERE transaction_id = %s",
                                              (cb.transaction_id,)).fetchone()
                enqueue(conn, cb.merchant_id, webhook_url, {"event": f"chargeback.{outcome.lower()}", **view(resolved)})
            return resolved, []

    def submit_evidence(self, merchant_id: UUID, chargeback_id: UUID, evidence: dict) -> Chargeback:
        """The merchant's defence, once, before the deadline: PENDING -> UNDER_REVIEW."""
        with self.pool.connection() as conn, conn.transaction():
            cb = _row(conn, "chargeback_id = %s AND merchant_id = %s", (chargeback_id, merchant_id), lock=True)
            if cb is None:
                raise NotFound("chargeback not found", code="CHARGEBACK_NOT_FOUND")
            if cb.status != "PENDING":
                raise Conflict(f"evidence can only be submitted once, while PENDING; this chargeback is {cb.status}",
                               code="CHARGEBACK_NOT_DISPUTABLE")
            (late,) = conn.execute("SELECT now() > %s", (cb.evidence_deadline,)).fetchone()
            if late:
                raise Conflict("the evidence deadline has passed", code="CHARGEBACK_EVIDENCE_LATE")
            conn.execute("UPDATE chargebacks SET evidence = %s, evidence_submitted_at = now(), status = 'UNDER_REVIEW',"
                         " updated_at = now() WHERE chargeback_id = %s", (Jsonb(evidence), chargeback_id))
            _audit_entity(conn, "MERCHANT", str(merchant_id), "chargeback", chargeback_id, "chargeback.evidence",
                          "PENDING", "UNDER_REVIEW")
            return _row(conn, "chargeback_id = %s", (chargeback_id,))

    def get(self, merchant_id: UUID, chargeback_id: UUID) -> Chargeback | None:
        with self.pool.connection() as conn:
            return _row(conn, "chargeback_id = %s AND merchant_id = %s", (chargeback_id, merchant_id))
