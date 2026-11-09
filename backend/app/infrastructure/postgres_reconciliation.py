"""Reconciliation in Postgres (PR 7). A settlement file is applied in one database transaction: every line's outcome,
every SETTLEMENT entry and every CAPTURED -> SETTLED move commit together, or none do. The file's SHA-256 is unique,
so the same file delivered twice (a re-sent SFTP drop, a retried job) is reconciled once."""
import hashlib
from datetime import date, datetime, time
from uuid import UUID
from zoneinfo import ZoneInfo

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.domain.reconciliation import SettlementLine, classify, parse, settlement_postings
from app.domain.state_machine import transition
from app.infrastructure.postgres_ledger import record_entry
from app.infrastructure.postgres_transactions import _audit_entity, _response
from app.infrastructure.webhook_outbox import enqueue

BUSINESS_ZONE = ZoneInfo("Asia/Kolkata")  # acquirers in India cut settlement days at midnight IST
# Statuses a payment whose money moved can be in; a refunded sale was still settled first.
_MONEY_MOVED = ("CAPTURED", "SETTLED", "PARTIALLY_REFUNDED", "REFUNDED")
# How each file's rail names the payments it settles. A UPI QR is settled by the UPI PSP.
_RAIL_MATCH = {  # {t} is the table alias prefix, "" or "t."
    "CARD": "{t}payment_method = 'CARD'",
    "UPI": "({t}payment_method = 'UPI' OR ({t}payment_method = 'QR' AND {t}qr_encoded_rail = 'UPI'))",
    "WALLET": "{t}payment_method = 'WALLET'",
}


def _rail(rail: str, alias: str = "") -> str:
    return _RAIL_MATCH[rail].format(t=alias)


def _summary(outcomes: list[str], lines: list[SettlementLine] | None, bank_credited: int | None) -> dict:
    counts = {o: outcomes.count(o) for o in sorted(set(outcomes))}
    summary = {"outcomes": counts, "items": len(outcomes)}
    if lines is not None:
        net = sum(line.net for line in lines)
        summary |= {"gross_total": sum(line.gross for line in lines), "fee_total": sum(line.fee for line in lines),
                    "net_total": net}
        if bank_credited is not None:
            summary |= {"bank_credited": bank_credited, "liquidity_gap": net - bank_credited}
    return summary


class PostgresReconciliation:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def reconcile_file(self, raw: bytes, source: str, rail: str, acquirer_id: str,
                       bank_credited: int | None) -> tuple[UUID, dict, bool]:
        """(run_id, summary, new). A file already reconciled returns its first run with new=False."""
        if rail not in _RAIL_MATCH:
            raise ValueError(f"unknown rail {rail}")
        digest = hashlib.sha256(raw).hexdigest()
        lines = parse(raw.decode("utf-8"))  # SettlementFileInvalid before anything is written
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended('reconciliation', 0))")  # one run at a time
            existing = conn.execute("SELECT r.run_id, r.summary FROM settlement_files f JOIN reconciliation_runs r"
                                    " USING (file_id) WHERE f.sha256 = %s", (digest,)).fetchone()
            if existing:
                return existing[0], existing[1], False
            settled_on = lines[0].settlement_date if lines else date.today()
            (file_id,) = conn.execute(
                "INSERT INTO settlement_files (source, rail, acquirer_id, settlement_date, sha256, row_count, gross_total,"
                " fee_total, net_total) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING file_id",
                (source, rail, acquirer_id, settled_on, digest, len(lines), sum(x.gross for x in lines),
                 sum(x.fee for x in lines), sum(x.net for x in lines))).fetchone()
            (run_id,) = conn.execute("INSERT INTO reconciliation_runs (kind, file_id, rail, business_date, bank_credited,"
                                     " summary) VALUES ('FILE', %s, %s, %s, %s, '{}') RETURNING run_id",
                                     (file_id, rail, settled_on, bank_credited)).fetchone()
            outcomes = [self._line(conn, run_id, rail, line) for line in lines]
            summary = _summary(outcomes, lines, bank_credited)
            conn.execute("UPDATE reconciliation_runs SET summary = %s WHERE run_id = %s", (Jsonb(summary), run_id))
            return run_id, summary, True

    def _line(self, conn, run_id: UUID, rail: str, line: SettlementLine) -> str:
        payment = conn.execute(
            f"SELECT transaction_id, amount, status, merchant_id, currency, webhook_url FROM transactions"
            f" WHERE method_reference = %s AND {_rail(rail)} AND status = ANY(%s)"
            f" AND EXISTS (SELECT 1 FROM journal_entries j WHERE j.transaction_id = transactions.transaction_id"
            f" AND j.entry_type = 'SALE') FOR UPDATE", (line.reference, list(_MONEY_MOVED))).fetchone()
        transaction_id = payment[0] if payment else None
        settled = payment is not None and conn.execute(
            "SELECT 1 FROM reconciliation_items WHERE transaction_id = %s AND outcome IN ('MATCHED', 'FEE_ADJUSTED')",
            (transaction_id,)).fetchone() is not None
        outcome = classify(line, payment[1] if payment else None, settled)
        if payment and payment[4] != line.currency and outcome in ("MATCHED", "FEE_ADJUSTED"):
            outcome = "AMOUNT_MISMATCH"  # same number, different currency: not the same money
        detail = None
        if outcome in ("MATCHED", "FEE_ADJUSTED"):
            _id, _amount, status, merchant_id, currency, webhook_url = payment
            # Clearing emptied by the gross, the bank credited the net, the acquirer's fee an expense.
            record_entry(conn, transaction_id, merchant_id, currency, "SETTLEMENT",
                         f"settled {line.settlement_date} ({line.reference})", settlement_postings(line.gross, line.fee))
            if transition(status, "SETTLED") == "apply":  # a card payment: CAPTURED until its money arrives
                row = conn.execute(
                    "UPDATE transactions SET status = 'SETTLED', updated_at = now() WHERE transaction_id = %s"
                    " AND status = %s RETURNING transaction_id, idempotency_key, status, amount, currency,"
                    " payment_method, method_reference, auth_code, error, metadata, created_at, updated_at",
                    (transaction_id, status)).fetchone()
                _audit_entity(conn, "SYSTEM", None, "transaction", transaction_id, "transaction.settle", status,
                              "SETTLED", payload={"reconciliation_run": str(run_id), "fee": line.fee})
                enqueue(conn, merchant_id, webhook_url, _response(row))
        elif outcome == "AMOUNT_MISMATCH":
            detail = f"ledger expects {payment[1]} {payment[4]}, the file settles {line.gross} {line.currency}"
        conn.execute(
            "INSERT INTO reconciliation_items (run_id, transaction_id, method_reference, outcome, expected_amount,"
            " gross_amount, fee_amount, net_amount, detail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (run_id, transaction_id, line.reference, outcome, payment[1] if payment else None, line.gross, line.fee,
             line.net, detail or (f"line {line.line}: {line.record_type}" if outcome == "UNSUPPORTED_ROW" else None)))
        return outcome

    def close_day(self, rail: str, business_date: date) -> tuple[UUID, dict]:
        """Once every file for `business_date` is in: payments whose money moved before that day began (IST) and that
        no file has settled are MISSING_IN_SETTLEMENT. Reported once each, not again every night."""
        if rail not in _RAIL_MATCH:
            raise ValueError(f"unknown rail {rail}")
        cutoff = datetime.combine(business_date, time.min, BUSINESS_ZONE)
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended('reconciliation', 0))")
            (run_id,) = conn.execute("INSERT INTO reconciliation_runs (kind, rail, business_date, summary)"
                                     " VALUES ('CLOSE_DAY', %s, %s, '{}') RETURNING run_id", (rail, business_date)).fetchone()
            missing = conn.execute(
                f"SELECT t.transaction_id, t.method_reference, t.amount FROM transactions t"
                f" JOIN journal_entries j ON j.transaction_id = t.transaction_id AND j.entry_type = 'SALE'"
                f" WHERE {_rail(rail, 't.')}"
                f" AND t.status = ANY(%s) AND j.created_at < %s AND NOT EXISTS (SELECT 1 FROM reconciliation_items i"
                f" WHERE i.transaction_id = t.transaction_id AND i.outcome IN"
                f" ('MATCHED', 'FEE_ADJUSTED', 'MISSING_IN_SETTLEMENT'))",
                (list(_MONEY_MOVED), cutoff)).fetchall()
            for transaction_id, reference, amount in missing:
                conn.execute("INSERT INTO reconciliation_items (run_id, transaction_id, method_reference, outcome,"
                             " expected_amount, detail) VALUES (%s, %s, %s, 'MISSING_IN_SETTLEMENT', %s, %s)",
                             (run_id, transaction_id, reference, amount, f"not settled by {business_date}"))
            summary = _summary(["MISSING_IN_SETTLEMENT"] * len(missing), None, None)
            conn.execute("UPDATE reconciliation_runs SET summary = %s WHERE run_id = %s", (Jsonb(summary), run_id))
            return run_id, summary

    def run(self, run_id: UUID) -> dict | None:
        with self.pool.connection() as conn:
            head = conn.execute("SELECT run_id, kind, rail, business_date, bank_credited, summary, created_at, file_id"
                                " FROM reconciliation_runs WHERE run_id = %s", (run_id,)).fetchone()
            if head is None:
                return None
            items = conn.execute("SELECT transaction_id, method_reference, outcome, expected_amount, gross_amount,"
                                 " fee_amount, net_amount, detail FROM reconciliation_items WHERE run_id = %s"
                                 " ORDER BY outcome, method_reference", (run_id,)).fetchall()
        keys = ("transaction_id", "method_reference", "outcome", "expected_amount", "gross_amount", "fee_amount",
                "net_amount", "detail")
        return {"run_id": str(head[0]), "kind": head[1], "rail": head[2], "business_date": head[3].isoformat(),
                "bank_credited": head[4], "summary": head[5], "created_at": head[6].isoformat(),
                "file_id": str(head[7]) if head[7] else None,
                "items": [{k: (str(v) if isinstance(v, UUID) else v) for k, v in zip(keys, row) if v is not None}
                          for row in items]}

    def runs(self, limit: int = 50) -> list[dict]:
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT run_id, kind, rail, business_date, summary, created_at FROM reconciliation_runs"
                                " ORDER BY created_at DESC LIMIT %s", (limit,)).fetchall()
        return [{"run_id": str(r[0]), "kind": r[1], "rail": r[2], "business_date": r[3].isoformat(), "summary": r[4],
                 "created_at": r[5].isoformat()} for r in rows]

    def captured_for_mock_file(self, rail: str, since: datetime) -> list[tuple[str, int, str]]:
        """(reference, amount, currency) of unsettled payments: what a mock acquirer would put in tomorrow's file."""
        with self.pool.connection() as conn:
            return conn.execute(
                f"SELECT t.method_reference, t.amount, t.currency FROM transactions t WHERE {_rail(rail, 't.')}"
                f" AND t.status = ANY(%s) AND t.method_reference IS NOT NULL AND t.created_at >= %s"
                f" AND NOT EXISTS (SELECT 1 FROM reconciliation_items i WHERE i.transaction_id = t.transaction_id"
                f" AND i.outcome IN ('MATCHED', 'FEE_ADJUSTED')) ORDER BY t.created_at",
                (list(_MONEY_MOVED), since)).fetchall()

