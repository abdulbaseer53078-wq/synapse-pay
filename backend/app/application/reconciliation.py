"""Settlement reconciliation (PR 7): the ledger against the acquirer's file against the bank.

Run nightly per file, then once per day per rail to find what no file settled. Every break an operator must act on
raises an alert; everything lands in a report the operations team can read.
"""
import csv
import io
from datetime import date
from typing import Protocol
from uuid import UUID

from app.domain.reconciliation import HEADER

# Outcomes that need a person. MATCHED and FEE_ADJUSTED post themselves; UNSUPPORTED_ROW is in the report.
_ALERT = {"MISSING_IN_LEDGER": "critical",  # money we have no record of: a ghost payment or a bug
          "AMOUNT_MISMATCH": "critical",  # the bank settled a different amount than we charged
          "DUPLICATE_IN_SETTLEMENT": "error",
          "MISSING_IN_SETTLEMENT": "error"}  # we charged, nobody paid us: a lost transaction


class ReconciliationStore(Protocol):
    def reconcile_file(self, raw: bytes, source: str, rail: str, acquirer_id: str,
                       bank_credited: int | None) -> tuple[UUID, dict, bool]: ...
    def close_day(self, rail: str, business_date: date) -> tuple[UUID, dict]: ...
    def run(self, run_id: UUID) -> dict | None: ...
    def runs(self, limit: int = 50) -> list[dict]: ...


class Alerts(Protocol):
    def ops_alert(self, summary: str, severity: str, details: dict) -> None: ...


class ReconciliationService:
    def __init__(self, store: ReconciliationStore, alerts: Alerts):
        self.store = store
        self.alerts = alerts

    def reconcile_file(self, raw: bytes, source: str, rail: str, acquirer_id: str,
                       bank_credited: int | None = None) -> tuple[UUID, dict, bool]:
        run_id, summary, new = self.store.reconcile_file(raw, source, rail, acquirer_id, bank_credited)
        if new:  # a file seen before was alerted on the first time
            self._alert(run_id, summary, f"{rail} settlement file from {acquirer_id}")
            gap = summary.get("liquidity_gap")
            if gap:
                self.alerts.ops_alert(f"LIQUIDITY GAP: the bank credited {summary['bank_credited']}, the file settled "
                                      f"{summary['net_total']}", "critical", {"run_id": str(run_id), "gap": gap})
        return run_id, summary, new

    def close_day(self, rail: str, business_date: date) -> tuple[UUID, dict]:
        run_id, summary = self.store.close_day(rail, business_date)
        self._alert(run_id, summary, f"{rail} close of {business_date}")
        return run_id, summary

    def report_csv(self, run_id: UUID) -> str:
        """The run, one line per item: what the operations team reads."""
        run = self.store.run(run_id)
        if run is None:
            raise KeyError(run_id)
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(["outcome", "transaction_id", "method_reference", "expected_amount", "gross_amount",
                         "fee_amount", "net_amount", "detail"])
        for item in run["items"]:
            writer.writerow([item.get(k, "") for k in ("outcome", "transaction_id", "method_reference",
                                                         "expected_amount", "gross_amount", "fee_amount", "net_amount",
                                                         "detail")])
        return out.getvalue()

    def _alert(self, run_id: UUID, summary: dict, what: str) -> None:
        for outcome, count in summary.get("outcomes", {}).items():
            if outcome in _ALERT and count:
                self.alerts.ops_alert(f"RECONCILIATION: {count} {outcome} in the {what}", _ALERT[outcome],
                                      {"run_id": str(run_id), "outcome": outcome, "count": count})


def mock_settlement_file(rows: list[tuple[str, int, str]], settlement_date: date, fee_bps: int = 0) -> str:
    """What a mock acquirer or PSP would send for these (reference, amount, currency) payments, keeping `fee_bps`."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(HEADER)
    for reference, amount, currency in rows:
        fee = amount * fee_bps // 10_000
        writer.writerow(["SALE", reference, amount, fee, amount - fee, currency, settlement_date.isoformat()])
    return out.getvalue()
