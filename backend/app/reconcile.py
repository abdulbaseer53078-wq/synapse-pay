"""Settlement reconciliation jobs (PR 7). Schedule `file` nightly after the acquirer's drop (e.g. 02:00 IST) and
`close-day` after all of a day's files are in.

    python -m app.reconcile file --rail CARD --acquirer acquirer_a --source dir:./settlement [--bank-credited N]
                                 [--report-dir ./reports]
    python -m app.reconcile close-day --rail CARD --date 2026-11-08
    python -m app.reconcile mock-file --rail CARD --date 2026-11-09 --fee-bps 150 --out ./settlement/card.csv

Env: DATABASE_URL; AUDIT_ALERT_WEBHOOK_URL for alerts (printed when unset).
"""
import argparse
import os
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from psycopg_pool import ConnectionPool

from app.application.reconciliation import ReconciliationService, mock_settlement_file
from app.domain.reconciliation import SettlementFileInvalid
from app.infrastructure.audit_alerts import NullAlerter, WebhookAlerter
from app.infrastructure.postgres_reconciliation import PostgresReconciliation
from app.infrastructure.settlement_sources import source


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.reconcile")
    jobs = parser.add_subparsers(dest="job", required=True)
    one = jobs.add_parser("file", help="reconcile every settlement file at a source")
    one.add_argument("--rail", required=True, choices=["CARD", "UPI", "WALLET"])
    one.add_argument("--acquirer", required=True)
    one.add_argument("--source", required=True, help="dir:<path> or s3://bucket/prefix")
    one.add_argument("--bank-credited", type=int, help="what reached the bank for this file, minor units")
    one.add_argument("--report-dir", help="write each run's report CSV here")
    close = jobs.add_parser("close-day", help="report payments no file settled")
    close.add_argument("--rail", required=True, choices=["CARD", "UPI", "WALLET"])
    close.add_argument("--date", required=True, type=date.fromisoformat)
    mock = jobs.add_parser("mock-file", help="write the file a mock acquirer would send (sandbox)")
    mock.add_argument("--rail", required=True, choices=["CARD", "UPI", "WALLET"])
    mock.add_argument("--date", required=True, type=date.fromisoformat)
    mock.add_argument("--fee-bps", type=int, default=0)
    mock.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    alert_url = os.environ.get("AUDIT_ALERT_WEBHOOK_URL")
    with ConnectionPool(os.environ["DATABASE_URL"], min_size=1, max_size=2) as pool:
        store = PostgresReconciliation(pool)
        service = ReconciliationService(store, WebhookAlerter(alert_url) if alert_url else NullAlerter())
        if args.job == "mock-file":
            rows = store.captured_for_mock_file(args.rail, datetime.now(UTC) - timedelta(days=30))
            Path(args.out).write_text(mock_settlement_file(rows, args.date, args.fee_bps), encoding="utf-8")
            print(f"wrote {len(rows)} line(s) to {args.out}")
            return 0
        if args.job == "close-day":
            run_id, summary = service.close_day(args.rail, args.date)
            print(f"close-day {run_id}: {summary}")
            return 0
        failed = 0
        for name, raw in source(args.source).files():
            try:
                run_id, summary, new = service.reconcile_file(raw, name, args.rail, args.acquirer, args.bank_credited)
            except SettlementFileInvalid as exc:  # the whole file is refused; nothing from it was applied
                failed += 1
                service.alerts.ops_alert(f"RECONCILIATION: settlement file refused ({exc})", "critical", {"file": name})
                continue
            print(f"{name}: {'reconciled' if new else 'already reconciled'} as {run_id}: {summary}")
            if args.report_dir and new:
                out = Path(args.report_dir) / f"reconciliation-{run_id}.csv"
                out.write_text(service.report_csv(run_id), encoding="utf-8")
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
