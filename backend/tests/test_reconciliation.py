"""PR 7: settlement reconciliation against the real Postgres test database. The ledger, the acquirer's file and the
bank credit are compared; every difference is either posted (a fee the bank kept) or alerted (money nobody can
account for); and a file is reconciled exactly once."""
from datetime import date, datetime, timedelta
from uuid import uuid4

import pytest
from psycopg_pool import ConnectionPool

from app import reconcile
from app.application.fees import ConfigFeePolicy
from app.application.methods import MethodResult
from app.application.reconciliation import ReconciliationService, mock_settlement_file
from app.domain.reconciliation import SettlementFileInvalid, parse, settlement_postings
from app.domain.ledger import Posting
from app.infrastructure.postgres_reconciliation import BUSINESS_ZONE, PostgresReconciliation
from app.infrastructure.postgres_transactions import PostgresTransactionRepository

TODAY = date(2026, 11, 9)


class Alerts:
    def __init__(self):
        self.raised = []

    def ops_alert(self, summary, severity, details):
        self.raised.append((severity, summary))


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=3) as connections:
        yield connections


@pytest.fixture
def alerts():
    return Alerts()


@pytest.fixture
def service(pool, alerts):
    return ReconciliationService(PostgresReconciliation(pool), alerts)


def _captured(db, pool, reference, amount=100_000, method="CARD", status="CAPTURED"):
    merchant_id, terminal_id, transaction_id = uuid4(), uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model) VALUES (%s, %s, %s, %s)",
               (terminal_id, merchant_id, f"SN-{transaction_id.hex[:8]}", "PAX A920 Pro"))
    db.execute("INSERT INTO transactions (transaction_id, idempotency_key, merchant_id, terminal_id, amount, currency,"
               " payment_method, capture_mode, status) VALUES (%s, %s, %s, %s, %s, 'INR', %s, 'AUTO', 'PENDING')",
               (transaction_id, uuid4(), merchant_id, terminal_id, amount, method))
    PostgresTransactionRepository(pool, ConfigFeePolicy({method: 200})).finish(
        transaction_id, terminal_id, MethodResult(status=status, method_reference=reference), status, None,
        store_response=True)
    return transaction_id


def _file(*lines, when=TODAY):
    """A settlement file with one SALE line per (reference, gross, fee)."""
    return ("record_type,reference,gross_amount,fee_amount,net_amount,currency,settlement_date\n" + "".join(
        f"SALE,{r},{a},{f},{a - f},INR,{when}\n" for r, a, f in lines)).encode()


def _settlement(db, transaction_id):
    rows = db.execute(
        "SELECT a.code, p.debit_amount, p.credit_amount FROM ledger_postings p JOIN accounts a USING (account_id)"
        " JOIN journal_entries e USING (journal_entry_id) WHERE e.transaction_id = %s AND e.entry_type = 'SETTLEMENT'"
        " ORDER BY a.code", (transaction_id,)).fetchall()
    return [(code, int(d), int(c)) for code, d, c in rows]


def _status(db, transaction_id):
    return db.execute("SELECT status FROM transactions WHERE transaction_id = %s", (transaction_id,)).fetchone()[0]


# --- the rules -------------------------------------------------------------------------------------------------

def test_a_settlement_moves_clearing_to_the_bank_and_the_fee_to_expense():
    assert settlement_postings(100_000, 1_500) == [Posting("1100", debit=98_500), Posting("5000", debit=1_500),
                                                   Posting("1000", credit=100_000)]
    assert settlement_postings(100_000, 0) == [Posting("1100", debit=100_000), Posting("1000", credit=100_000)]


def test_a_malformed_file_is_refused_whole():
    header = "record_type,reference,gross_amount,fee_amount,net_amount,currency,settlement_date\n"
    for bad in ("", "a,b\n", header + "SALE,R1,100,10,95,INR,2026-11-09\n",  # net isn't gross - fee
                header + "SALE,R1,1.5,0,1.5,INR,2026-11-09\n", header + "SALE,,100,0,100,INR,2026-11-09\n"):
        with pytest.raises(SettlementFileInvalid):
            parse(bad)


# --- the four matches ------------------------------------------------------------------------------------------

def test_a_perfect_match_settles_the_payment(db, pool, service, alerts):
    payment = _captured(db, pool, "RRN000000001")
    run_id, summary, new = service.reconcile_file(_file(("RRN000000001", 100_000, 0)), "test", "CARD", "acquirer_a")
    assert new and summary["outcomes"] == {"MATCHED": 1}
    assert _settlement(db, payment) == [("1000", 0, 100_000), ("1100", 100_000, 0)]
    assert _status(db, payment) == "SETTLED", "a card payment is SETTLED once its money arrives"
    assert alerts.raised == []


def test_a_fee_the_bank_kept_is_posted_as_interchange_expense(db, pool, service):
    payment = _captured(db, pool, "RRN000000002")
    _, summary, _ = service.reconcile_file(_file(("RRN000000002", 100_000, 1_500)), "test", "CARD", "acquirer_a")
    assert summary["outcomes"] == {"FEE_ADJUSTED": 1}
    assert _settlement(db, payment) == [("1000", 0, 100_000), ("1100", 98_500, 0), ("5000", 1_500, 0)]
    # Clearing for this payment is empty again: the SALE debited 100,000, the settlement credited 100,000.
    (clearing,) = db.execute(
        "SELECT sum(p.debit_amount - p.credit_amount) FROM ledger_postings p JOIN accounts a USING (account_id)"
        " JOIN journal_entries e USING (journal_entry_id) WHERE e.transaction_id = %s AND a.code = '1000'",
        (payment,)).fetchone()
    assert clearing == 0


def test_money_we_have_no_record_of_is_a_critical_alert(db, pool, service, alerts):
    _, summary, _ = service.reconcile_file(_file(("RRN-GHOST", 70_000, 0)), "test", "CARD", "acquirer_a")
    assert summary["outcomes"] == {"MISSING_IN_LEDGER": 1}
    assert alerts.raised == [("critical", "RECONCILIATION: 1 MISSING_IN_LEDGER in the CARD settlement file from acquirer_a")]
    assert db.execute("SELECT count(*) FROM journal_entries WHERE entry_type = 'SETTLEMENT'").fetchone()[0] == 0


def test_a_different_amount_is_alerted_not_posted(db, pool, service, alerts):
    payment = _captured(db, pool, "RRN000000003")
    _, summary, _ = service.reconcile_file(_file(("RRN000000003", 99_000, 0)), "test", "CARD", "acquirer_a")
    assert summary["outcomes"] == {"AMOUNT_MISMATCH": 1}
    assert _settlement(db, payment) == [] and _status(db, payment) == "CAPTURED"
    assert alerts.raised[0][0] == "critical"


def test_the_close_of_day_finds_what_no_file_settled_once(db, pool, service, alerts):
    settled, lost = _captured(db, pool, "RRN000000004"), _captured(db, pool, "RRN000000005")
    service.reconcile_file(_file(("RRN000000004", 100_000, 0)), "test", "CARD", "acquirer_a")
    tomorrow = datetime.now(BUSINESS_ZONE).date() + timedelta(days=1)
    _, summary = service.close_day("CARD", tomorrow)
    assert summary["outcomes"] == {"MISSING_IN_SETTLEMENT": 1}
    assert db.execute("SELECT transaction_id FROM reconciliation_items WHERE outcome = 'MISSING_IN_SETTLEMENT'"
                      ).fetchone()[0] == lost
    assert ("error", f"RECONCILIATION: 1 MISSING_IN_SETTLEMENT in the CARD close of {tomorrow}") in alerts.raised
    assert service.close_day("CARD", tomorrow)[1]["items"] == 0, "reported once, not every night"
    assert _status(db, settled) == "SETTLED" and _status(db, lost) == "CAPTURED"
    # A payment made today isn't missing yet: its money is due tomorrow.
    _captured(db, pool, "RRN000000006")
    assert service.close_day("CARD", datetime.now(BUSINESS_ZONE).date())[1]["items"] == 0


# --- exactly once, and the third leg ---------------------------------------------------------------------------

def test_the_same_file_twice_is_reconciled_once_and_a_second_settlement_is_a_duplicate(db, pool, service, alerts):
    payment = _captured(db, pool, "RRN000000007")
    raw = _file(("RRN000000007", 100_000, 0))
    first, _, _ = service.reconcile_file(raw, "drop-1", "CARD", "acquirer_a")
    again, _, new = service.reconcile_file(raw, "drop-1-resent", "CARD", "acquirer_a")
    assert (again, new) == (first, False)
    _, summary, _ = service.reconcile_file(_file(("RRN000000007", 100_000, 0), when=TODAY + timedelta(days=1)),
                                           "drop-2", "CARD", "acquirer_a")
    assert summary["outcomes"] == {"DUPLICATE_IN_SETTLEMENT": 1}
    assert len(_settlement(db, payment)) == 2, "one SETTLEMENT entry (two postings), not two"


def test_a_bank_credit_short_of_the_file_is_a_liquidity_gap(db, pool, service, alerts):
    _captured(db, pool, "RRN000000008")
    _, summary, _ = service.reconcile_file(_file(("RRN000000008", 100_000, 1_000)), "test", "CARD", "acquirer_a",
                                           bank_credited=98_000)
    assert (summary["net_total"], summary["bank_credited"], summary["liquidity_gap"]) == (99_000, 98_000, 1_000)
    assert any(sev == "critical" and "LIQUIDITY GAP" in text for sev, text in alerts.raised)


def test_the_nightly_job_reconciles_its_first_mock_settlement_file(db, pool, database_url, tmp_path, monkeypatch, capsys):
    """End to end through the job: a mock acquirer's file is written, reconciled, and reported."""
    payments = [_captured(db, pool, f"RRN00000010{i}", amount=10_000 * (i + 1)) for i in range(3)]
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.delenv("AUDIT_ALERT_WEBHOOK_URL", raising=False)
    drop, reports = tmp_path / "drop", tmp_path / "reports"
    drop.mkdir()
    reports.mkdir()
    assert reconcile.main(["mock-file", "--rail", "CARD", "--date", "2026-11-09", "--fee-bps", "150",
                           "--out", str(drop / "acquirer_a-2026-11-09.csv")]) == 0
    assert reconcile.main(["file", "--rail", "CARD", "--acquirer", "acquirer_a", "--source", f"dir:{drop}",
                           "--report-dir", str(reports)]) == 0
    assert all(_status(db, p) == "SETTLED" for p in payments)
    [report] = list(reports.glob("*.csv"))
    lines = report.read_text().splitlines()
    assert lines[0].startswith("outcome,transaction_id") and len(lines) == 4
    assert all(line.startswith("FEE_ADJUSTED,") for line in lines[1:])
    assert "reconciled as" in capsys.readouterr().out


def test_operators_read_runs_through_the_admin_api(client, auth, db, pool):
    _captured(db, pool, "RRN000000009")
    run_id, _, _ = client.app.state.reconciliation.reconcile_file(_file(("RRN000000009", 100_000, 0)), "test", "CARD",
                                                                  "acquirer_a")
    admin = auth(sub="ops-1", scope="registry:admin")
    listed = client.get("/api/v1/reconciliation/runs", headers=admin).json()["runs"]
    assert listed[0]["run_id"] == str(run_id)
    detail = client.get(f"/api/v1/reconciliation/runs/{run_id}", headers=admin).json()
    assert [i["outcome"] for i in detail["items"]] == ["MATCHED"]
    assert client.get(f"/api/v1/reconciliation/runs/{run_id}/report.csv", headers=admin).text.startswith("outcome,")
    assert client.get("/api/v1/reconciliation/runs", headers=auth(scope="registry:read")).status_code == 403
    assert client.get(f"/api/v1/reconciliation/runs/{uuid4()}", headers=admin).status_code == 404
