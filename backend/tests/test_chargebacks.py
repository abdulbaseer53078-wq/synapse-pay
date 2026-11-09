"""PR 8: chargebacks against the real Postgres test database. The money leaves when the chargeback opens (that's when
the acquirer takes it) and comes back if it's won; the ledger balances throughout; notices are trusted only when signed
and applied only once; and a dispute and a refund can't both pay the customer."""
import hashlib
import hmac
import json
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg_pool import ConnectionPool

from app.application.fees import ConfigFeePolicy
from app.application.methods import MethodRegistry, MethodResult
from app.application.refunds import RefundService
from app.application.transactions import public_id
from app.infrastructure.methods.upi import UPI_CAPABILITIES
from app.infrastructure.postgres_refunds import PostgresRefunds
from app.infrastructure.postgres_transactions import PostgresTransactionRepository
from app.main import create_app

SECRET = "whsec_acquirer_test"


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=3) as connections:
        yield connections


@pytest.fixture
def acquirer(settings, db):
    """The app, with the acquirer's webhook secret configured, and a way to send it signed notices."""
    with TestClient(create_app(replace(settings, chargeback_webhook_secret=SECRET))) as client:
        raised = []
        client.app.state.chargebacks.alerts = type("A", (), {"ops_alert": lambda self, s, sev, d: raised.append(s)})()

        def send(path, body, secret=SECRET, ts=None):
            raw = json.dumps(body).encode()
            stamp = str(ts or int(time.time()))
            signature = hmac.new(secret.encode(), f"{stamp}.".encode() + raw, hashlib.sha256).hexdigest()
            return client.post(f"/api/v1/webhooks/chargebacks{path}", content=raw,
                               headers={"X-Timestamp": stamp, "X-Signature": signature,
                                        "Content-Type": "application/json"})
        yield client, send, raised


def _sale(db, pool, reference, amount=100_000, method="CARD", webhook=True):
    """A captured ₹1,000 card sale with a ₹20 fee, through the real finish(), so its SALE is in the ledger."""
    merchant_id, terminal_id, transaction_id = uuid4(), uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id, webhook_secret) VALUES (%s, 'whsec_m')", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model) VALUES (%s, %s, %s, %s)",
               (terminal_id, merchant_id, f"SN-{transaction_id.hex[:8]}", "PAX A920 Pro"))
    db.execute("INSERT INTO transactions (transaction_id, idempotency_key, merchant_id, terminal_id, amount, currency,"
               " payment_method, capture_mode, status, webhook_url) VALUES (%s, %s, %s, %s, %s, 'INR', %s, 'AUTO',"
               " 'PENDING', %s)", (transaction_id, uuid4(), merchant_id, terminal_id, amount, method,
                                   "https://shop.example/hooks" if webhook else None))
    status = "CAPTURED" if method == "CARD" else "SETTLED"
    PostgresTransactionRepository(pool, ConfigFeePolicy({method: 200})).finish(
        transaction_id, terminal_id, MethodResult(status=status, method_reference=reference), status, None,
        store_response=True)
    return merchant_id, transaction_id


def _opened(reference, case="CB-1", amount=100_000, event=None, deadline_days=10):
    return {"event_id": event or f"evt-{uuid4().hex}", "acquirer_id": "acquirer_a", "case_id": case,
            "network_reference": reference, "amount": amount, "currency": "INR", "reason_code": "10.4",
            "evidence_deadline": (datetime.now(UTC) + timedelta(days=deadline_days)).isoformat()}


def _resolution(case="CB-1", outcome="WON"):
    return {"event_id": f"evt-{uuid4().hex}", "acquirer_id": "acquirer_a", "case_id": case, "outcome": outcome}


def _balance(db, transaction_id, code):
    """Debits minus credits on one account, for one payment."""
    (net,) = db.execute(
        "SELECT coalesce(sum(p.debit_amount - p.credit_amount), 0) FROM ledger_postings p JOIN accounts a"
        " USING (account_id) JOIN journal_entries e USING (journal_entry_id) WHERE e.transaction_id = %s"
        " AND a.code = %s", (transaction_id, code)).fetchone()
    return int(net)


def _whole_ledger_balances(db):
    return db.execute("SELECT sum(debit_amount) = sum(credit_amount) FROM ledger_postings").fetchone()[0] is True


# --- the three required tests ----------------------------------------------------------------------------------

def test_1_a_chargeback_takes_the_money_when_it_opens(acquirer, db, pool):
    client, send, _ = acquirer
    _, payment = _sale(db, pool, "RRN100000001")
    assert _balance(db, payment, "2000") == -98_000  # the merchant is owed ₹980 (credit)
    r = send("", _opened("RRN100000001"))
    assert r.status_code == 200 and r.json()["status"] == "PENDING", r.text
    assert _balance(db, payment, "2000") == -98_000 + 100_000, "the merchant's payable drops by ₹1,000"
    assert _balance(db, payment, "1000") == 0, "not settled yet: the acquirer won't pay it, so clearing gives it up"
    assert _whole_ledger_balances(db)


def test_2_winning_puts_the_money_back(acquirer, db, pool):
    client, send, _ = acquirer
    _, payment = _sale(db, pool, "RRN100000002")
    send("", _opened("RRN100000002", case="CB-2"))
    assert send("/resolution", _resolution("CB-2", "WON")).json()["status"] == "WON"
    assert _balance(db, payment, "1000") == 100_000, "the acquirer pays it after all"
    assert _balance(db, payment, "2000") == -98_000, "owed the ₹980 again"
    assert _whole_ledger_balances(db)


def test_3_losing_moves_nothing_more_the_money_already_left(acquirer, db, pool):
    client, send, _ = acquirer
    _, payment = _sale(db, pool, "RRN100000003")
    send("", _opened("RRN100000003", case="CB-3"))
    before = db.execute("SELECT count(*) FROM ledger_postings").fetchone()[0]
    send("/resolution", _resolution("CB-3", "LOST"))
    assert db.execute("SELECT count(*) FROM ledger_postings").fetchone()[0] == before
    assert _balance(db, payment, "1000") == 0, "clearing: +₹1,000 from the sale, −₹1,000 when it opened"
    assert _balance(db, payment, "2000") == 2_000, "the merchant now owes the ₹20 fee: it isn't refunded"
    assert _whole_ledger_balances(db)


# --- the cases behind them -------------------------------------------------------------------------------------

def test_after_settlement_the_money_leaves_the_bank_and_comes_back_there(acquirer, db, pool):
    client, send, _ = acquirer
    _, payment = _sale(db, pool, "RRN100000004")
    from app.application.reconciliation import ReconciliationService
    from app.infrastructure.postgres_reconciliation import PostgresReconciliation
    file = ("record_type,reference,gross_amount,fee_amount,net_amount,currency,settlement_date\n"
            "SALE,RRN100000004,100000,0,100000,INR,2026-11-09\n").encode()
    ReconciliationService(PostgresReconciliation(pool), client.app.state.ops_alerts).reconcile_file(
        file, "test", "CARD", "acquirer_a")
    send("", _opened("RRN100000004", case="CB-4"))
    assert _balance(db, payment, "1000") == 0, "clearing was already emptied by the settlement"
    assert _balance(db, payment, "1100") == 0, "the bank: +₹1,000 settled, −₹1,000 taken back at once"
    send("/resolution", _resolution("CB-4", "WON"))
    assert _balance(db, payment, "1100") == 100_000, "won: returned to the bank it left"
    assert _whole_ledger_balances(db)


def test_a_notice_is_applied_once(acquirer, db, pool):
    client, send, _ = acquirer
    _, payment = _sale(db, pool, "RRN100000005")
    notice = _opened("RRN100000005", case="CB-5", event="evt-same")
    first, again = send("", notice), send("", notice)
    restated = send("", _opened("RRN100000005", case="CB-5"))  # the same case, a new event id
    assert first.json()["chargeback_id"] == again.json()["chargeback_id"] == restated.json()["chargeback_id"]
    assert db.execute("SELECT count(*) FROM journal_entries WHERE transaction_id = %s AND entry_type = 'CHARGEBACK'",
                      (payment,)).fetchone()[0] == 1
    resolution = _resolution("CB-5", "WON")
    send("/resolution", resolution)
    send("/resolution", resolution)
    assert db.execute("SELECT count(*) FROM journal_entries WHERE transaction_id = %s"
                      " AND entry_type = 'CHARGEBACK_RESOLUTION'", (payment,)).fetchone()[0] == 1


def test_only_signed_fresh_notices_are_trusted(acquirer, settings, db, pool):
    client, send, _ = acquirer
    _sale(db, pool, "RRN100000006")
    assert send("", _opened("RRN100000006"), secret="wrong").status_code == 401
    assert send("", _opened("RRN100000006"), ts=int(time.time()) - 3600).status_code == 400  # a replayed old notice
    assert send("", {"event_id": "x"}).status_code == 400
    assert db.execute("SELECT count(*) FROM chargebacks").fetchone()[0] == 0
    with TestClient(create_app(settings)) as unconfigured:  # no secret: refused, never accepted unsigned
        assert unconfigured.post("/api/v1/webhooks/chargebacks", json=_opened("RRN100000006")).status_code == 503


def test_a_chargeback_for_a_payment_we_dont_know_is_recorded_and_alerted(acquirer, db):
    client, send, raised = acquirer
    r = send("", _opened("RRN-UNKNOWN", case="CB-7"))
    assert r.status_code == 200 and r.json()["status"] == "PENDING"
    assert any("no record of" in a for a in raised)
    assert db.execute("SELECT count(*) FROM journal_entries").fetchone()[0] == 0


def test_a_disputed_payment_cant_also_be_refunded(acquirer, db, pool):
    client, send, raised = acquirer

    class Rail:  # UPI-like capabilities on a card payment would be wrong; refunds here go through a fake card rail
        method = "CARD"

        def capabilities(self):
            return replace(UPI_CAPABILITIES, payment_method="CARD")

        def refund(self, *args, **kwargs):
            return MethodResult(status="REFUNDED", method_reference="r")

    refunds = RefundService(PostgresRefunds(pool), MethodRegistry([Rail()]))
    merchant, payment = _sale(db, pool, "RRN100000008")
    send("", _opened("RRN100000008", case="CB-8", amount=40_000))
    with pytest.raises(Exception, match="open chargeback"):
        refunds.refund(merchant, payment, 10_000, None, uuid4())
    send("/resolution", _resolution("CB-8", "LOST"))
    with pytest.raises(Exception, match="remaining"):
        refunds.refund(merchant, payment, 60_001, None, uuid4())  # ₹400 went to the chargeback
    assert refunds.refund(merchant, payment, 60_000, None, uuid4())[0].status == "COMPLETED"
    # A chargeback on top of a full refund is still recorded (the network decides), and raised to a person.
    send("", _opened("RRN100000008", case="CB-9", amount=10_000))
    assert any("exceed the payment" in a for a in raised)
    assert _whole_ledger_balances(db)


def test_the_merchant_sees_its_chargeback_and_defends_it_once_before_the_deadline(acquirer, db, pool):
    client, send, _ = acquirer
    merchant, payment = _sale(db, pool, "RRN100000010")
    stranger, _ = _sale(db, pool, "RRN100000011")
    cb = send("", _opened("RRN100000010", case="CB-10")).json()["chargeback_id"]
    late = send("", _opened("RRN100000011", case="CB-11", deadline_days=-1)).json()["chargeback_id"]
    key = {"Authorization": f"Bearer {client.app.state.api_keys.create(merchant)}"}
    other = {"Authorization": f"Bearer {client.app.state.api_keys.create(stranger)}"}

    seen = client.get(f"/api/v1/chargebacks/{cb}", headers=key).json()
    assert (seen["status"], seen["transaction_id"], seen["reason_code"]) == ("PENDING", public_id(payment), "10.4")
    assert client.get(f"/api/v1/chargebacks/{cb}", headers=other).status_code == 404
    evidence = {"explanation": "Delivered and signed for", "tracking_number": "DTDC123", "delivery_date": "2026-11-02"}
    r = client.post(f"/api/v1/chargebacks/{cb}/evidence", headers=key, json=evidence)
    assert r.status_code == 200 and r.json()["status"] == "UNDER_REVIEW" and r.json()["evidence"] == evidence
    assert client.post(f"/api/v1/chargebacks/{cb}/evidence", headers=key, json=evidence).status_code == 409
    assert client.post(f"/api/v1/chargebacks/{late}/evidence", headers=other,
                       json=evidence).json()["error_code"] == "CHARGEBACK_EVIDENCE_LATE"
    assert client.post(f"/api/v1/chargebacks/{cb}/evidence", headers=key,
                       json={"explanation": "x", "evidence_url": "https://evil"}).status_code == 400

    bodies = [json.loads(b) for (b,) in db.execute("SELECT body FROM webhook_deliveries ORDER BY created_at").fetchall()]
    assert [b.get("event") for b in bodies if "event" in b][:2] == ["chargeback.opened", "chargeback.opened"]
