"""PR 4: refunds, captures and voids against the real Postgres test database. A refund is never made twice, never
exceeds the payment, survives a lost answer, and reverses the ledger exactly; a void moves no money."""
import threading
from uuid import uuid4

import pytest
from psycopg_pool import ConnectionPool

from app.application.fees import ConfigFeePolicy
from app.application.methods import MethodRegistry, MethodResult
from app.application.refunds import RefundService
from app.application.transactions import public_id
from app.infrastructure.methods.base import BaseMethodAdapter
from app.infrastructure.methods.card import CARD_CAPABILITIES
from app.infrastructure.methods.upi import UPI_CAPABILITIES
from app.infrastructure.postgres_refunds import PostgresRefunds
from app.infrastructure.postgres_transactions import PostgresTransactionRepository


class FakeUpi(BaseMethodAdapter):
    """The PSP as PR 4 needs it: refunds keyed by our refund id, so a re-sent one is answered, not repeated."""
    method = "UPI"
    CAPABILITIES = UPI_CAPABILITIES

    def __init__(self):
        self.mode = "ok"
        self.made: dict[str, int] = {}
        self.calls: list[str] = []

    def send(self, request):
        raise AssertionError("not used")

    def refund(self, transaction_id, amount, reference=None, refund_id=None):
        self.calls.append(refund_id)
        if self.mode == "timeout":
            raise TimeoutError("no answer")
        if self.mode == "decline":
            return MethodResult(status="FAILED", error={"error_code": "REFUND_DECLINED", "error_message": "no",
                                                        "error_category": "HARD_DECLINE", "retryable": False})
        self.made.setdefault(refund_id, amount)
        return MethodResult(status="REFUNDED", method_reference=f"psp_{refund_id}")


class FakeCard(BaseMethodAdapter):
    method = "CARD"
    CAPABILITIES = CARD_CAPABILITIES

    def send(self, request):
        raise AssertionError("not used")

    def void(self, transaction_id, reference=None):
        return MethodResult(status="VOIDED")


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=4) as connections:
        yield connections


@pytest.fixture
def upi():
    return FakeUpi()


@pytest.fixture
def service(pool, upi):
    return RefundService(PostgresRefunds(pool, ConfigFeePolicy({"UPI": 200})), MethodRegistry([upi, FakeCard()]))


def _payment(db, pool, amount=100_000, method="UPI", status="SETTLED", fee_bps=200):
    """A finished payment, through the real finish(), so its SALE is in the ledger like any other."""
    merchant_id, terminal_id, transaction_id = uuid4(), uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model)"
               " VALUES (%s, %s, %s, %s)", (terminal_id, merchant_id, f"SN-{transaction_id.hex[:8]}", "PAX A920 Pro"))
    db.execute("INSERT INTO transactions (transaction_id, idempotency_key, merchant_id, terminal_id, amount, currency,"
               " payment_method, capture_mode, status) VALUES (%s, %s, %s, %s, %s, 'INR', %s, 'AUTO', 'PENDING')",
               (transaction_id, uuid4(), merchant_id, terminal_id, amount, method))
    PostgresTransactionRepository(pool, ConfigFeePolicy({method: fee_bps})).finish(
        transaction_id, terminal_id, MethodResult(status=status, method_reference="psp_1", bin="411111", last4="1111"),
        status, None, store_response=True)
    return merchant_id, transaction_id


def _ledger(db, transaction_id, entry_type=None):
    """{account: (debits, credits)} for this payment, optionally one entry type only."""
    rows = db.execute(
        "SELECT a.code, sum(p.debit_amount), sum(p.credit_amount) FROM ledger_postings p JOIN accounts a"
        " USING (account_id) JOIN journal_entries e USING (journal_entry_id) WHERE e.transaction_id = %s"
        " AND (%s::varchar IS NULL OR e.entry_type = %s) GROUP BY a.code", (transaction_id, entry_type, entry_type)).fetchall()
    return {code: (int(d), int(c)) for code, d, c in rows}


def _refunds(db, transaction_id):
    return db.execute("SELECT amount, status FROM refunds WHERE transaction_id = %s ORDER BY created_at",
                      (transaction_id,)).fetchall()


def _status(db, transaction_id):
    return db.execute("SELECT status, refunded_amount FROM transactions WHERE transaction_id = %s",
                      (transaction_id,)).fetchone()


# --- the four required tests -----------------------------------------------------------------------------------

def test_1_a_double_clicked_refund_refunds_once(client, db, pool, service, upi):
    merchant_id, transaction_id = _payment(db, pool)
    client.app.state.refunds = service
    key = client.app.state.api_keys.create(merchant_id)
    headers = {"Authorization": f"Bearer {key}", "Idempotency-Key": str(uuid4())}
    url = f"/api/v1/transactions/{public_id(transaction_id)}/refund"

    first = client.post(url, headers=headers, json={"amount": 50_000, "reason": "Customer return"})
    second = client.post(url, headers=headers, json={"amount": 50_000, "reason": "Customer return"})

    assert (first.status_code, second.status_code) == (201, 200), (first.text, second.text)
    assert first.json()["refund_id"] == second.json()["refund_id"] and first.json()["status"] == "COMPLETED"
    assert _refunds(db, transaction_id) == [(50_000, "COMPLETED")]
    assert db.execute("SELECT count(*) FROM journal_entries WHERE transaction_id = %s AND entry_type = 'REFUND'",
                      (transaction_id,)).fetchone()[0] == 1
    assert len(upi.made) == 1
    other = client.post(url, headers=headers, json={"amount": 10_000})
    assert other.status_code == 409 and other.json()["error_code"] == "IDEMPOTENCY_KEY_CONFLICT"


def test_2_an_over_refund_is_refused_and_records_nothing(client, db, pool, service):
    merchant_id, transaction_id = _payment(db, pool)
    client.app.state.refunds = service
    key = client.app.state.api_keys.create(merchant_id)
    r = client.post(f"/api/v1/transactions/{public_id(transaction_id)}/refund", json={"amount": 150_000},
                    headers={"Authorization": f"Bearer {key}", "Idempotency-Key": str(uuid4())})
    assert r.status_code == 400 and r.json()["error_code"] == "REFUND_EXCEEDS_AMOUNT", r.text
    assert _refunds(db, transaction_id) == []
    assert _status(db, transaction_id) == ("SETTLED", 0)


def test_3_a_partial_refund_reverses_the_ledger_proportionally(db, pool, service):
    merchant_id, transaction_id = _payment(db, pool)  # ₹1,000 with a ₹20 fee
    refund, _ = service.refund(merchant_id, transaction_id, 50_000, "Customer return", uuid4())

    assert refund.status == "COMPLETED"
    assert _ledger(db, transaction_id, "REFUND") == {"2000": (49_000, 0), "4000": (1_000, 0), "1000": (0, 50_000)}
    assert _status(db, transaction_id) == ("PARTIALLY_REFUNDED", 50_000)

    service.refund(merchant_id, transaction_id, 50_000, None, uuid4())
    assert _status(db, transaction_id) == ("REFUNDED", 100_000)
    # Fully refunded: every account nets to zero, fee included.
    assert {code: d - c for code, (d, c) in _ledger(db, transaction_id).items()} == {"1000": 0, "2000": 0, "4000": 0}


def test_4_a_void_moves_no_money(db, pool, service):
    merchant_id, transaction_id = _payment(db, pool, method="CARD", status="AUTHORIZED")
    view = service.void(merchant_id, transaction_id)
    assert view["status"] == "VOIDED"
    assert _ledger(db, transaction_id) == {}, "an authorization was a hold: nothing to post, nothing to reverse"
    assert db.execute("SELECT card_bin, card_last4, method_reference FROM transactions WHERE transaction_id = %s",
                      (transaction_id,)).fetchone() == ("411111", "1111", "psp_1"), "a void keeps the card details"
    assert service.void(merchant_id, transaction_id)["status"] == "VOIDED", "voiding twice is the same void"


# --- the guarantees behind them --------------------------------------------------------------------------------

def test_many_partial_refunds_close_the_fee_exactly(db, pool, service):
    merchant_id, transaction_id = _payment(db, pool, amount=10_000, fee_bps=333)  # fee 333 paise
    for _ in range(10):
        service.refund(merchant_id, transaction_id, 1_000, None, uuid4())
    fee_backs = [int(d) for (d,) in db.execute(
        "SELECT p.debit_amount FROM ledger_postings p JOIN accounts a USING (account_id) JOIN journal_entries e"
        " USING (journal_entry_id) WHERE e.transaction_id = %s AND e.entry_type = 'REFUND' AND a.code = '4000'"
        " ORDER BY e.created_at", (transaction_id,)).fetchall()]
    assert fee_backs == [33] * 9 + [36]
    assert {code: d - c for code, (d, c) in _ledger(db, transaction_id).items()} == {"1000": 0, "2000": 0, "4000": 0}


def test_the_penny_sweep_gives_back_exactly_the_original_fee(db, pool, service):
    """₹10 three times, then the final ₹70, on a ₹100 sale with a 333-paise fee: the refunds' fee_reversed adds up
    to the fee exactly, and the last one takes what proportional rounding left behind."""
    merchant_id, transaction_id = _payment(db, pool, amount=10_000, fee_bps=333)
    for amount in (1_000, 1_000, 1_000, 7_000):
        assert service.refund(merchant_id, transaction_id, amount, None, uuid4())[0].status == "COMPLETED"
    reversed_ = [int(f) for (f,) in db.execute("SELECT fee_reversed FROM refunds WHERE transaction_id = %s"
                                               " ORDER BY created_at", (transaction_id,)).fetchall()]
    assert reversed_ == [33, 33, 33, 234] and sum(reversed_) == 333
    assert _status(db, transaction_id) == ("REFUNDED", 10_000)


def test_the_refund_that_completes_last_takes_the_remainder_even_out_of_order(db, pool, service, upi):
    """Why fee_reversed is fixed at completion, not at reservation: ₹10 is reserved first but its answer is lost,
    the ₹90 completes meanwhile, and only when the ₹10 completes is the payment fully refunded."""
    merchant_id, transaction_id = _payment(db, pool, amount=10_000, fee_bps=333)
    upi.mode = "timeout"
    first, _ = service.refund(merchant_id, transaction_id, 1_000, None, uuid4())
    upi.mode = "ok"
    service.refund(merchant_id, transaction_id, 9_000, None, uuid4())
    service.resolve_pending(older_than_seconds=0)
    rows = db.execute("SELECT amount, fee_reversed FROM refunds WHERE transaction_id = %s ORDER BY updated_at",
                      (transaction_id,)).fetchall()
    assert rows == [(9_000, 299), (1_000, 34)] and sum(f for _, f in rows) == 333
    assert {code: d - c for code, (d, c) in _ledger(db, transaction_id).items()} == {"1000": 0, "2000": 0, "4000": 0}


def test_a_final_refund_smaller_than_the_fee_left_over_completes(db, pool, service):
    """The audit's P1: ₹100 with a ₹2 fee, refunded 3,333 paise three times (66 paise of fee back each, 198 in all) and
    then 1 paisa, which has 2 paise of fee left to give back. The extra paisa goes back to the merchant, the refund
    completes instead of failing after the PSP already paid it, and every account nets to zero."""
    merchant_id, transaction_id = _payment(db, pool, amount=10_000, fee_bps=200)
    for amount in (3_333, 3_333, 3_333, 1):
        assert service.refund(merchant_id, transaction_id, amount, None, uuid4())[0].status == "COMPLETED"
    assert [int(f) for (f,) in db.execute("SELECT fee_reversed FROM refunds WHERE transaction_id = %s ORDER BY created_at",
                                          (transaction_id,)).fetchall()] == [66, 66, 66, 2]
    assert _status(db, transaction_id) == ("REFUNDED", 10_000)
    assert {code: d - c for code, (d, c) in _ledger(db, transaction_id).items()} == {"1000": 0, "2000": 0, "4000": 0}


def test_concurrent_refunds_cannot_over_refund(db, pool, service):
    merchant_id, transaction_id = _payment(db, pool)
    outcomes = []

    def attempt():
        try:
            outcomes.append(service.refund(merchant_id, transaction_id, 60_000, None, uuid4())[0].status)
        except Exception as exc:  # noqa: BLE001
            outcomes.append(getattr(exc, "code", type(exc).__name__))

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["COMPLETED", "REFUND_EXCEEDS_AMOUNT", "REFUND_EXCEEDS_AMOUNT", "REFUND_EXCEEDS_AMOUNT"]
    assert _status(db, transaction_id) == ("PARTIALLY_REFUNDED", 60_000)


def test_a_lost_answer_stays_pending_and_recovery_finishes_it_once(db, pool, service, upi):
    merchant_id, transaction_id = _payment(db, pool)
    upi.mode = "timeout"
    refund, _ = service.refund(merchant_id, transaction_id, 30_000, None, uuid4())
    assert refund.status == "PENDING"
    assert _ledger(db, transaction_id, "REFUND") == {} and _status(db, transaction_id) == ("SETTLED", 0)
    # Reserved meanwhile: the other 70,000 is all that is left to refund.
    with pytest.raises(Exception, match="remaining"):
        service.refund(merchant_id, transaction_id, 70_001, None, uuid4())

    upi.mode = "ok"
    assert service.resolve_pending(older_than_seconds=0) == 1
    assert service.resolve_pending(older_than_seconds=0) == 0, "finished: nothing left to recover"
    assert _refunds(db, transaction_id) == [(30_000, "COMPLETED")]
    assert upi.calls == [f"rfnd_{refund.refund_id.hex}"] * 2, "re-sent under the same refund id"
    assert len(upi.made) == 1, "and refunded once"


def test_a_declined_refund_releases_its_reservation(db, pool, service, upi):
    merchant_id, transaction_id = _payment(db, pool)
    upi.mode = "decline"
    refund, _ = service.refund(merchant_id, transaction_id, 100_000, None, uuid4())
    assert refund.status == "FAILED" and refund.error["error_code"] == "REFUND_DECLINED"
    upi.mode = "ok"
    assert service.refund(merchant_id, transaction_id, 100_000, None, uuid4())[0].status == "COMPLETED"


def test_merchants_only_reach_their_own_payments_and_rails_that_can_do_it(client, db, pool, service):
    merchant_id, transaction_id = _payment(db, pool)
    stranger, _ = _payment(db, pool)
    client.app.state.refunds = service
    key = client.app.state.api_keys.create(stranger)
    url = f"/api/v1/transactions/{public_id(transaction_id)}/refund"
    r = client.post(url, json={"amount": 100}, headers={"Authorization": f"Bearer {key}", "Idempotency-Key": str(uuid4())})
    assert r.status_code == 404, "another merchant's payment looks like no payment"
    assert client.post(url, json={"amount": 100}, headers={"Authorization": f"Bearer {key}"}).status_code == 400
    assert client.post(url, json={"amount": 100}).status_code == 401

    card_merchant, card_payment = _payment(db, pool, method="CARD", status="CAPTURED")
    with pytest.raises(Exception, match="can't be refunded yet"):
        service.refund(card_merchant, card_payment, 100, None, uuid4())
    held_merchant, held = _payment(db, pool, method="CARD", status="AUTHORIZED")
    with pytest.raises(Exception, match="can't be captured yet"):
        service.capture(held_merchant, held)
    with pytest.raises(Exception, match="can't be voided"):
        service.void(merchant_id, transaction_id)  # SETTLED: nothing to void
    assert _refunds(db, card_payment) == []
