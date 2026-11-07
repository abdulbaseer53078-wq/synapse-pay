"""The wallet adapter (Step 12, tokenised flow) against a fake and the real mock provider."""
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.application.methods import InvalidMethodDetails, MethodRegistry, UnsupportedOperation
from app.application.transactions import Claim, TransactionService
from app.infrastructure.methods.wallet import (WALLET_CAPABILITIES, HttpWallet, WalletDeclined, WalletMethodAdapter,
                                               WalletUnavailable)

ROOT = Path(__file__).parents[2]
TERMINAL, MERCHANT = uuid4(), uuid4()
DETAILS = {"wallet_provider": "PAYTM", "wallet_token": "tok_live_1"}


class FakeWallet:
    def __init__(self):
        self.debits, self.statuses = [], []
        self.next_status = "SUCCESS"

    def debit(self, wallet_token, amount, currency, merchant_transaction_id):
        if wallet_token == "tok_blocked":
            raise WalletDeclined("WALLET_BLOCKED", "wallet is blocked pending KYC")
        if wallet_token == "tok_poor":
            raise WalletDeclined("WALLET_INSUFFICIENT_BALANCE", "balance too low", "SOFT_DECLINE", True)
        if amount > 1000000:
            raise WalletDeclined("WALLET_LIMIT_EXCEEDED", "above the per-transaction limit")
        self.debits.append({"token": wallet_token, "amount": amount, "ref": merchant_transaction_id})
        return {"wallet_transaction_id": "wal_1", "status": "SUCCESS"}

    def status(self, wallet_transaction_id):
        self.statuses.append(wallet_transaction_id)
        return {"wallet_transaction_id": wallet_transaction_id, "status": self.next_status}


def _request(details=None, amount=5000):
    from app.application.methods import MethodRequest
    return MethodRequest(transaction_id=uuid4(), amount=amount, currency="INR", capture_mode="AUTO",
                         merchant_id=MERCHANT, terminal_id=TERMINAL, details=details or dict(DETAILS))


# --- descriptor -----------------------------------------------------------------------------------------

def test_wallet_descriptor_has_no_partial_refunds_or_chargebacks():
    body = WALLET_CAPABILITIES.to_dict()
    assert body["payment_method"] == "WALLET"
    assert body["supports_refund"] is True and body["supports_partial_refund"] is False
    assert body["supports_chargeback"] is False
    assert body["settlement_timeline"] == "T+0"


# --- validation -----------------------------------------------------------------------------------------

def test_the_spec_requires_a_token():
    with pytest.raises(InvalidMethodDetails) as raised:
        WalletMethodAdapter(FakeWallet()).validate({"wallet_provider": "PAYTM"})
    assert "method_details.wallet_token" in raised.value.message


@pytest.mark.parametrize("details", [
    {"wallet_provider": "GOOGLE_PAY", "wallet_token": "t"},   # not one of the three providers
    {"wallet_provider": "PAYTM", "wallet_token": "t", "card_number": "4111111111111111"},
])
def test_unknown_providers_and_extra_fields_are_rejected(details):
    with pytest.raises(InvalidMethodDetails):
        WalletMethodAdapter(FakeWallet()).validate(details)


# --- the direct debit -----------------------------------------------------------------------------------

def test_a_successful_debit_settles_immediately():
    """Stored value is a closed-loop transfer: nothing is left pending."""
    wallet = FakeWallet()
    request = _request()
    result = WalletMethodAdapter(wallet).initiate(request)

    assert result.status == "SETTLED" and result.method_reference == "wal_1"
    assert wallet.debits[0]["ref"] == str(request.transaction_id)  # idempotent on the engine's id
    assert wallet.debits[0]["amount"] == 5000


@pytest.mark.parametrize("token, code, category, retryable", [
    ("tok_blocked", "WALLET_BLOCKED", "HARD_DECLINE", False),
    ("tok_poor", "WALLET_INSUFFICIENT_BALANCE", "SOFT_DECLINE", True),
])
def test_wallet_declines_map_to_the_taxonomy(token, code, category, retryable):
    result = WalletMethodAdapter(FakeWallet()).initiate(
        _request({**DETAILS, "wallet_token": token}))
    assert result.status == "FAILED"
    assert (result.error["error_code"], result.error["error_category"], result.error["retryable"]) == (
        code, category, retryable)


def test_a_transport_failure_is_retryable_and_never_a_decline():
    class Down(FakeWallet):
        def debit(self, **_kwargs):
            raise WalletUnavailable("the wallet provider did not answer (ConnectError)")

    from app.application.methods import AdapterUnavailable
    with pytest.raises(AdapterUnavailable):
        WalletMethodAdapter(Down()).initiate(_request())


def test_status_needs_the_provider_reference():
    with pytest.raises(UnsupportedOperation, match="reference"):
        WalletMethodAdapter(FakeWallet()).status(uuid4())


# --- the engine routes it -------------------------------------------------------------------------------

class _Repo:
    def __init__(self):
        self.finished = []

    def terminal_merchant(self, terminal_id):
        return MERCHANT

    def spent_today(self, terminal_id, since):
        return 0

    def claim(self, txn):
        return Claim(transaction_id=uuid4())

    def mark_pending(self, transaction_id, terminal_id):
        pass

    def finish(self, transaction_id, terminal_id, result, status, error, store_response):
        self.finished.append({"status": status, "stored": store_response})
        return {"transaction_id": f"txn_{transaction_id.hex}", "status": status}


class _Auth:
    def authorize(self, terminal_id, method, amount):
        return SimpleNamespace(reason=None, profile=None)


def test_the_engine_routes_wallet_and_settles():
    repo = _Repo()
    service = TransactionService(repo, _Auth(), MethodRegistry([WalletMethodAdapter(FakeWallet())]))
    body = {"idempotency_key": str(uuid4()), "amount": 5000, "currency": "INR", "payment_method": "WALLET",
            "method_details": dict(DETAILS), "terminal_id": str(TERMINAL), "merchant_id": str(MERCHANT)}

    response = service.create(TERMINAL, body)

    assert response["status"] == "SETTLED"
    assert repo.finished[0]["stored"] is True


# --- against the real mock provider ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def live_wallet():
    script = ROOT / "mock-wallet" / "mock_wallet.py"
    proc = subprocess.Popen([sys.executable, str(script), "--port", "0"], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    if "LISTENING" not in line:
        proc.kill()
        pytest.skip(f"mock wallet did not start: {line!r}")
    yield f"http://127.0.0.1:{line.split()[1]}", proc
    proc.terminate()
    proc.wait(5)


def test_against_the_mock_wallet_a_debit_settles(live_wallet):
    url, _ = live_wallet
    provider = HttpWallet(url)
    try:
        adapter = WalletMethodAdapter(provider)
        assert adapter.initiate(_request()).status == "SETTLED"
        assert adapter.initiate(_request({**DETAILS, "wallet_token": "tok_blocked"})).error["error_code"] == \
            "WALLET_BLOCKED"
    finally:
        provider.close()


def test_against_the_mock_wallet_a_limit_is_a_decline_not_a_crash(live_wallet):
    url, _ = live_wallet
    provider = HttpWallet(url)
    try:
        result = WalletMethodAdapter(provider).initiate(_request(amount=1_500_000))
        assert result.status == "FAILED" and result.error["error_code"] == "WALLET_LIMIT_EXCEEDED"
    finally:
        provider.close()
