"""The UPI adapter (Step 10A) and the mock PSP it talks to."""
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.application.methods import (CapabilityDescriptor, InvalidMethodDetails, MethodRegistry, MethodRequest,
                                     MethodResult, UnsupportedOperation)
from app.application.transactions import Claim, TransactionService
from app.infrastructure.methods.upi import UPI_CAPABILITIES, UpiMethodAdapter
from app.infrastructure.upi_client import HttpUpiPsp, PspDeclined, PspUnavailable

ROOT = Path(__file__).parents[2]
TERMINAL, MERCHANT = uuid4(), uuid4()
VPA = {"vpa": "asha@okhdfcbank", "flow_type": "COLLECT"}


class FakePsp:
    def __init__(self):
        self.collects, self.statuses, self.refunds = [], [], []
        self.next_status = "SUCCESS"

    def validate_vpa(self, vpa):
        if vpa == "nobody@upi":
            raise PspDeclined("VPA_NOT_FOUND", "no account is registered to this VPA")
        return {"vpa": vpa, "name": "Asha Menon", "status": "VALID"}

    def collect(self, merchant_transaction_id, amount, currency, vpa, flow_type="COLLECT"):
        if amount == 5100:
            raise PspDeclined("LIMIT_EXCEEDED", "over the per-transaction limit", "SOFT_DECLINE", retryable=True)
        self.collects.append({"merchant_transaction_id": merchant_transaction_id, "amount": amount, "vpa": vpa})
        return {"psp_transaction_id": "psp_abc", "status": "PENDING"}

    def status(self, psp_transaction_id):
        self.statuses.append(psp_transaction_id)
        if self.next_status == "SUCCESS":
            return {"psp_transaction_id": psp_transaction_id, "status": "SUCCESS", "rrn": "123456789012"}
        if self.next_status == "FAILURE":
            return {"psp_transaction_id": psp_transaction_id, "status": "FAILURE",
                    "reason": "INSUFFICIENT_FUNDS"}
        return {"psp_transaction_id": psp_transaction_id, "status": "PENDING"}

    def refund(self, psp_transaction_id, amount, refund_id=None):
        if amount > 100000:
            raise PspDeclined("BAD_REFUND", "amount exceeds the original")
        self.refunds.append((psp_transaction_id, amount))
        return {"refund_id": "rfnd_abc", "status": "SUCCESS"}


def _request(**overrides):
    base = dict(transaction_id=uuid4(), amount=1500, currency="INR", capture_mode="AUTO",
                merchant_id=MERCHANT, terminal_id=TERMINAL, details=dict(VPA))
    return MethodRequest(**{**base, **overrides})


# --- the descriptor -------------------------------------------------------------------------------------

def test_upi_capabilities_say_it_is_asynchronous_and_has_no_chargeback():
    caps: CapabilityDescriptor = UPI_CAPABILITIES
    assert caps.payment_method == "UPI"
    assert caps.is_synchronous is False
    assert caps.supports_chargeback is False
    assert caps.supports_refund is True and caps.supports_partial_refund is True
    assert caps.settlement_timeline == "instant"
    assert caps.dispute_rules.framework == "NPCI_UPI"


def test_the_descriptor_matches_the_contract_example():
    assert UPI_CAPABILITIES.to_dict()["is_synchronous"] is False
    assert UPI_CAPABILITIES.to_dict()["transitions"][1] == {"from": "PENDING", "to": "SETTLED"}


# --- validation -----------------------------------------------------------------------------------------

def test_valid_details_pass():
    assert UpiMethodAdapter(FakePsp()).validate(VPA) == VPA


@pytest.mark.parametrize("details, expected", [
    ({"vpa": "not-a-vpa", "flow_type": "COLLECT"}, "method_details.vpa"),
    ({"flow_type": "COLLECT"}, "method_details.vpa"),
    ({"vpa": "asha@okhdfcbank", "flow_type": "MANDATE"}, "method_details.mandate_details: required"),
    ({"vpa": "asha@okhdfcbank", "flow_type": "COLLECT", "mandate_details": {}},
     "method_details.mandate_details: only allowed"),
])
def test_invalid_details_are_rejected_with_field_paths(details, expected):
    with pytest.raises(InvalidMethodDetails) as raised:
        UpiMethodAdapter(FakePsp()).validate(details)
    assert expected in raised.value.message


def test_vpa_validation_returns_the_registered_name():
    assert UpiMethodAdapter(FakePsp()).validate_vpa("asha@okhdfcbank") == "Asha Menon"


# --- initiate -------------------------------------------------------------------------------------------

def test_collect_returns_pending_with_the_psp_reference():
    psp = FakePsp()
    request = _request()
    result = UpiMethodAdapter(psp).initiate(request)

    assert result.status == "PENDING"          # never SUCCESS: the customer has not approved yet
    assert result.method_reference == "psp_abc"
    assert psp.collects[0]["merchant_transaction_id"] == str(request.transaction_id)  # idempotent on replay
    assert psp.collects[0]["amount"] == 1500


def test_a_psp_decline_is_a_failed_result_not_an_exception():
    result = UpiMethodAdapter(FakePsp()).initiate(_request(amount=5100))
    assert result.status == "FAILED"
    assert result.error["error_category"] == "SOFT_DECLINE"
    assert result.error["retryable"] is True


def test_transport_failure_is_retryable_and_never_a_decline():
    class Down(FakePsp):
        def collect(self, **_kwargs):
            raise PspUnavailable("the UPI PSP did not answer (ConnectError); nothing was sent")

    from app.application.methods import AdapterUnavailable
    with pytest.raises(AdapterUnavailable):
        UpiMethodAdapter(Down()).initiate(_request())


def test_intent_and_mandate_flows_are_not_implemented_yet():
    for flow in ("INTENT", "MANDATE"):
        details = {"vpa": "asha@okhdfcbank", "flow_type": flow}
        if flow == "MANDATE":
            details["mandate_details"] = {"frequency": "MONTHLY"}
        with pytest.raises(UnsupportedOperation, match="isn't implemented yet"):
            UpiMethodAdapter(FakePsp()).initiate(_request(details=details))


# --- status and refund ----------------------------------------------------------------------------------

@pytest.mark.parametrize("psp_status, expected", [
    ("SUCCESS", "SETTLED"), ("FAILURE", "FAILED"), ("PENDING", "PENDING")])
def test_status_maps_the_psp_answer(psp_status, expected):
    psp = FakePsp()
    psp.next_status = psp_status
    result = UpiMethodAdapter(psp).status(uuid4(), "psp_abc")
    assert result.status == expected
    assert psp.statuses == ["psp_abc"]


def test_status_needs_the_stored_reference():
    with pytest.raises(UnsupportedOperation, match="reference"):
        UpiMethodAdapter(FakePsp()).status(uuid4())


def test_refund_uses_the_reference():
    psp = FakePsp()
    result = UpiMethodAdapter(psp).refund(uuid4(), 500, "psp_abc")
    assert result.status == "REFUNDED" and result.method_reference == "rfnd_abc"
    assert psp.refunds == [("psp_abc", 500)]


def test_refund_without_a_reference_is_explicit():
    with pytest.raises(UnsupportedOperation, match="reference"):
        UpiMethodAdapter(FakePsp()).refund(uuid4(), 500)


# --- the engine routes to it with no UPI knowledge ------------------------------------------------------

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
        self.finished.append({"status": status, "stored": store_response, "result": result})
        return {"transaction_id": f"txn_{transaction_id.hex}", "status": status}


class _Auth:
    def authorize(self, terminal_id, method, amount, card_network=None):
        return SimpleNamespace(reason=None, profile=None)


def test_the_engine_routes_upi_and_returns_pending():
    repo = _Repo()
    service = TransactionService(repo, _Auth(), MethodRegistry([UpiMethodAdapter(FakePsp())]))
    body = {"idempotency_key": str(uuid4()), "amount": 1500, "currency": "INR", "payment_method": "UPI",
            "method_details": dict(VPA), "terminal_id": str(TERMINAL), "merchant_id": str(MERCHANT)}

    response = service.create(TERMINAL, body)

    assert response["status"] == "PENDING"
    assert repo.finished[0]["stored"] is True   # a retry must not create a second collect
    assert repo.finished[0]["result"].method_reference == "psp_abc"


# --- against the real mock PSP --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def live_psp():
    script = ROOT / "mock-psp" / "mock_psp.py"
    proc = subprocess.Popen([sys.executable, str(script), "--port", "0"], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    if "LISTENING" not in line:
        proc.kill()
        pytest.skip(f"mock PSP did not start: {line!r}")
    yield f"http://127.0.0.1:{line.split()[1]}", proc
    proc.terminate()
    proc.wait(5)


def test_against_the_mock_psp_a_collect_settles(live_psp):
    url, _ = live_psp
    psp = HttpUpiPsp(url)
    try:
        assert psp.validate_vpa("asha@okhdfcbank")["name"] == "Asha Menon"
        with pytest.raises(PspDeclined):
            psp.validate_vpa("nobody@nowhere")

        collect = psp.collect(merchant_transaction_id="txn_1", amount=1500, currency="INR",
                              vpa="asha@okhdfcbank")
        assert collect["status"] == "PENDING"
        psp_id = collect["psp_transaction_id"]

        psp.client.post("/mock/advance", json={"psp_transaction_id": psp_id})  # what the poller would see
        assert psp.status(psp_id)["status"] == "SUCCESS"
        assert psp.refund(psp_id, 500)["status"] == "SUCCESS"
    finally:
        psp.close()


def test_against_the_mock_psp_a_declining_amount_fails_the_same_way(live_psp):
    """Amount 5100 declines; the adapter turns that into a FAILED transaction, not an exception."""
    url, _ = live_psp
    psp = HttpUpiPsp(url)
    try:
        collect = psp.collect(merchant_transaction_id="txn_2", amount=5100, currency="INR",
                              vpa="asha@okhdfcbank")
        psp.client.post("/mock/advance", json={"psp_transaction_id": collect["psp_transaction_id"]})
        result = UpiMethodAdapter(psp).status(uuid4(), collect["psp_transaction_id"])
        assert result.status == "FAILED"
        assert result.error["error_category"] == "HARD_DECLINE"
    finally:
        psp.close()
