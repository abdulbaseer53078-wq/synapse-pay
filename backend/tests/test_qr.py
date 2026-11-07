"""The QR adapter (Step 11): it parses, names the rail, and dispatches — it never moves money itself."""
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.application.methods import InvalidMethodDetails, MethodRegistry, MethodResult, UnsupportedOperation
from app.application.transactions import Claim, TransactionService
from app.infrastructure.methods.qr import QR_CAPABILITIES, QrMethodAdapter, generate_qr, parse_qr

TERMINAL, MERCHANT = uuid4(), uuid4()
UPI_QR = "upi://pay?pa=asha@okhdfcbank&pn=Asha%20Menon&am=15.00&cu=INR&tn=chai"


class FakeUpi:
    method = "UPI"

    def __init__(self):
        self.requests = []

    def validate(self, details):
        return details

    def initiate(self, request):
        self.requests.append(request)
        return MethodResult(status="PENDING", method_reference="psp_from_qr")

    def capabilities(self):
        from app.infrastructure.methods.upi import UPI_CAPABILITIES
        return UPI_CAPABILITIES


# --- parsing --------------------------------------------------------------------------------------------

def test_a_upi_qr_parses_to_a_vpa_and_a_rail():
    parsed = parse_qr(UPI_QR)
    assert parsed["rail"] == "UPI"
    assert parsed["vpa"] == "asha@okhdfcbank"
    assert parsed["payee_name"] == "Asha Menon"
    assert parsed["amount"] == 1500  # rupees on the code, minor units here


def test_a_qr_without_an_amount_leaves_it_to_the_payer():
    assert parse_qr("upi://pay?pa=asha@okhdfcbank&pn=Asha")["amount"] is None


@pytest.mark.parametrize("qr_data, message", [
    ("https://evil.example/pay?pa=asha@okhdfcbank", "not a upi://pay URI"),
    ("upi://pay?pn=Asha&am=10.00", "pa is missing or not a VPA"),
    ("upi://pay?pa=asha&am=10.00", "pa is missing or not a VPA"),
    ("upi://pay?pa=asha@okhdfcbank&am=ten", "am is not a number"),
    ("upi://pay?pa=asha@okhdfcbank&am=-1", "am must be positive"),
])
def test_bad_qr_strings_are_rejected_with_a_reason(qr_data, message):
    with pytest.raises(InvalidMethodDetails) as raised:
        parse_qr(qr_data)
    assert message in raised.value.message


def test_bharat_qr_is_not_supported_yet():
    with pytest.raises(UnsupportedOperation, match="tokenised card"):
        parse_qr("bharatqr://pay?mc=5411&tr=123")


# --- dynamic generation ---------------------------------------------------------------------------------

def test_generated_qr_round_trips_through_the_parser():
    qr = generate_qr("merchant@okicici", "Chai Corner", 2500, note="table 4", reference="txn_abc")
    parsed = parse_qr(qr)
    assert parsed["vpa"] == "merchant@okicici" and parsed["amount"] == 2500
    assert parsed["payee_name"] == "Chai Corner" and parsed["note"] == "table 4"
    assert "tr=txn_abc" in qr


# --- the descriptor -------------------------------------------------------------------------------------

def test_qr_descriptor_is_the_contracts_fallback():
    body = QR_CAPABILITIES.to_dict()
    assert body["payment_method"] == "QR"
    assert body["is_synchronous"] is False
    assert body["supports_chargeback"] is False
    assert body["settlement_timeline"] == "unknown"  # the rail it encodes decides settlement


# --- dispatch -------------------------------------------------------------------------------------------

def test_validation_names_the_rail_so_it_can_be_persisted():
    adapter = QrMethodAdapter(MethodRegistry([FakeUpi()]))
    clean = adapter.validate({"qr_data": UPI_QR})
    assert clean["qr_encoded_rail"] == "UPI" and clean["vpa"] == "asha@okhdfcbank"
    assert clean["qr_amount"] == 1500


def test_initiate_dispatches_to_the_upi_adapter():
    upi = FakeUpi()
    adapter = QrMethodAdapter(MethodRegistry([upi]))
    details = adapter.validate({"qr_data": UPI_QR})

    result = adapter.initiate(_request(details, amount=1500))

    assert result.status == "PENDING" and result.method_reference == "psp_from_qr"
    assert upi.requests[0].details == {"vpa": "asha@okhdfcbank", "flow_type": "COLLECT"}


def test_the_qr_amount_must_match_the_charge():
    """The anti-tampering check: a QR for 15.00 cannot be charged at 1.00."""
    upi = FakeUpi()
    adapter = QrMethodAdapter(MethodRegistry([upi]))
    details = adapter.validate({"qr_data": UPI_QR})

    with pytest.raises(InvalidMethodDetails, match="the QR is for 1500"):
        adapter.initiate(_request(details, amount=100))
    assert upi.requests == []  # never reached the rail


def _request(details, amount=1500):
    from app.application.methods import MethodRequest
    return MethodRequest(transaction_id=uuid4(), amount=amount, currency="INR", capture_mode="AUTO",
                         merchant_id=MERCHANT, terminal_id=TERMINAL, details=details)


# --- the engine routes QR, and persists the rail --------------------------------------------------------

class _Repo:
    def __init__(self):
        self.txn = None
        self.finished = []

    def terminal_merchant(self, terminal_id):
        return MERCHANT

    def spent_today(self, terminal_id, since):
        return 0

    def claim(self, txn):
        self.txn = txn
        return Claim(transaction_id=uuid4())

    def mark_pending(self, transaction_id, terminal_id):
        pass

    def finish(self, transaction_id, terminal_id, result, status, error, store_response):
        self.finished.append({"status": status, "stored": store_response})
        return {"transaction_id": f"txn_{transaction_id.hex}", "status": status}


class _Auth:
    def authorize(self, terminal_id, method, amount):
        return SimpleNamespace(reason=None, profile=None)


def test_the_engine_routes_qr_and_records_the_encoded_rail():
    repo = _Repo()
    upi = FakeUpi()
    service = TransactionService(repo, _Auth(), MethodRegistry([QrMethodAdapter(MethodRegistry([upi]))]))
    body = {"idempotency_key": str(uuid4()), "amount": 1500, "currency": "INR", "payment_method": "QR",
            "method_details": {"qr_data": UPI_QR}, "terminal_id": str(TERMINAL), "merchant_id": str(MERCHANT)}

    response = service.create(TERMINAL, body)

    assert response["status"] == "PENDING"
    assert repo.txn.payment_method == "QR"          # what the merchant asked for
    assert repo.txn.qr_encoded_rail == "UPI"        # what actually moved the money
    assert repo.finished[0]["stored"] is True
