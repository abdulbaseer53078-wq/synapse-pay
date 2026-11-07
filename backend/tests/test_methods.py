"""The payment method adapter contract (Step 8): registry, card adapter, and the engine staying method-agnostic."""
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.application.methods import (AdapterUnavailable, InvalidMethodDetails, MethodNotSupported, MethodRegistry,
                                     MethodRequest, MethodResult, OutcomeUnknown, UnsupportedOperation)
from app.application.transactions import (BadCardData, CardOutcomeUnknown, CardResult, CardServiceUnavailable, Claim,
                                          IntentNotPayable, TransactionService)
from app.infrastructure.methods.card import CardMethodAdapter, CardDetails, acquirer_ids

TERMINAL, MERCHANT = uuid4(), uuid4()


# --- registry -------------------------------------------------------------------------------------------

class _Adapter:
    def __init__(self, method, result=None):
        self.method = method
        self.result = result or MethodResult(status="AUTHORIZED")
        self.initiated = []

    def validate(self, details):
        return details

    def initiate(self, request):
        self.initiated.append(request)
        return self.result

    def capture(self, transaction_id, amount):
        raise UnsupportedOperation("not here yet")

    def refund(self, transaction_id, amount):
        raise UnsupportedOperation("not here yet")

    def status(self, transaction_id):
        raise UnsupportedOperation("not here yet")

    def handle_webhook(self, payload):
        raise UnsupportedOperation("not here yet")


def test_registry_looks_up_by_method_name():
    registry = MethodRegistry([_Adapter("CARD"), _Adapter("UPI")])
    assert registry.for_method("UPI").method == "UPI"
    assert registry.methods() == ["CARD", "UPI"]
    assert "CARD" in registry and "WALLET" not in registry


def test_unknown_method_is_a_clean_422_not_a_crash():
    registry = MethodRegistry([_Adapter("CARD")])
    with pytest.raises(MethodNotSupported) as raised:
        registry.for_method("WALLET")
    assert "WALLET isn't supported yet" in raised.value.message
    assert "CARD" in raised.value.message


def test_two_adapters_for_one_method_is_a_startup_error():
    with pytest.raises(ValueError, match="two adapters"):
        MethodRegistry([_Adapter("CARD"), _Adapter("CARD")])


# --- the engine is method-agnostic ----------------------------------------------------------------------

class _Repo:
    """Only the five calls TransactionService.create makes."""

    def __init__(self):
        self.claims = 0
        self.finished = []
        self.pending = False

    def terminal_merchant(self, terminal_id):
        return MERCHANT

    def spent_today(self, terminal_id, since):
        return 0

    def claim(self, txn):
        self.claims += 1
        return Claim(transaction_id=uuid4())

    def mark_pending(self, transaction_id, terminal_id):
        self.pending = True

    def finish(self, transaction_id, terminal_id, result, status, error, store_response):
        self.finished.append({"status": status, "error": error, "stored": store_response, "result": result})
        return {"transaction_id": f"txn_{transaction_id.hex}", "status": status}


class _Auth:
    def authorize(self, terminal_id, method, amount):
        return SimpleNamespace(reason=None, profile=None)


def _body(method: str, details: dict) -> dict:
    return {"idempotency_key": str(uuid4()), "amount": 49999, "currency": "INR",
            "payment_method": method, "method_details": details,
            "terminal_id": str(TERMINAL), "merchant_id": str(MERCHANT)}


def test_a_new_method_needs_no_engine_change():
    """The whole point of Step 8: register an adapter, and the engine processes it unchanged."""
    fake = _Adapter("UPI_LIKE", MethodResult(status="AUTHORIZED", method_reference="upi-123", auth_code="00"))
    repo = _Repo()
    service = TransactionService(repo, _Auth(), MethodRegistry([fake]))

    response = service.create(TERMINAL, _body("UPI_LIKE", {"vpa": "asha@okhdfc"}))

    assert response["status"] == "AUTHORIZED"
    assert repo.finished[0]["status"] == "AUTHORIZED"
    assert repo.finished[0]["stored"] is True
    assert repo.pending is True  # the engine marked it pending before handing over
    assert fake.initiated[0].details == {"vpa": "asha@okhdfc"}
    assert fake.initiated[0].amount == 49999


def test_unknown_method_never_reaches_the_repository():
    repo = _Repo()
    service = TransactionService(repo, _Auth(), MethodRegistry([_Adapter("CARD")]))
    with pytest.raises(MethodNotSupported):
        service.create(TERMINAL, _body("WALLET", {}))
    assert repo.claims == 0 and repo.finished == []


def test_unavailable_adapter_fails_retryable_and_frees_the_key():
    class Unavailable(_Adapter):
        def initiate(self, request):
            raise AdapterUnavailable("the network is unreachable; nothing was charged")

    repo = _Repo()
    service = TransactionService(repo, _Auth(), MethodRegistry([Unavailable("CARD")]))
    with pytest.raises(AdapterUnavailable):
        service.create(TERMINAL, _body("CARD", {}))

    finished = repo.finished[0]
    assert finished["status"] == "FAILED" and finished["stored"] is False  # not stored: the retry must run
    assert finished["error"]["retryable"] is True
    assert finished["error"]["error_message"] == "the network is unreachable; nothing was charged"


def test_unknown_outcome_returns_pending_and_is_stored():
    class Unknown(_Adapter):
        def initiate(self, request):
            raise OutcomeUnknown()

    repo = _Repo()
    service = TransactionService(repo, _Auth(), MethodRegistry([Unknown("CARD")]))
    response = service.create(TERMINAL, _body("CARD", {}))

    assert response["status"] == "PENDING"
    assert repo.finished[0]["stored"] is True  # a retry must not charge twice


def test_invalid_details_are_rejected_before_a_transaction_exists():
    """Validation runs before the idempotency claim, so a malformed body never leaves a row behind."""
    class Strict(_Adapter):
        def validate(self, details):
            raise InvalidMethodDetails("method_details.vpa: field required")

    repo = _Repo()
    service = TransactionService(repo, _Auth(), MethodRegistry([Strict("UPI")]))
    with pytest.raises(InvalidMethodDetails):
        service.create(TERMINAL, _body("UPI", {}))
    assert repo.claims == 0 and repo.finished == []


# --- the card adapter -----------------------------------------------------------------------------------

class _Processor:
    def __init__(self, result=None, raises=None):
        self.result, self.raises, self.requests = result, raises, []

    def process(self, request):
        self.requests.append(request)
        if self.raises:
            raise self.raises
        return self.result


VALID = {"encrypted_card_data": "ciphertext", "card_expiry": "12/29", "card_network": "VISA"}


def test_card_details_are_validated_with_field_paths():
    adapter = CardMethodAdapter(_Processor())
    with pytest.raises(InvalidMethodDetails) as raised:
        adapter.validate({"card_expiry": "12/29", "card_network": "VISA"})
    assert "method_details.encrypted_card_data" in raised.value.message
    assert "ciphertext" not in raised.value.message  # never echo card data


def test_card_details_reject_unknown_fields_and_bad_expiry():
    adapter = CardMethodAdapter(_Processor())
    with pytest.raises(InvalidMethodDetails):
        adapter.validate({**VALID, "card_number": "4111111111111111"})
    with pytest.raises(InvalidMethodDetails):
        adapter.validate({**VALID, "card_expiry": "13/29"})


def test_card_details_normalise_away_absent_optionals():
    adapter = CardMethodAdapter(_Processor())
    assert adapter.validate(VALID) == VALID
    assert "pin_block" not in adapter.validate(VALID)


def test_card_adapter_builds_the_acquirer_request():
    processor = _Processor(CardResult("AUTHORIZED", "rrn-1", "00", None, "NOT_NEEDED", "411111", "1111"))
    adapter = CardMethodAdapter(processor)

    result = adapter.initiate(MethodRequest(uuid4(), 49999, "INR", "AUTO", MERCHANT, TERMINAL, VALID))

    request = processor.requests[0]
    assert request.kind == "PURCHASE" and request.amount == 49999
    assert (request.acquirer_terminal_id, request.acquirer_merchant_id) == acquirer_ids(TERMINAL, MERCHANT)
    assert result.status == "AUTHORIZED" and result.method_reference == "rrn-1"
    assert (result.bin, result.last4) == ("411111", "1111")


def test_manual_capture_mode_authorizes_only():
    processor = _Processor(CardResult("AUTHORIZED", None, None, None, "NOT_NEEDED", "411111", "1111"))
    CardMethodAdapter(processor).initiate(
        MethodRequest(uuid4(), 100, "INR", "MANUAL", MERCHANT, TERMINAL, VALID))
    assert processor.requests[0].kind == "AUTHORIZATION"


@pytest.mark.parametrize("raised, expected", [
    (CardServiceUnavailable("card service down"), AdapterUnavailable),
    (BadCardData("bad ciphertext"), InvalidMethodDetails),
    (CardOutcomeUnknown(), OutcomeUnknown),
])
def test_card_failures_are_translated_to_the_shared_vocabulary(raised, expected):
    adapter = CardMethodAdapter(_Processor(raises=raised))
    with pytest.raises(expected):
        adapter.initiate(MethodRequest(uuid4(), 100, "INR", "AUTO", MERCHANT, TERMINAL, VALID))


@pytest.mark.parametrize("call", [
    lambda a: a.capture(uuid4(), 100),
    lambda a: a.refund(uuid4(), 100),
    lambda a: a.status(uuid4()),
    lambda a: a.handle_webhook({}),
])
def test_unbuilt_contract_calls_say_so(call):
    with pytest.raises(UnsupportedOperation):
        call(CardMethodAdapter(_Processor()))
