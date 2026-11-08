"""The capability descriptor (Task 8.2): what each rail can do, and the engine refusing impossible work."""
import time
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import capabilities as capabilities_api
from app.api import errors as errors_module
from app.application.methods import (CapabilityDescriptor, CapabilityNotSupported, DisputeRules, MethodRegistry,
                                     MethodResult, Transition, UnsupportedOperation)
from app.application.transactions import CardResult
from app.infrastructure.methods.card import CARD_CAPABILITIES, CardMethodAdapter

PEM = serialization.Encoding.PEM


class _Processor:
    def process(self, request):
        return CardResult("AUTHORIZED", None, None, None, "NOT_NEEDED", "411111", "1111")


def _capabilities(method="UPI", **overrides) -> CapabilityDescriptor:
    base = dict(
        payment_method=method, supports_chargeback=False, supports_recurring=False, supports_offline=False,
        supports_refund=True, supports_partial_refund=False, supports_partial_capture=False,
        settlement_timeline="instant", auth_type="vpa_collect", is_synchronous=False,
        dispute_rules=DisputeRules("NPCI_UPI", 30, 30),
        transitions=(Transition("PENDING", "SETTLED"),))
    return CapabilityDescriptor(**{**base, **overrides})


class _StubAdapter:
    def __init__(self, method="UPI", caps=None):
        self.method = method
        self._caps = caps or _capabilities(method)
        self.calls = []

    def capabilities(self):
        return self._caps

    def validate(self, details):
        return details

    def initiate(self, request):
        self.calls.append("initiate")
        return MethodResult(status="SETTLED")

    def capture(self, transaction_id, amount):
        self.calls.append("capture")
        raise UnsupportedOperation("no")

    def refund(self, transaction_id, amount):
        self.calls.append("refund")
        raise UnsupportedOperation("no")

    def status(self, transaction_id):
        self.calls.append("status")
        raise UnsupportedOperation("no")

    def handle_webhook(self, payload):
        self.calls.append("handle_webhook")
        raise UnsupportedOperation("no")


# --- the card descriptor matches the frozen contract ----------------------------------------------------

def test_card_capabilities_match_the_spec_example():
    assert CARD_CAPABILITIES.to_dict() == {
        "payment_method": "CARD",
        "supports_chargeback": True,
        "supports_recurring": True,
        "supports_offline": True,
        "supports_refund": False,  # PR 4: until card-service can send refunds and completions
        "supports_partial_refund": False,
        "supports_partial_capture": False,
        "settlement_timeline": "T+1",
        "auth_type": "issuer_authorization",
        "is_synchronous": True,
        "dispute_rules": {"framework": "CARD_SCHEME", "dispute_window_days": 120,
                          "resolution_timeline_days": 45},
        "transitions": [
            {"from": "INITIATED", "to": "PENDING"},
            {"from": "PENDING", "to": "AUTHORIZED"},
            {"from": "PENDING", "to": "FAILED"},
            {"from": "AUTHORIZED", "to": "CAPTURED"},
            {"from": "AUTHORIZED", "to": "VOIDED"},
            {"from": "CAPTURED", "to": "SETTLED"},
        ],
    }


def test_dispute_rules_omit_an_absent_resolution_timeline():
    descriptor = _capabilities(dispute_rules=DisputeRules("NONE", 0))
    assert descriptor.to_dict()["dispute_rules"] == {"framework": "NONE", "dispute_window_days": 0}


def test_supports_accepts_bare_and_prefixed_names():
    caps = _capabilities(supports_partial_refund=True)
    assert caps.supports("partial_refund") and caps.supports("supports_partial_refund")
    assert not caps.supports("chargeback")
    with pytest.raises(ValueError):
        caps.supports("teleportation")


# --- the engine refuses impossible work without calling the adapter -------------------------------------

def test_partial_refund_on_a_rail_without_it_never_reaches_the_adapter():
    """The task's example: UPI has no partial refunds, so the decision is made from the descriptor."""
    upi = _StubAdapter("UPI", _capabilities(supports_refund=True, supports_partial_refund=False))
    registry = MethodRegistry([upi])

    with pytest.raises(CapabilityNotSupported) as raised:
        registry.require("UPI", "partial_refund")

    assert "UPI doesn't support partial refund" in raised.value.message
    assert upi.calls == []  # the adapter was never asked


def test_chargeback_is_refused_on_a_rail_without_chargebacks():
    registry = MethodRegistry([_StubAdapter("UPI")])
    with pytest.raises(CapabilityNotSupported):
        registry.require("UPI", "chargeback")


def test_a_supported_capability_returns_the_adapter():
    upi = _StubAdapter("UPI", _capabilities(supports_refund=True))
    assert MethodRegistry([upi]).require("UPI", "refund") is upi


def test_require_on_an_unknown_method_is_still_422():
    from app.application.methods import MethodNotSupported
    with pytest.raises(MethodNotSupported):
        MethodRegistry([_StubAdapter("UPI")]).require("WALLET", "refund")


# --- the endpoint the spec has always described ---------------------------------------------------------

@pytest.fixture
def caps_client():
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    app = FastAPI()
    app.state.methods = MethodRegistry([CardMethodAdapter(_Processor()), _StubAdapter("UPI")])
    app.state.jwt_public_key = public
    errors_module.install(app)
    app.include_router(capabilities_api.router)
    return TestClient(app), key


def _token(key, scope="transactions:read"):
    return {"Authorization": "Bearer " + jwt.encode(
        {"sub": str(uuid4()), "scope": scope, "exp": int(time.time()) + 300}, key, "ES256")}


def test_capabilities_endpoint_serves_the_card_descriptor(caps_client):
    client, key = caps_client
    r = client.get("/api/v1/capabilities/CARD", headers=_token(key))
    assert r.status_code == 200, r.text
    assert r.json() == CARD_CAPABILITIES.to_dict()


def test_capabilities_for_upi(caps_client):
    client, key = caps_client
    body = client.get("/api/v1/capabilities/UPI", headers=_token(key)).json()
    assert body["settlement_timeline"] == "instant" and body["supports_chargeback"] is False


def test_capabilities_rejects_an_unknown_method_with_400(caps_client):
    client, key = caps_client
    r = client.get("/api/v1/capabilities/WALLET", headers=_token(key))
    assert r.status_code == 400
    assert r.json()["error_code"] == "INVALID_REQUEST"
    assert "WALLET isn't supported yet" in r.json()["error_message"]


def test_capabilities_needs_a_credential(caps_client):
    client, _ = caps_client
    assert client.get("/api/v1/capabilities/CARD").status_code == 401


def test_capabilities_needs_the_transactions_read_scope(caps_client):
    client, key = caps_client
    r = client.get("/api/v1/capabilities/CARD", headers=_token(key, scope="registry:read"))
    assert r.status_code == 403


def test_a_terminal_reads_capabilities_over_mtls(caps_client):
    """The spec allows MutualTLS here; the gateway forwards the certificate's terminal id as a header."""
    client, _ = caps_client
    r = client.get("/api/v1/capabilities/CARD", headers={"x-terminal-id": str(uuid4())})
    assert r.status_code == 200
