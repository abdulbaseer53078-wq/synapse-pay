"""The QR adapter (Stage 1, Step 11): a router, not a rail.

A UPI QR is just a VPA in a URI; a Bharat QR is a card-network payload. There is no separate money movement
for QR, so there must be no separate implementation: this adapter parses the string, names the rail it encodes
(`qr_encoded_rail`), rewrites the request for that rail and delegates to that rail's adapter. Refunds, status,
webhooks and every error mapping then belong to the real rail, unchanged.

That is also why its CapabilityDescriptor is the contract's QR *fallback*: a QR payment encoded on a known rail
inherits that rail's descriptor (the spec says so), and this descriptor only describes the case where the rail
is UNKNOWN.
"""
import re
from typing import Literal
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, ConfigDict, Field

from app.application.methods import (CapabilityDescriptor, DisputeRules, InvalidMethodDetails, MethodRegistry,
                                     MethodRequest, MethodResult, Transition, UnsupportedOperation)
from app.infrastructure.methods.base import BaseMethodAdapter

# upi://pay?pa=asha@okhdfcbank&pn=Asha&am=15.00&cu=INR&tn=chai
UPI_QR = re.compile(r"^upi://pay\?", re.IGNORECASE)
BHARAT_QR = re.compile(r"^bharatqr://", re.IGNORECASE)
VPA = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9]+$")

QR_CAPABILITIES = CapabilityDescriptor(
    payment_method="QR",
    supports_chargeback=False,
    supports_recurring=False,
    supports_offline=False,
    supports_refund=False,  # the fallback descriptor; a QR on a known rail follows that rail
    supports_partial_refund=False,
    supports_partial_capture=False,
    settlement_timeline="unknown",
    auth_type="unknown",
    is_synchronous=False,
    dispute_rules=DisputeRules(framework="NONE", dispute_window_days=0),
    transitions=(
        Transition("INITIATED", "PENDING"),
        Transition("PENDING", "SETTLED"),
        Transition("PENDING", "FAILED"),
    ),
)


class QrDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    qr_data: str = Field(min_length=1, max_length=2048)
    qr_standard: Literal["UPI_QR", "BHARAT_QR"] | None = None


def parse_qr(qr_data: str) -> dict:
    """Raw scanned string → {rail, vpa, payee_name, amount (minor units), note}.

    Raises InvalidMethodDetails for anything it cannot trust: a QR is attacker-controlled input the moment a
    camera reads it.
    """
    if BHARAT_QR.match(qr_data):
        # Bharat QR carries card-network tokens; the tokenised-card flow is Step 5B territory.
        raise UnsupportedOperation("Bharat QR needs tokenised card data; UPI QR is supported")
    if not UPI_QR.match(qr_data):
        raise InvalidMethodDetails("method_details.qr_data: not a upi://pay URI")

    parsed = urlparse(qr_data)
    params = {key: values[0] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}

    vpa = params.get("pa", "")
    if not VPA.match(vpa):
        raise InvalidMethodDetails("method_details.qr_data: pa is missing or not a VPA")

    amount = None
    if params.get("am"):
        try:
            amount = int(round(float(params["am"]) * 100))  # rupees on the QR, minor units here
        except ValueError:
            raise InvalidMethodDetails("method_details.qr_data: am is not a number") from None
        if amount <= 0:
            raise InvalidMethodDetails("method_details.qr_data: am must be positive")

    currency = params.get("cu", "INR").upper()
    if currency != "INR":
        raise InvalidMethodDetails("method_details.qr_data: only INR UPI QRs are supported")

    return {"rail": "UPI", "vpa": vpa, "payee_name": params.get("pn"), "amount": amount,
            "note": params.get("tn"), "currency": currency}


def generate_qr(payee_vpa: str, payee_name: str, amount: int, note: str | None = None,
                reference: str | None = None) -> str:
    """The dynamic UPI intent string a merchant displays (or deep-links into a UPI app).

    Dynamic matters: a static QR leaves the amount to the payer, which is exactly the tampering a fixed amount
    prevents. The same string works as `upi://pay?...` for a deep link on a phone.
    """
    from urllib.parse import quote

    query = [f"pa={quote(payee_vpa)}", f"pn={quote(payee_name)}", f"am={amount / 100:.2f}", "cu=INR"]
    if note:
        query.append(f"tn={quote(note)}")
    if reference:
        query.append(f"tr={quote(reference)}")
    return "upi://pay?" + "&".join(query)


class QrMethodAdapter(BaseMethodAdapter):
    method = "QR"
    CAPABILITIES = QR_CAPABILITIES
    DETAILS = QrDetails

    def __init__(self, methods: MethodRegistry):
        self.methods = methods  # the rails this router may dispatch to

    def validate(self, details: dict) -> dict:
        clean = super().validate(details)
        parsed = parse_qr(clean["qr_data"])
        # Normalised details carry the rail, so the engine can persist it and the audit trail can name it.
        return {**clean, "qr_encoded_rail": parsed["rail"], "vpa": parsed["vpa"],
                "payee_name": parsed["payee_name"], "qr_amount": parsed["amount"]}

    def send(self, request: MethodRequest) -> MethodResult:
        details = request.details
        # The amount baked into the QR must equal what is being charged: this is the anti-tampering check.
        if details.get("qr_amount") is not None and details["qr_amount"] != request.amount:
            raise InvalidMethodDetails(
                f"method_details.qr_data: the QR is for {details['qr_amount']} but the request is {request.amount}")

        rail = details["qr_encoded_rail"]
        adapter = self.methods.for_method(rail)  # dispatch: no rail-specific code lives here
        inner = MethodRequest(transaction_id=request.transaction_id, amount=request.amount,
                              currency=request.currency, capture_mode=request.capture_mode,
                              merchant_id=request.merchant_id, terminal_id=request.terminal_id,
                              details={"vpa": details["vpa"], "flow_type": "COLLECT"},
                              customer_ref=request.customer_ref, metadata=request.metadata)
        return adapter.initiate(inner)
