"""The UPI adapter (Stage 1, Step 10A): HTTP/REST against a PSP, asynchronous by nature.

The shape of a UPI payment is what forces the contract's `is_synchronous: false`: a collect is answered
PENDING, the customer approves in their own app, and the PSP tells us later. So `send()` returns PENDING with
the PSP's reference, and the outcome arrives through a webhook (Step 10B) or the polling fallback (this step).

Status and refund need the PSP reference the engine stored with the transaction, which is why the contract
gives those two calls an optional `reference` — adapters are stateless and cannot look it up themselves.

Declines are results, not exceptions: a PSP 4xx is an answer ("no"), and the engine needs its error_category
to route. Exceptions are reserved for "we could not ask", which the base class turns into a retryable
AdapterUnavailable.
"""
import hashlib
import hmac
import json
import time
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.application.methods import (AdapterUnavailable, CapabilityDescriptor, DisputeRules, InvalidMethodDetails,
                                     MethodRequest, MethodResult, Transition, UnsupportedOperation, WebhookRejected,
                                     WebhookRequest, WebhookUpdate)
from app.infrastructure.methods.base import BaseMethodAdapter
from app.infrastructure.upi_client import PspDeclined, PspUnavailable

REPLAY_WINDOW_SECONDS = 300

UPI_CAPABILITIES = CapabilityDescriptor(
    payment_method="UPI",
    supports_chargeback=False,  # disputes go through NPCI's grievance framework, not card chargebacks
    supports_recurring=True,  # e-mandates
    supports_offline=False,
    supports_refund=True,
    supports_partial_refund=True,
    supports_partial_capture=False,
    settlement_timeline="instant",
    auth_type="vpa_collect",
    is_synchronous=False,  # answered PENDING; the customer approves in their own app
    dispute_rules=DisputeRules(framework="NPCI_UPI", dispute_window_days=30, resolution_timeline_days=30),
    transitions=(
        Transition("INITIATED", "PENDING"),
        Transition("PENDING", "SETTLED"),
        Transition("PENDING", "FAILED"),
        Transition("SETTLED", "REFUNDED"),
        Transition("SETTLED", "PARTIALLY_REFUNDED"),
        Transition("PARTIALLY_REFUNDED", "PARTIALLY_REFUNDED"),
        Transition("PARTIALLY_REFUNDED", "REFUNDED"),
    ),
)


class UpiPsp(Protocol):
    """What the adapter needs from a PSP. `HttpUpiPsp` implements it; tests pass a plain object."""

    def validate_vpa(self, vpa: str) -> dict: ...
    def collect(self, merchant_transaction_id: str, amount: int, currency: str, vpa: str,
                flow_type: str = "COLLECT") -> dict: ...
    def status(self, psp_transaction_id: str) -> dict: ...
    def refund(self, psp_transaction_id: str, amount: int) -> dict: ...


class UpiDetails(BaseModel):
    """method_details for UPI, matching the contract's UpiDetails."""

    model_config = ConfigDict(extra="forbid")

    vpa: str = Field(pattern=r"^[A-Za-z0-9._-]+@[A-Za-z0-9]+$", max_length=255)
    flow_type: Literal["COLLECT", "INTENT", "MANDATE"]
    mandate_details: dict | None = None


def _failure(code: str, message: str, category: str, retryable: bool) -> MethodResult:
    return MethodResult(status="FAILED", error={
        "error_code": code, "error_message": message, "error_category": category, "retryable": retryable})


def _status_result(reply: dict) -> MethodResult:
    """PSP status → transaction status. PENDING is a real answer here, not a timeout."""
    state = reply.get("status")
    reference = reply.get("psp_transaction_id")
    if state == "SUCCESS":
        return MethodResult(status="SETTLED", method_reference=reference, auth_code=reply.get("rrn"))
    if state == "FAILURE":
        reason = reply.get("reason") or "the PSP reported a failure"
        return MethodResult(status="FAILED", method_reference=reference,
                            error={"error_code": "UPI_DECLINED", "error_message": reason,
                                   "error_category": "HARD_DECLINE", "retryable": False})
    return MethodResult(status="PENDING", method_reference=reference)


class UpiMethodAdapter(BaseMethodAdapter):
    method = "UPI"
    CAPABILITIES = UPI_CAPABILITIES
    DETAILS = UpiDetails
    ERROR_MAP = {PspUnavailable: lambda exc: AdapterUnavailable(exc.message)}

    def __init__(self, psp: UpiPsp, webhook_secret: str | None = None, clock=time.time,
                 replay_window: int = REPLAY_WINDOW_SECONDS):
        self.psp = psp
        self.webhook_secret = webhook_secret
        self.clock = clock  # injectable so the replay window can be tested without sleeping
        self.replay_window = replay_window

    def validate(self, details: dict) -> dict:
        clean = super().validate(details)
        mandate = clean.get("mandate_details")
        if clean["flow_type"] == "MANDATE" and not mandate:
            raise InvalidMethodDetails("method_details.mandate_details: required when flow_type is MANDATE")
        if clean["flow_type"] != "MANDATE" and mandate is not None:
            raise InvalidMethodDetails("method_details.mandate_details: only allowed when flow_type is MANDATE")
        return clean

    def validate_vpa(self, vpa: str) -> str:
        """The registered payee name, for the merchant to display. Raises PspDeclined if there is no account."""
        return str(self.psp.validate_vpa(vpa)["name"])

    def send(self, request: MethodRequest) -> MethodResult:
        details = request.details
        if details["flow_type"] != "COLLECT":
            raise UnsupportedOperation(f"the {details['flow_type']} flow isn't implemented yet; COLLECT is")
        try:
            reply = self.psp.collect(
                merchant_transaction_id=str(request.transaction_id), amount=request.amount,
                currency=request.currency, vpa=details["vpa"], flow_type=details["flow_type"])
        except PspDeclined as declined:
            return _failure(declined.code, declined.message, declined.category, declined.retryable)
        # The PSP has the request; the customer has not approved it yet. PENDING is the correct answer.
        return MethodResult(status="PENDING", method_reference=reply["psp_transaction_id"])

    def status(self, transaction_id: UUID, reference: str | None = None) -> MethodResult:
        if not reference:
            raise UnsupportedOperation("UPI status needs the PSP reference stored with the transaction")
        try:
            return _status_result(self.psp.status(reference))
        except PspDeclined as declined:
            return _failure(declined.code, declined.message, declined.category, declined.retryable)

    def refund(self, transaction_id: UUID, amount: int, reference: str | None = None) -> MethodResult:
        if not reference:
            raise UnsupportedOperation("UPI refund needs the PSP reference stored with the transaction")
        try:
            reply = self.psp.refund(reference, amount)
        except PspDeclined as declined:
            return _failure(declined.code, declined.message, declined.category, declined.retryable)
        return MethodResult(status="REFUNDED", method_reference=reply.get("refund_id", reference))

    # --- 10B: inbound webhook ---------------------------------------------------------------------------

    def handle_webhook(self, request: WebhookRequest) -> WebhookUpdate:
        """Verify the PSP's signature and timestamp, then normalise. Never touches the database.

        The signature covers "<timestamp>.<raw body>", not the body alone. A body-only signature can be
        replayed by pairing a captured signature with a fresh timestamp header; binding the two means the
        whole thing falls outside the window together.
        """
        self._verify(request)
        try:
            body = json.loads(request.raw or b"{}")
        except ValueError:
            raise WebhookRejected(400, "INVALID_JSON", "body is not JSON") from None
        if not isinstance(body, dict):
            raise WebhookRejected(400, "INVALID_JSON", "body must be a JSON object")

        event_id = str(body.get("event_id") or "")
        psp_id = str(body.get("psp_transaction_id") or "")
        state = body.get("status")
        if not event_id or not psp_id or state not in ("SUCCESS", "FAILURE"):
            raise WebhookRejected(400, "INVALID_PAYLOAD",
                                  "event_id, psp_transaction_id and a known status are required")
        return WebhookUpdate(event_id=event_id, result=_status_result({
            "psp_transaction_id": psp_id, "status": state, "reason": body.get("reason"), "rrn": body.get("rrn")}))

    def _verify(self, request: WebhookRequest) -> None:
        from app.infrastructure.webhook_signature import verify_signature
        verify_signature(request.raw, request.headers, self.webhook_secret,
                         timestamp_header="X-UPI-Timestamp", signature_header="X-UPI-Signature",
                         label="UPI", now=self.clock, window=self.replay_window)
