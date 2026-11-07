"""The card adapter: the only code that knows about encrypted card data, acquirers and ISO 8583.

It is a translation layer, not a new implementation. Everything below already existed inside
`TransactionService.create`; moving it here is what lets UPI be added without touching the engine.
"""
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.application.methods import (AdapterUnavailable, CapabilityDescriptor, DisputeRules, InvalidMethodDetails,
                                     MethodRequest, MethodResult, OutcomeUnknown, Transition, UnsupportedOperation)
from app.application.transactions import (BadCardData, CardOutcomeUnknown, CardProcessor, CardRequest,
                                          CardServiceUnavailable)


# The spec's CardCapabilities example, as code. Card present is synchronous, settles T+1, and is the only rail
# in v1 with chargebacks — which is exactly what dispute management needs to know without asking a card expert.
CARD_CAPABILITIES = CapabilityDescriptor(
    payment_method="CARD",
    supports_chargeback=True,
    supports_recurring=True,
    supports_offline=True,  # the edge node accepts cards while the link is down
    supports_refund=True,
    supports_partial_refund=True,
    supports_partial_capture=True,
    settlement_timeline="T+1",
    auth_type="issuer_authorization",
    dispute_rules=DisputeRules(framework="CARD_SCHEME", dispute_window_days=120, resolution_timeline_days=45),
    transitions=(
        Transition("INITIATED", "PENDING"),
        Transition("PENDING", "AUTHORIZED"),
        Transition("PENDING", "FAILED"),
        Transition("AUTHORIZED", "CAPTURED"),
        Transition("AUTHORIZED", "VOIDED"),
        Transition("CAPTURED", "SETTLED"),
        Transition("CAPTURED", "REFUNDED"),
        Transition("CAPTURED", "PARTIALLY_REFUNDED"),
        Transition("SETTLED", "REFUNDED"),
        Transition("SETTLED", "PARTIALLY_REFUNDED"),
        Transition("PARTIALLY_REFUNDED", "PARTIALLY_REFUNDED"),
        Transition("PARTIALLY_REFUNDED", "REFUNDED"),
    ),
)


class CardDetails(BaseModel):
    """method_details for CARD. `extra=forbid` so a typo in a client's field name is an error, not a silent no-op."""

    model_config = ConfigDict(extra="forbid")

    encrypted_card_data: str = Field(min_length=1, max_length=4096)
    card_expiry: str = Field(pattern=r"^(0[1-9]|1[0-2])/[0-9]{2}$")
    cardholder_name: str | None = Field(default=None, max_length=128)
    card_network: Literal["VISA", "MASTERCARD", "RUPAY", "AMEX"]
    pin_block: str | None = Field(default=None, min_length=1, max_length=512)


def acquirer_ids(terminal_id: UUID, merchant_id: UUID) -> tuple[str, str]:
    """The terminal ID (DE 41, 8 chars) and merchant ID (DE 42, 15 chars) the acquirer knows them by.

    shortcut: derived from the registry UUIDs. Acquirers assign these at merchant onboarding; store them on the
    terminal and merchant records when the first real acquirer is integrated.
    """
    return terminal_id.hex[:8].upper(), merchant_id.hex[:15].upper()


class CardMethodAdapter:
    method = "CARD"

    def __init__(self, processor: CardProcessor):
        self.processor = processor

    def capabilities(self) -> CapabilityDescriptor:
        return CARD_CAPABILITIES

    def validate(self, details: dict) -> dict:
        """Field paths and reasons only: never echo the values back, they are card data."""
        try:
            return CardDetails.model_validate(details).model_dump(exclude_none=True)
        except ValidationError as exc:
            raise InvalidMethodDetails("; ".join(
                f"method_details.{'.'.join(map(str, error['loc']))}: {error['msg']}"
                for error in exc.errors())) from exc

    def initiate(self, request: MethodRequest) -> MethodResult:
        terminal, merchant = acquirer_ids(request.terminal_id, request.merchant_id)
        card = CardRequest(
            transaction_id=request.transaction_id,
            kind="PURCHASE" if request.capture_mode == "AUTO" else "AUTHORIZATION",
            amount=request.amount, currency=request.currency,
            acquirer_terminal_id=terminal, acquirer_merchant_id=merchant,
            encrypted_card_data=request.details["encrypted_card_data"],
            card_expiry=request.details["card_expiry"],
            pin_block=request.details.get("pin_block"))
        try:
            result = self.processor.process(card)
        except CardServiceUnavailable as exc:
            raise AdapterUnavailable(exc.message) from exc
        except BadCardData as exc:
            raise InvalidMethodDetails(exc.message) from exc
        except CardOutcomeUnknown as exc:
            raise OutcomeUnknown() from exc
        return MethodResult(status=result.status, method_reference=result.method_reference,
                            auth_code=result.auth_code, error=result.error, reversal=result.reversal,
                            bin=result.card_bin, last4=result.card_last4)

    # The contract has six calls; CARD can only do what Step 5 built. Being explicit beats a silent None.
    def capture(self, transaction_id: UUID, amount: int) -> MethodResult:
        raise UnsupportedOperation("capture isn't implemented for CARD yet")

    def refund(self, transaction_id: UUID, amount: int) -> MethodResult:
        raise UnsupportedOperation("refund isn't implemented for CARD yet")

    def status(self, transaction_id: UUID) -> MethodResult:
        raise UnsupportedOperation("status lookups aren't implemented for CARD yet")

    def handle_webhook(self, payload: dict) -> MethodResult:
        raise UnsupportedOperation("CARD has no asynchronous webhook; the acquirer answers in-line")
