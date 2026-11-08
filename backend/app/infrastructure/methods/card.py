"""The card adapter: the only code that knows about encrypted card data, acquirers and ISO 8583.

It is a translation layer, not a new implementation. Everything below already existed inside
`TransactionService.create`; moving it here is what lets UPI be added without touching the engine. Since Step
8.3 it only implements `send()` — validation, error translation and the unbuilt calls come from the base.
"""
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.application.methods import (AdapterUnavailable, CapabilityDescriptor, DisputeRules, InvalidMethodDetails,
                                     MethodRequest, MethodResult, OutcomeUnknown, Transition)
from app.application.transactions import (BadCardData, CardOutcomeUnknown, CardProcessor, CardRequest,
                                          CardServiceUnavailable)
from app.infrastructure.methods.base import BaseMethodAdapter


class CardDetails(BaseModel):
    """method_details for CARD. `extra=forbid` so a typo in a client's field name is an error, not a silent no-op."""

    model_config = ConfigDict(extra="forbid")

    encrypted_card_data: str | None = Field(default=None, min_length=1, max_length=4096)
    # Step 29 (spec 1.12.0): a card the merchant saved, instead of encrypted_card_data.
    card_token: str | None = Field(default=None, pattern=r"^tok_[0-9a-f]{32}$")
    card_expiry: str | None = Field(default=None, pattern=r"^(0[1-9]|1[0-2])/[0-9]{2}$")
    cardholder_name: str | None = Field(default=None, max_length=128)
    card_network: Literal["VISA", "MASTERCARD", "RUPAY", "AMEX"]
    pin_block: str | None = Field(default=None, min_length=1, max_length=512)
    # Chip and contactless (spec 1.11.0): the chip's EMV data as uppercase hex BER-TLV, sent as DE 55.
    emv_data: str | None = Field(default=None, pattern=r"^(?:[0-9A-F]{2}){1,255}$")

    @model_validator(mode="after")
    def _one_card(self):
        if (self.encrypted_card_data is None) == (self.card_token is None):
            raise ValueError("give exactly one of method_details.encrypted_card_data or method_details.card_token")
        if self.encrypted_card_data is not None and self.card_expiry is None:
            raise ValueError("method_details.card_expiry is required with method_details.encrypted_card_data")
        return self


def acquirer_ids(terminal_id: UUID, merchant_id: UUID) -> tuple[str, str]:
    """The terminal ID (DE 41, 8 chars) and merchant ID (DE 42, 15 chars) the acquirer knows them by.

    shortcut: derived from the registry UUIDs. Acquirers assign these at merchant onboarding; store them on the
    terminal and merchant records when the first real acquirer is integrated.
    """
    return terminal_id.hex[:8].upper(), merchant_id.hex[:15].upper()


# The spec's CardCapabilities example, as code. Card present is synchronous, settles T+1, and is the only rail
# in v1 with chargebacks — which is exactly what dispute management needs to know without asking a card expert.
CARD_CAPABILITIES = CapabilityDescriptor(
    payment_method="CARD",
    supports_chargeback=True,
    supports_recurring=True,
    supports_offline=True,  # the edge node accepts cards while the link is down
    # PR 4: false until card-service can send them (ISO 8583 refund and completion); the descriptor must not promise
    # what the API can't do.
    supports_refund=False,
    supports_partial_refund=False,
    supports_partial_capture=False,
    settlement_timeline="T+1",
    auth_type="issuer_authorization",
    is_synchronous=True,  # the issuer authorizes in-line: the API answers AUTHORIZED, not PENDING
    dispute_rules=DisputeRules(framework="CARD_SCHEME", dispute_window_days=120, resolution_timeline_days=45),
    transitions=(
        Transition("INITIATED", "PENDING"),
        Transition("PENDING", "AUTHORIZED"),
        Transition("PENDING", "FAILED"),
        Transition("AUTHORIZED", "CAPTURED"),
        Transition("AUTHORIZED", "VOIDED"),
        Transition("CAPTURED", "SETTLED"),
        # Refund transitions return with card refunds (card-service follow-up to PR 4).
    ),
)


class CardMethodAdapter(BaseMethodAdapter):
    method = "CARD"
    CAPABILITIES = CARD_CAPABILITIES
    DETAILS = CardDetails
    # The card service owns one pool per acquirer, so a hint sent here actually picks the host on the wire.
    SUPPORTS_HOST_ROUTING = True
    # The card service's vocabulary, translated once. Everything else falls through to AdapterUnavailable.
    ERROR_MAP = {
        CardServiceUnavailable: lambda exc: AdapterUnavailable(exc.message),
        BadCardData: lambda exc: InvalidMethodDetails(exc.message),
        CardOutcomeUnknown: lambda exc: OutcomeUnknown(),
    }

    def __init__(self, processor: CardProcessor):
        self.processor = processor

    def send(self, request: MethodRequest) -> MethodResult:
        terminal, merchant = acquirer_ids(request.terminal_id, request.merchant_id)
        card = CardRequest(
            transaction_id=request.transaction_id,
            kind="PURCHASE" if request.capture_mode == "AUTO" else "AUTHORIZATION",
            amount=request.amount, currency=request.currency,
            acquirer_terminal_id=terminal, acquirer_merchant_id=merchant,
            encrypted_card_data=request.details.get("encrypted_card_data") or "",
            card_expiry=request.details.get("card_expiry") or "",
            card_token=request.details.get("card_token"), merchant_id=str(request.merchant_id),
            pin_block=request.details.get("pin_block"), emv_data=request.details.get("emv_data"),
            host_hint=list(request.host_hint), trace_id=request.trace_id)
        result = self.processor.process(card)
        return MethodResult(status=result.status, method_reference=result.method_reference,
                            auth_code=result.auth_code, error=result.error, reversal=result.reversal,
                            bin=result.card_bin, last4=result.card_last4, host_used=result.host_used)
