"""The payment method adapter contract (Stage 1, Step 8).

The transaction engine knows one thing about payment methods: they are looked up by name, and they all answer
the same six calls. Card logic lives in the card adapter; UPI (Step 10) will be a file of its own. Adding a
method must never mean editing `TransactionService` — that is the whole point of this module.

Adapters translate a network's vocabulary (ISO 8583 response codes, a UPI PSP's JSON) into `MethodResult` and
the four shared errors below. The engine maps those onto transaction states and HTTP responses, and knows
nothing about acquirers, VPAs or ISO 8583.

The contract is a `Protocol`, not an ABC: adapters stay structurally typed, tests can pass plain objects, and
nothing has to inherit from a base class to participate.
"""
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from app.application.registration import RegistrationError


class MethodNotSupported(RegistrationError):
    """No adapter is registered for this payment_method. A 422: the request is fine, the method isn't offered."""
    code = "INVALID_REQUEST"


class InvalidMethodDetails(RegistrationError):
    """method_details doesn't match what this adapter needs — a card without encrypted_card_data, a UPI
    payment without a VPA. A 400 naming the offending field, never the value."""
    code = "INVALID_REQUEST"


class AdapterUnavailable(RegistrationError):
    """The network behind the adapter could not be reached, so nothing was sent. Retryable: nothing moved."""
    code = "INTERNAL_ERROR"


class UnsupportedOperation(RegistrationError):
    """The adapter cannot do this yet (CARD capture/refund/status until Step 11 builds them)."""
    code = "INVALID_REQUEST"


class OutcomeUnknown(Exception):
    """Sent, and no answer came back: the network may have acted on it. Not an error to the client — the
    transaction becomes PENDING and reconciliation settles it. Deliberately not a RegistrationError, so it can
    never be rendered as a client-facing failure."""


@dataclass(frozen=True)
class MethodRequest:
    """Everything an adapter may need. Method-specific data is in `details`, already validated."""

    transaction_id: UUID
    amount: int
    currency: str
    capture_mode: str  # AUTO captures in one step; MANUAL authorizes only
    merchant_id: UUID
    terminal_id: UUID
    details: dict
    customer_ref: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class MethodResult:
    """What an adapter reports back. `status` is a TransactionStatus; `error` is the spec's Error or None."""

    status: str
    method_reference: str | None = None  # the network's id (RRN, UPI transaction id) for support and reconciliation
    auth_code: str | None = None
    error: dict | None = None
    reversal: str = "NOT_NEEDED"
    bin: str | None = None  # instrument display data, when the method has an instrument
    last4: str | None = None

    @property
    def retryable(self) -> bool:
        return bool(self.error and self.error.get("retryable"))


class PaymentMethodAdapter(Protocol):
    """The contract every method implements. The engine calls nothing else on an adapter."""

    method: str  # the payment_method value this adapter serves, e.g. "CARD"

    def validate(self, details: dict) -> dict:
        """Return normalised method_details, or raise InvalidMethodDetails."""

    def initiate(self, request: MethodRequest) -> MethodResult:
        """Start the payment.

        Raises AdapterUnavailable (not sent), InvalidMethodDetails (rejected before sending) or OutcomeUnknown
        (sent, no answer).
        """

    def capture(self, transaction_id: UUID, amount: int) -> MethodResult:
        """Capture a previously authorized payment. Raise UnsupportedOperation if the method cannot."""

    def refund(self, transaction_id: UUID, amount: int) -> MethodResult:
        """Refund all or part of a payment."""

    def status(self, transaction_id: UUID) -> MethodResult:
        """Ask the network for the authoritative status (reconciliation, stuck payments)."""

    def handle_webhook(self, payload: dict) -> MethodResult:
        """Parse an asynchronous callback and return the state it moves the transaction to. Essential for
        UPI and wallets, which answer the API before the network settles."""


class MethodRegistry:
    """method name → adapter. The only lookup the engine performs; an unknown method is a clean 422."""

    def __init__(self, adapters):
        self._adapters: dict[str, PaymentMethodAdapter] = {}
        for adapter in adapters:
            if adapter.method in self._adapters:
                raise ValueError(f"two adapters registered for {adapter.method}")
            self._adapters[adapter.method] = adapter

    def for_method(self, method: str) -> PaymentMethodAdapter:
        adapter = self._adapters.get(method)
        if adapter is None:
            supported = ", ".join(sorted(self._adapters)) or "none"
            raise MethodNotSupported(f"{method} isn't supported yet; supported: {supported}")
        return adapter

    def methods(self) -> list[str]:
        return sorted(self._adapters)

    def __contains__(self, method: str) -> bool:
        return method in self._adapters
