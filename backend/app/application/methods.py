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
from typing import Mapping, Protocol
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


class CapabilityNotSupported(RegistrationError):
    """The method exists but cannot do this: a partial refund on a rail that has none, a chargeback on UPI.
    The engine rejects it from the descriptor, without calling the adapter at all."""
    code = "INVALID_REQUEST"


class OutcomeUnknown(Exception):
    """Sent, and no answer came back: the network may have acted on it. Not an error to the client — the
    transaction becomes PENDING and reconciliation settles it. Deliberately not a RegistrationError, so it can
    never be rendered as a client-facing failure."""


class WebhookRejected(Exception):
    """An inbound callback failed verification. Carries the status the provider should see.

    Not a RegistrationError: it is not part of the merchant API's error contract, and it must never be
    rendered with the API's error taxonomy — a webhook caller is a network, not a merchant.
    """

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class WebhookRequest:
    """A callback exactly as it arrived.

    `raw` is the point: JSON parsing reorders keys and normalises whitespace, so a signature computed over a
    parsed-and-reserialised body will not match the one the provider signed. Adapters verify `raw`.
    """

    raw: bytes
    headers: Mapping[str, str]  # lower-cased keys


@dataclass(frozen=True)
class WebhookUpdate:
    """A verified callback: what the provider says happened, and the delivery id to deduplicate on."""

    event_id: str
    result: "MethodResult"


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
    # Present when the customer must finish elsewhere (wallet login, 3-D Secure): {"type", "url"}.
    next_action: dict | None = None

    @property
    def retryable(self) -> bool:
        return bool(self.error and self.error.get("retryable"))


@dataclass(frozen=True)
class DisputeRules:
    framework: str  # CARD_SCHEME | NPCI_UPI | NONE
    dispute_window_days: int
    resolution_timeline_days: int | None = None

    def to_dict(self) -> dict:
        body = {"framework": self.framework, "dispute_window_days": self.dispute_window_days}
        if self.resolution_timeline_days is not None:
            body["resolution_timeline_days"] = self.resolution_timeline_days
        return body


@dataclass(frozen=True)
class Transition:
    from_status: str
    to_status: str

    def to_dict(self) -> dict:
        return {"from": self.from_status, "to": self.to_status}


@dataclass(frozen=True)
class CapabilityDescriptor:
    """What a method can do (spec: CapabilityDescriptor). Static per method: the SDK caches it.

    Every downstream decision branches on these values instead of on the method name — dispute management
    reading supports_chargeback, refunds reading supports_partial_refund, the offline edge reading
    supports_offline. Adding a rail never adds a branch to those services.
    """

    payment_method: str
    supports_chargeback: bool
    supports_recurring: bool
    supports_offline: bool
    supports_refund: bool
    supports_partial_refund: bool
    supports_partial_capture: bool
    settlement_timeline: str
    auth_type: str
    is_synchronous: bool  # True: initiate() returns the final outcome. False: PENDING, settled by webhook.
    dispute_rules: DisputeRules
    transitions: tuple[Transition, ...]

    def supports(self, capability: str) -> bool:
        """`supports("partial_refund")` and `supports("supports_partial_refund")` both work."""
        name = capability if capability.startswith("supports_") else f"supports_{capability}"
        if name not in {"supports_chargeback", "supports_recurring", "supports_offline", "supports_refund",
                        "supports_partial_refund", "supports_partial_capture"}:
            raise ValueError(f"{capability} is not a capability")
        return bool(getattr(self, name))

    def to_dict(self) -> dict:
        return {
            "payment_method": self.payment_method,
            "supports_chargeback": self.supports_chargeback,
            "supports_recurring": self.supports_recurring,
            "supports_offline": self.supports_offline,
            "supports_refund": self.supports_refund,
            "supports_partial_refund": self.supports_partial_refund,
            "supports_partial_capture": self.supports_partial_capture,
            "settlement_timeline": self.settlement_timeline,
            "auth_type": self.auth_type,
            "is_synchronous": self.is_synchronous,
            "dispute_rules": self.dispute_rules.to_dict(),
            "transitions": [t.to_dict() for t in self.transitions],
        }


class PaymentMethodAdapter(Protocol):
    """The contract every method implements. The engine calls nothing else on an adapter."""

    method: str  # the payment_method value this adapter serves, e.g. "CARD"

    def capabilities(self) -> CapabilityDescriptor:
        """What this method can do. Static, so it is safe to call on every request."""

    def validate(self, details: dict) -> dict:
        """Return normalised method_details, or raise InvalidMethodDetails."""

    def initiate(self, request: MethodRequest) -> MethodResult:
        """Start the payment.

        Raises AdapterUnavailable (not sent), InvalidMethodDetails (rejected before sending) or OutcomeUnknown
        (sent, no answer).
        """

    def capture(self, transaction_id: UUID, amount: int) -> MethodResult:
        """Capture a previously authorized payment. Raise UnsupportedOperation if the method cannot."""

    def refund(self, transaction_id: UUID, amount: int, reference: str | None = None) -> MethodResult:
        """Refund all or part of a payment. `reference` is the network's id, as the engine stored it —
        adapters are stateless and cannot look it up."""

    def status(self, transaction_id: UUID, reference: str | None = None) -> MethodResult:
        """Ask the network for the authoritative status (reconciliation, stuck payments)."""

    def handle_webhook(self, request: WebhookRequest) -> WebhookUpdate:
        """Verify an asynchronous callback (signature, timestamp) and return what it says happened.

        Raises WebhookRejected if it cannot be trusted. Verification belongs here because only the adapter
        knows the provider's signing scheme; applying the state change belongs to the engine.
        """


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

    def require(self, method: str, capability: str) -> PaymentMethodAdapter:
        """The adapter for `method`, or CapabilityNotSupported if the rail cannot do `capability`.

        Call this before the adapter is asked to do anything: a partial refund on a method without partial
        refunds is decided from the descriptor, so the network is never touched.
        """
        adapter = self.for_method(method)
        if not adapter.capabilities().supports(capability):
            what = capability.removeprefix("supports_").replace("_", " ")
            raise CapabilityNotSupported(f"{method} doesn't support {what}")
        return adapter

    def methods(self) -> list[str]:
        return sorted(self._adapters)

    def adapters(self):
        """The registered adapters, in registration order (used to build a second registry that adds one)."""
        return list(self._adapters.values())

    def __contains__(self, method: str) -> bool:
        return method in self._adapters
