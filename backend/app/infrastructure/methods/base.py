"""Shared adapter plumbing (Task 8.3).

A subclass implements one method — `send()` — and declares three class attributes. Everything an adapter would
otherwise repeat lives here: the capabilities call, method_details validation, translation of whatever the
processor throws into the shared error taxonomy, and a guarantee that only a `MethodResult` ever comes back.

Two things are deliberately **not** here, because putting them here would be wrong in this architecture:

*Idempotency.* The engine claims the idempotency key in one transaction, before any adapter is reached
(`TransactionService.create` → `repo.claim`), and replays the stored response on a repeat. If an adapter also
claimed it, a retry would either double-charge or need database access an adapter must not have. The property
is pinned by `test_idempotency_is_enforced_by_the_engine_not_the_adapter`.

*Audit.* Every transition is written to `audit_log` by the repository, in the same transaction as the state
change — that is what makes the outbox correct. An adapter runs outside that transaction, so an audit row
written from here could commit while the transaction rolled back, recording a payment that never happened.
Adapters are asked to describe what they did (`MethodResult` carries the reference, BIN and last four); the
engine persists it.
"""
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from uuid import UUID

from pydantic import BaseModel, ValidationError

from app.application.methods import (AdapterUnavailable, CapabilityDescriptor, InvalidMethodDetails, MethodRequest,
                                     MethodResult, OutcomeUnknown, UnsupportedOperation)

log = logging.getLogger(__name__)

# The adapter vocabulary, and only it. A processor's own errors may also be RegistrationError subclasses (the
# card service's are), so catching RegistrationError here would let them through untranslated.
ALREADY_TRANSLATED = (AdapterUnavailable, InvalidMethodDetails, UnsupportedOperation, OutcomeUnknown)


class BaseMethodAdapter(ABC):
    """Template for a payment method adapter. Subclasses set the attributes and implement `send`."""

    method: str = ""
    CAPABILITIES: CapabilityDescriptor
    DETAILS: type[BaseModel] | None = None  # pydantic shape of method_details; None means "accept as-is"
    # processor exception → shared adapter exception. Anything unmapped becomes AdapterUnavailable.
    ERROR_MAP: Mapping[type[Exception], Callable[[Exception], Exception]] = {}

    def capabilities(self) -> CapabilityDescriptor:
        return self.CAPABILITIES

    def validate(self, details: dict) -> dict:
        """Validate and normalise method_details. Field paths and reasons only: never echo the values."""
        if self.DETAILS is None:
            return details
        try:
            return self.DETAILS.model_validate(details).model_dump(exclude_none=True)
        except ValidationError as exc:
            raise InvalidMethodDetails("; ".join(
                f"method_details.{'.'.join(map(str, error['loc']))}: {error['msg']}"
                for error in exc.errors())) from exc

    def initiate(self, request: MethodRequest) -> MethodResult:
        """Run the payment, translating anything the processor throws into the shared taxonomy."""
        try:
            result = self.send(request)
        except ALREADY_TRANSLATED:
            raise  # already our vocabulary (or the deliberate non-error): don't re-wrap
        except Exception as exc:
            translated = self.translate(exc)
            # One line, no request detail: enough to find the bug, nothing that could be card data.
            log.warning("adapter %s failed on transaction %s: %s -> %s", self.method, request.transaction_id,
                        type(exc).__name__, type(translated).__name__)
            raise translated from exc
        if not isinstance(result, MethodResult):
            # An adapter returning the wrong type is a bug, not a payment problem: fail loudly and early.
            raise TypeError(f"{type(self).__name__}.send() returned {type(result).__name__}, not MethodResult")
        return result

    def translate(self, exc: Exception) -> Exception:
        for kind, make in self.ERROR_MAP.items():
            if isinstance(exc, kind):
                return make(exc)
        # Unknown failure: retryable, because we cannot prove the network did not act. The engine decides.
        return AdapterUnavailable(f"the {self.method.lower()} processor failed unexpectedly; nothing was charged")

    @abstractmethod
    def send(self, request: MethodRequest) -> MethodResult:
        """Talk to the rail. Raises processor-specific exceptions; `initiate` translates them."""

    # Calls a rail has not built yet are explicit rather than absent, so a caller gets a clear 4xx instead of
    # an AttributeError. Override only what the method can actually do.
    def capture(self, transaction_id: UUID, amount: int) -> MethodResult:
        raise UnsupportedOperation(f"{self.method} has no capture step yet")

    def refund(self, transaction_id: UUID, amount: int, reference: str | None = None) -> MethodResult:
        raise UnsupportedOperation(f"{self.method} has no refund step yet")

    def status(self, transaction_id: UUID, reference: str | None = None) -> MethodResult:
        raise UnsupportedOperation(f"{self.method} has no status lookup yet")

    def handle_webhook(self, request) -> "WebhookUpdate":
        raise UnsupportedOperation(f"{self.method} has no asynchronous callback")
