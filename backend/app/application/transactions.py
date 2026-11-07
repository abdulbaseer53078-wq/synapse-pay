"""Transactions (Stage 1, Step 5), method-agnostic since Step 8.

The terminal's identity comes from its mTLS certificate (the gateway passes it on as x-terminal-id), never
from the body. Which rail handles the payment is the registry's business: this engine validates the request,
authorizes the terminal, claims the idempotency key, hands the payment to the method's adapter and maps the
answer onto a transaction state. It contains no card, UPI or wallet logic.

Idempotency follows the spec: the same idempotency_key with the same body replays the stored response;
with a different body it's a 409. A retryable failure is not stored as the key's result, so the retry runs.
"""
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID
from zoneinfo import ZoneInfo

from app.application.authorization import AuthorizationService
from app.application.methods import (AdapterUnavailable, InvalidMethodDetails, MethodRegistry, MethodRequest,
                                     MethodResult, OutcomeUnknown)
from app.application.registration import Forbidden, NotFound, RegistrationError, Unauthenticated

# Daily limits reset at midnight in India, where the merchants are.
# shortcut: one time zone for every merchant; take it from the merchant record when there are others.
LIMIT_DAY_ZONE = ZoneInfo("Asia/Kolkata")


class IdempotencyConflict(RegistrationError):
    code = "IDEMPOTENCY_KEY_CONFLICT"


class StillProcessing(RegistrationError):
    """Same key and body as a request that hasn't finished yet: retry shortly."""
    code = "IDEMPOTENCY_KEY_CONFLICT"


class CardServiceUnavailable(RegistrationError):
    """The card service couldn't be reached, so nothing was sent to the acquirer."""
    code = "INTERNAL_ERROR"


class BadCardData(RegistrationError):
    code = "INVALID_REQUEST"


class MerchantMismatch(RegistrationError):
    code = "MERCHANT_NOT_FOUND"


class IntentNotPayable(RegistrationError):
    """payment_intent_id names an intent this terminal can't pay right now (wrong terminal, amount, state)."""
    code = "INVALID_REQUEST"


def parse_public_id(value: str, prefix: str) -> UUID | None:
    """pi_<32 hex> / txn_<32 hex> → UUID, or None if malformed."""
    if not value.startswith(prefix) or len(value) != len(prefix) + 32:
        return None
    try:
        return UUID(hex=value[len(prefix):])
    except ValueError:
        return None


@dataclass(frozen=True)
class CardResult:
    """What the card service answered. `status` is a TransactionStatus; `error` is the spec's Error or None."""
    status: str
    method_reference: str | None
    auth_code: str | None
    error: dict | None
    reversal: str
    card_bin: str
    card_last4: str


@dataclass(frozen=True)
class CardRequest:
    transaction_id: UUID
    kind: str  # PURCHASE or AUTHORIZATION
    amount: int
    currency: str
    acquirer_terminal_id: str
    acquirer_merchant_id: str
    encrypted_card_data: str
    card_expiry: str
    pin_block: str | None


class CardOutcomeUnknown(Exception):
    """The card service was sent the request but didn't answer: the acquirer may have acted on it."""


class CardProcessor(Protocol):
    def process(self, request: CardRequest) -> CardResult:
        """Raises CardServiceUnavailable (not sent), BadCardData (rejected before sending) or
        CardOutcomeUnknown (sent, no answer)."""


@dataclass(frozen=True)
class NewTransaction:
    idempotency_key: UUID
    request_hash: bytes
    merchant_id: UUID
    terminal_id: UUID
    amount: int
    currency: str
    payment_method: str
    capture_mode: str
    card_network: str | None
    metadata: dict[str, str]
    webhook_url: str | None = None
    payment_intent_id: UUID | None = None  # set: this payment completes a terminal checkout (Step 6)
    qr_encoded_rail: str | None = None  # set for QR: the rail the code actually encodes (Step 11)


@dataclass(frozen=True)
class Claim:
    """Result of claiming an idempotency key: either ours to process, or an earlier request's."""
    transaction_id: UUID | None = None   # set when the key is newly ours
    replay: dict | None = None           # stored response of a finished request with the same body
    conflict: bool = False               # same key, different body
    in_flight: bool = False              # same key and body, still running
    intent_error: str | None = None      # payment_intent_id given but unusable: why


class TransactionRepository(Protocol):
    def terminal_merchant(self, terminal_id: UUID) -> UUID | None: ...
    def spent_today(self, terminal_id: UUID, since: datetime) -> int: ...
    def claim(self, txn: NewTransaction) -> Claim: ...
    def mark_pending(self, transaction_id: UUID, terminal_id: UUID) -> None: ...
    def finish(self, transaction_id: UUID, terminal_id: UUID, result: MethodResult | None, status: str,
               error: dict | None, store_response: bool,
               attempts: list[dict] | None = None) -> dict: ...


def request_hash(body: dict[str, Any]) -> bytes:
    """SHA-256 of the body as canonical JSON (sorted keys, no whitespace), so key order doesn't matter."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).digest()


def public_id(transaction_id: UUID) -> str:
    return f"txn_{transaction_id.hex}"


def system_error(code: str, message: str, retryable: bool) -> dict:
    return {"error_code": code, "error_message": message, "error_category": "SYSTEM_ERROR", "retryable": retryable}


def apply_method_result(repo: TransactionRepository, transaction_id: UUID, terminal_id: UUID,
                        result: MethodResult) -> dict:
    """The one place an asynchronous method result becomes a transaction state.

    The polling fallback uses it now, and the webhook handler will in Step 10B, so both go through the same
    repository call as the synchronous path — same audit row, same webhook outbox, same idempotency handling.
    An adapter never writes state itself; it reports, and this decides.
    """
    return repo.finish(transaction_id, terminal_id, result, result.status, result.error, store_response=True)


@dataclass
class TransactionService:
    repo: TransactionRepository
    authorization: AuthorizationService
    methods: MethodRegistry
    now: Any = field(default=None)  # callable returning an aware datetime; tests can fix the clock

    def create(self, caller_terminal: UUID | None, body: dict[str, Any]) -> dict:
        """`body` is the validated request (JSON-ready). Returns the TransactionResponse to send with 201."""
        if caller_terminal is None:
            # shortcut: merchant backends (OAuth) arrive with the Merchant SDK (Step 6).
            raise Unauthenticated("transactions currently require a terminal's client certificate (mTLS)")
        if body["terminal_id"] != str(caller_terminal):
            raise Forbidden("terminal_id doesn't match the client certificate")
        merchant = self.repo.terminal_merchant(caller_terminal)
        if merchant is None:
            raise NotFound("terminal not found")
        if body["merchant_id"] != str(merchant):
            raise MerchantMismatch("this terminal doesn't belong to that merchant")
        # Step 8: one lookup, one validation, and no knowledge of what the method actually is.
        adapter = self.methods.for_method(body["payment_method"])
        details = adapter.validate(body["method_details"])
        intent_id = None
        if "payment_intent_id" in body:
            intent_id = parse_public_id(body["payment_intent_id"], "pi_")
            if intent_id is None:
                raise IntentNotPayable("payment_intent_id is not a payment intent ID")
        txn = NewTransaction(
            idempotency_key=UUID(body["idempotency_key"]), request_hash=request_hash(body), merchant_id=merchant,
            terminal_id=caller_terminal, amount=body["amount"], currency=body["currency"],
            payment_method=body["payment_method"], capture_mode=body.get("capture_mode", "AUTO"),
            card_network=details.get("card_network"), metadata=body.get("metadata") or {},
            webhook_url=body.get("webhook_url"), payment_intent_id=intent_id,
            qr_encoded_rail=details.get("qr_encoded_rail"))

        claim = self.repo.claim(txn)
        if claim.intent_error:
            raise IntentNotPayable(claim.intent_error)
        if claim.conflict:
            raise IdempotencyConflict("idempotency_key was already used with a different request body")
        if claim.in_flight:
            raise StillProcessing("a request with this idempotency_key is still being processed; retry shortly")
        if claim.replay is not None:
            return claim.replay
        transaction_id = claim.transaction_id

        # New request: check the terminal may take it, now. Denials are final for this attempt.
        auth = self.authorization.authorize(caller_terminal, txn.payment_method, txn.amount)
        reason = auth.reason
        if reason is None and auth.profile is not None:
            day_start = (self.now() if self.now else datetime.now(LIMIT_DAY_ZONE)).astimezone(LIMIT_DAY_ZONE) \
                .replace(hour=0, minute=0, second=0, microsecond=0)
            if self.repo.spent_today(caller_terminal, day_start) + txn.amount > auth.profile.per_day_limit:
                reason = "LIMIT_EXCEEDED"
        if reason is not None:
            error = {"error_code": "FORBIDDEN", "error_message": f"terminal not authorized: {reason}",
                     "error_category": "HARD_DECLINE", "retryable": False}
            return self.repo.finish(transaction_id, caller_terminal, None, "FAILED", error, store_response=True)

        request = MethodRequest(
            transaction_id=transaction_id, amount=txn.amount, currency=txn.currency,
            capture_mode=txn.capture_mode, merchant_id=merchant, terminal_id=caller_terminal,
            details=details, customer_ref=body.get("customer_ref"), metadata=txn.metadata)
        self.repo.mark_pending(transaction_id, caller_terminal)
        try:
            result = adapter.initiate(request)
        except AdapterUnavailable as exc:
            error = system_error("INTERNAL_ERROR", exc.message, True)
            self.repo.finish(transaction_id, caller_terminal, None, "FAILED", error, store_response=False)
            raise
        except InvalidMethodDetails as exc:
            error = {"error_code": "INVALID_REQUEST", "error_message": exc.message,
                     "error_category": "VALIDATION_ERROR", "retryable": False}
            self.repo.finish(transaction_id, caller_terminal, None, "FAILED", error, store_response=False)
            raise
        except OutcomeUnknown:
            # Sent, no answer: the network may have acted on it. PENDING until reconciliation settles it, and
            # stored, so a retry with this key can't charge the customer twice.
            return self.repo.finish(transaction_id, caller_terminal, None, "PENDING", None, store_response=True)

        return self.repo.finish(transaction_id, caller_terminal, result, result.status, result.error,
                                store_response=not result.retryable)
