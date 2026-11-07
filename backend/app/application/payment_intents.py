"""Payment intents (Stage 1, Step 6): how merchant apps and websites take payments.

1. The merchant's server creates an intent with its secret API key: "charge ₹500". It gets a client_secret.
2. The customer's browser or app confirms it with the client_secret and the card, encrypted to the HSM's
   checkout key in Synapse's own card frame. Neither the merchant's page nor this backend sees the number.
3. Online card payments in India need 3-D Secure: usually the issuer's OTP page (next_action), then the
   authorization. A decline sends the intent back to REQUIRES_PAYMENT_METHOD so the customer can retry.
4. Or the intent names a terminal: the terminal picks it up (terminal checkout) and the customer taps there.

The amount is fixed by the merchant's server, so a customer can't change ₹500 to ₹1 in the browser.
"""
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

from app.application.registration import Forbidden, InvalidInput, NotFound, RegistrationError, Unauthenticated
from app.application.transactions import (BadCardData, CardOutcomeUnknown, CardProcessor, CardRequest, CardResult,
                                          CardServiceUnavailable, parse_public_id, public_id, request_hash,
                                          system_error)

INTENT_TTL = timedelta(hours=1)
# Sandbox issuer (ACS) OTP. shortcut: the real challenge is the issuer's page, reached through a 3DS server.
SANDBOX_OTP = "123456"


class IntentConflict(RegistrationError):
    code = "IDEMPOTENCY_KEY_CONFLICT"


class IntentNotConfirmable(RegistrationError):
    code = "INVALID_REQUEST"


def intent_not_found() -> NotFound:
    return NotFound("payment intent not found", "PAYMENT_INTENT_NOT_FOUND")


@dataclass(frozen=True)
class Intent:
    intent_id: UUID
    merchant_id: UUID
    amount: int
    currency: str
    capture_mode: str
    description: str | None
    metadata: dict
    webhook_url: str | None
    terminal_id: UUID | None
    status: str
    client_secret: str
    expires_at: datetime
    pending_card: dict | None
    transaction_id: UUID | None
    last_payment_error: dict | None
    card_bin: str | None
    card_last4: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class NewIntent:
    intent_id: UUID
    merchant_id: UUID
    idempotency_key: UUID
    request_hash: bytes
    amount: int
    currency: str
    capture_mode: str
    description: str | None
    metadata: dict
    webhook_url: str | None
    terminal_id: UUID | None
    client_secret: str
    expires_at: datetime


@dataclass(frozen=True)
class Authentication:
    three_ds: str  # FRICTIONLESS, CHALLENGE or REJECTED
    card_bin: str
    card_last4: str


class CheckoutCardProcessor(CardProcessor, Protocol):
    def authenticate(self, transaction_id: UUID, encrypted_card_data: str, encrypted_cvv: str | None, amount: int,
                     currency: str) -> Authentication: ...
    def checkout_key(self) -> dict: ...


class IntentRepository(Protocol):
    def create(self, new: NewIntent) -> tuple[Intent | None, bool]: ...
    def get(self, intent_id: UUID) -> Intent | None: ...
    def by_client_secret(self, client_secret: str) -> Intent | None: ...
    def begin_confirm(self, intent_id: UUID) -> Intent | None: ...
    def require_action(self, intent_id: UUID, pending_card: dict, card_bin: str, card_last4: str) -> None: ...
    def take_pending_card(self, intent_id: UUID) -> dict | None: ...
    def fail_attempt(self, intent_id: UUID, error: dict) -> None: ...
    def start_online_transaction(self, intent: Intent) -> UUID: ...
    def finish_online_transaction(self, intent: Intent, transaction_id: UUID, result: CardResult | None,
                                  status: str, error: dict | None) -> None: ...
    def cancel(self, intent_id: UUID, merchant_id: UUID) -> Intent | None: ...
    def next_for_terminal(self, terminal_id: UUID) -> Intent | None: ...
    def terminal_belongs(self, terminal_id: UUID, merchant_id: UUID) -> str | None: ...


def public_intent_id(intent_id: UUID) -> str:
    return f"pi_{intent_id.hex}"


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")


def online_acquirer_ids(merchant_id: UUID) -> tuple[str, str]:
    """DE 41/42 for online payments: one virtual terminal per merchant.
    shortcut: derived from the merchant UUID; acquirers assign e-commerce TIDs at onboarding."""
    return "E" + merchant_id.hex[:7].upper(), merchant_id.hex[:15].upper()


def view(intent: Intent, for_merchant: bool) -> dict[str, Any]:
    """The PaymentIntent object. The client_secret goes only to the merchant's server, which hands it to its
    page; a client holding it sees no merchant-private fields (metadata, webhook_url, description)."""
    body: dict[str, Any] = {
        "id": public_intent_id(intent.intent_id), "status": intent.status, "amount": intent.amount,
        "currency": intent.currency, "capture_mode": intent.capture_mode,
        "created_at": _iso(intent.created_at), "updated_at": _iso(intent.updated_at),
        "expires_at": _iso(intent.expires_at),
    }
    if intent.terminal_id:
        body["terminal_id"] = str(intent.terminal_id)
    if intent.transaction_id:
        body["transaction_id"] = public_id(intent.transaction_id)
    if intent.last_payment_error:
        body["last_payment_error"] = intent.last_payment_error
    if intent.card_last4:
        body["card"] = {"bin": intent.card_bin, "last4": intent.card_last4}
    if intent.status == "REQUIRES_ACTION":
        body["next_action"] = {"type": "THREE_DS_CHALLENGE",
                               "url": f"/sandbox/acs/{public_intent_id(intent.intent_id)}"
                                      f"?client_secret={intent.client_secret}"}
    if for_merchant:
        body["client_secret"] = intent.client_secret
        body["metadata"] = intent.metadata
        if intent.description:
            body["description"] = intent.description
        if intent.webhook_url:
            body["webhook_url"] = intent.webhook_url
    return body


def _declined(code: str, message: str, category: str = "HARD_DECLINE", retryable: bool = False) -> dict:
    return {"error_code": code, "error_message": message, "error_category": category, "retryable": retryable}


class PaymentIntentService:
    def __init__(self, repo: IntentRepository, cards: CheckoutCardProcessor, now=lambda: datetime.now(UTC)):
        self.repo = repo
        self.cards = cards
        self.now = now

    # Merchant server (secret API key)

    def create(self, merchant_id: UUID, body: dict[str, Any]) -> tuple[dict, bool]:
        """Returns (PaymentIntent, created). Same key and body → the same intent; different body → 409."""
        terminal_id = UUID(body["terminal_id"]) if body.get("terminal_id") else None
        if terminal_id is not None:
            status = self.repo.terminal_belongs(terminal_id, merchant_id)
            if status is None:
                raise NotFound("terminal not found")
            if status != "ACTIVE":
                raise Forbidden(f"terminal is {status}; only ACTIVE terminals can take payments")
        if body["currency"] != "INR":
            raise InvalidInput("only INR is supported for now")
        intent_id = uuid4()
        new = NewIntent(
            intent_id=intent_id, merchant_id=merchant_id, idempotency_key=UUID(body["idempotency_key"]), request_hash=request_hash(body),
            amount=body["amount"], currency=body["currency"], capture_mode=body.get("capture_mode", "AUTO"),
            description=body.get("description"), metadata=body.get("metadata") or {},
            webhook_url=body.get("webhook_url"), terminal_id=terminal_id,
            # The intent's ID is in its client secret, so client SDKs need only the secret.
            client_secret=f"{public_intent_id(intent_id)}_secret_{secrets.token_urlsafe(24)}", expires_at=self.now() + INTENT_TTL)
        intent, created = self.repo.create(new)
        if intent is None:
            raise IntentConflict("idempotency_key was already used with a different request body")
        return view(intent, for_merchant=True), created

    def retrieve(self, merchant_id: UUID, public: str) -> dict:
        return view(self._own(merchant_id, public), for_merchant=True)

    def cancel(self, merchant_id: UUID, public: str) -> dict:
        intent = self._own(merchant_id, public)
        cancelled = self.repo.cancel(intent.intent_id, merchant_id)
        if cancelled is None:
            raise IntentNotConfirmable(f"a {intent.status} payment intent can't be canceled")
        return view(cancelled, for_merchant=True)

    def _own(self, merchant_id: UUID, public: str) -> Intent:
        intent_id = parse_public_id(public, "pi_")
        intent = self.repo.get(intent_id) if intent_id else None
        if intent is None or intent.merchant_id != merchant_id:
            raise intent_not_found()
        return intent

    # Customer's browser or app (client_secret)

    def _by_secret(self, public: str, client_secret: str | None) -> Intent:
        if not client_secret:
            raise Unauthenticated("client_secret is required")
        intent = self.repo.by_client_secret(client_secret)
        if intent is None or public_intent_id(intent.intent_id) != public:
            raise intent_not_found()
        return intent

    def retrieve_for_client(self, public: str, client_secret: str | None) -> dict:
        return view(self._by_secret(public, client_secret), for_merchant=False)

    def checkout_key(self) -> dict:
        return self.cards.checkout_key()

    def confirm(self, public: str, client_secret: str, card: dict[str, Any]) -> dict:
        """Pays the intent with a card from Synapse's card frame. Safe to repeat: a second confirm of an intent
        that's already moving returns its current state instead of paying twice."""
        intent = self._by_secret(public, client_secret)
        if intent.terminal_id is not None:
            raise IntentNotConfirmable("this payment intent is paid on its terminal")
        if intent.status != "REQUIRES_PAYMENT_METHOD":
            return view(intent, for_merchant=False)
        if intent.expires_at <= self.now():
            raise IntentNotConfirmable("payment intent has expired")
        started = self.repo.begin_confirm(intent.intent_id)
        if started is None:  # someone else confirmed it a moment ago
            return view(self.repo.get(intent.intent_id), for_merchant=False)
        try:
            auth = self.cards.authenticate(intent.intent_id, card["encrypted_card_data"], card.get("encrypted_cvv"),
                                           intent.amount, intent.currency)
        except BadCardData as e:
            self.repo.fail_attempt(intent.intent_id, _declined("INVALID_REQUEST", e.message, "VALIDATION_ERROR"))
            raise
        except (CardServiceUnavailable, CardOutcomeUnknown):
            # Nothing was charged: authentication comes before authorization.
            self.repo.fail_attempt(intent.intent_id, system_error(
                "INTERNAL_ERROR", "the payment service is unavailable; nothing was charged", True))
            raise CardServiceUnavailable("the payment service is unavailable; nothing was charged")
        if auth.three_ds == "REJECTED":
            self.repo.fail_attempt(intent.intent_id, _declined(
                "AUTHENTICATION_FAILED", "the card's issuer could not authenticate the cardholder"))
        elif auth.three_ds == "CHALLENGE":
            # The CVV was checked by the issuer during authentication and is never kept, even encrypted.
            pending = {k: v for k, v in card.items() if k != "encrypted_cvv"}
            self.repo.require_action(intent.intent_id, pending, auth.card_bin, auth.card_last4)
        else:
            self._authorize(started, card)
        return view(self.repo.get(intent.intent_id), for_merchant=False)

    def complete_challenge(self, public: str, client_secret: str, otp: str) -> dict:
        """The sandbox issuer's OTP page posts here. Right OTP → authorize; wrong → back to the customer."""
        intent = self._by_secret(public, client_secret)
        if intent.status != "REQUIRES_ACTION":
            return view(intent, for_merchant=False)
        if not secrets.compare_digest(otp.strip(), SANDBOX_OTP):
            self.repo.fail_attempt(intent.intent_id, _declined(
                "AUTHENTICATION_FAILED", "the one-time password was wrong; the card was not charged"))
            return view(self.repo.get(intent.intent_id), for_merchant=False)
        card = self.repo.take_pending_card(intent.intent_id)
        if card is not None:
            self._authorize(intent, card)
        return view(self.repo.get(intent.intent_id), for_merchant=False)

    def _authorize(self, intent: Intent, card: dict) -> None:
        transaction_id = self.repo.start_online_transaction(intent)
        tid, mid = online_acquirer_ids(intent.merchant_id)
        request = CardRequest(
            transaction_id=transaction_id, kind="PURCHASE" if intent.capture_mode == "AUTO" else "AUTHORIZATION",
            amount=intent.amount, currency=intent.currency, acquirer_terminal_id=tid, acquirer_merchant_id=mid,
            encrypted_card_data=card["encrypted_card_data"], card_expiry=card["card_expiry"], pin_block=None)
        try:
            result = self.cards.process(request)
        except CardServiceUnavailable:
            self.repo.finish_online_transaction(intent, transaction_id, None, "FAILED", system_error(
                "INTERNAL_ERROR", "the payment service is unavailable; nothing was charged", True))
            return
        except BadCardData as e:
            self.repo.finish_online_transaction(intent, transaction_id, None, "FAILED",
                                                _declined("INVALID_REQUEST", e.message, "VALIDATION_ERROR"))
            return
        except CardOutcomeUnknown:
            self.repo.finish_online_transaction(intent, transaction_id, None, "PENDING", None)
            return
        self.repo.finish_online_transaction(intent, transaction_id, result, result.status, result.error)

    # Terminal checkout (mTLS terminal)

    def next_for_terminal(self, terminal_id: UUID) -> dict | None:
        intent = self.repo.next_for_terminal(terminal_id)
        if intent is None:
            return None
        body = {"payment_intent_id": public_intent_id(intent.intent_id), "amount": intent.amount,
                "currency": intent.currency, "capture_mode": intent.capture_mode,
                "expires_at": _iso(intent.expires_at)}
        if intent.description:
            body["description"] = intent.description
        return body
