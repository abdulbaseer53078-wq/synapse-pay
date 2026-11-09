"""The wallet adapter (Stage 1, Step 12): stored-value rails, server-to-server.

Wallets differ from cards and UPI in where the money is: it is already in the user's wallet, so a payment is a
closed-loop transfer the provider performs. That makes the tokenised flow a direct debit — one HTTP call,
settled — and the redirect flow a hand-off to the provider's own UI.

This module implements the tokenised flow, which is what the frozen contract models: `WalletDetails` *requires*
`wallet_token`. The redirect flow (no token, answered with a URL to open) needs two contract changes and is
tracked in docs/step12.md rather than smuggled in as a schema violation.

The client lives here rather than in its own module because it is two calls and the wallet vocabulary is only
used here; `upi_client.py` is separate because UPI and QR both speak it.
"""
import json
import time
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.application.methods import (AdapterUnavailable, CapabilityDescriptor, DisputeRules, MethodRequest,
                                     MethodResult, Transition, WebhookRejected, WebhookRequest, WebhookUpdate)
from app.infrastructure.methods.base import BaseMethodAdapter
from app.infrastructure.webhook_signature import REPLAY_WINDOW_SECONDS, verify_signature

DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=1.0)

WALLET_CAPABILITIES = CapabilityDescriptor(
    payment_method="WALLET",
    supports_chargeback=False,  # a wallet dispute is a provider support ticket, not a card chargeback
    supports_recurring=False,  # auto-debit exists, but not in this adapter yet
    supports_offline=False,
    supports_refund=False,  # PR 4: the wallet adapter has no refund call yet
    supports_partial_refund=False,  # the contract's WalletCapabilities: full refunds only
    supports_partial_capture=False,
    settlement_timeline="T+0",  # the contract says T+0; the brief said T+1
    auth_type="otp",
    is_synchronous=False,  # the redirect flow is asynchronous; the token flow happens to settle in-call
    dispute_rules=DisputeRules(framework="NONE", dispute_window_days=0),
    transitions=(
        Transition("INITIATED", "PENDING"),
        Transition("PENDING", "AUTHORIZED"),
        Transition("PENDING", "FAILED"),
        Transition("AUTHORIZED", "CAPTURED"),
        Transition("CAPTURED", "SETTLED"),
        # Refund transitions return with the wallet refund call (PR 4 follow-up).
    ),
)


class WalletUnavailable(Exception):
    """We could not ask the provider: transport, timeout or 5xx. Nothing is known, so nothing is declined."""

    def __init__(self, message: str = "the wallet provider is unavailable; nothing was charged"):
        super().__init__(message)
        self.message = message


class WalletDeclined(Exception):
    """The provider answered and refused. Carries the taxonomy the engine routes on."""

    def __init__(self, code: str, message: str, category: str = "HARD_DECLINE", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = category
        self.retryable = retryable


# Wallet-specific declines, mapped once. A top-up can fix a balance; nothing fixes a KYC block.
WALLET_ERRORS = {
    "WALLET_INSUFFICIENT_BALANCE": ("SOFT_DECLINE", True),
    "WALLET_BLOCKED": ("HARD_DECLINE", False),
    "WALLET_LIMIT_EXCEEDED": ("HARD_DECLINE", False),
}


class WalletDetails(BaseModel):
    """method_details for WALLET (contract 1.7.0): token for a direct debit, absent for a redirect flow."""

    model_config = ConfigDict(extra="forbid")

    wallet_provider: Literal["PAYTM", "PHONEPE", "AMAZON_PAY"]
    wallet_token: str | None = Field(default=None, min_length=1, max_length=4096)


class HttpWallet:
    def __init__(self, base_url: str, timeout: httpx.Timeout = DEFAULT_TIMEOUT):
        self.client = httpx.Client(base_url=base_url, timeout=timeout)

    def close(self) -> None:
        self.client.close()

    def pay(self, amount: int, currency: str, merchant_transaction_id: str) -> dict:
        """The redirect flow: the provider answers with its own URL for the customer to authorise at."""
        try:
            response = self.client.post("/wallet/v1/pay", json={
                "amount": amount, "currency": currency, "merchant_transaction_id": merchant_transaction_id})
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise WalletUnavailable(
                f"the wallet provider did not answer ({type(exc).__name__}); nothing was charged") from exc
        if response.status_code >= 500:
            raise WalletUnavailable(f"the wallet provider answered {response.status_code}; nothing was confirmed")
        if response.status_code >= 400:
            raise self._declined(response)
        return response.json()

    def debit(self, wallet_token: str, amount: int, currency: str, merchant_transaction_id: str) -> dict:
        try:
            response = self.client.post("/wallet/v1/debit", json={
                "wallet_token": wallet_token, "amount": amount, "currency": currency,
                "merchant_transaction_id": merchant_transaction_id})
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise WalletUnavailable(
                f"the wallet provider did not answer ({type(exc).__name__}); nothing was charged") from exc
        if response.status_code >= 500:
            raise WalletUnavailable(f"the wallet provider answered {response.status_code}; nothing was confirmed")
        if response.status_code >= 400:
            raise self._declined(response)
        try:
            return response.json()
        except ValueError as exc:
            raise WalletUnavailable("the wallet provider answered something that is not JSON") from exc

    def status(self, wallet_transaction_id: str) -> dict:
        try:
            response = self.client.get(f"/wallet/v1/status/{wallet_transaction_id}")
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise WalletUnavailable(f"the wallet provider did not answer ({type(exc).__name__})") from exc
        if response.status_code >= 400:
            raise WalletUnavailable(f"the wallet provider answered {response.status_code}")
        return response.json()

    @staticmethod
    def _declined(response: httpx.Response) -> WalletDeclined:
        try:
            error = response.json().get("error") or {}
        except ValueError:
            error = {}
        code = error.get("code") or f"WALLET_HTTP_{response.status_code}"
        message = error.get("message") or f"the wallet provider rejected the payment ({response.status_code})"
        category, retryable = WALLET_ERRORS.get(code, ("HARD_DECLINE", False))
        return WalletDeclined(code, message, category, retryable)


class WalletMethodAdapter(BaseMethodAdapter):
    method = "WALLET"
    CAPABILITIES = WALLET_CAPABILITIES
    DETAILS = WalletDetails
    ERROR_MAP = {WalletUnavailable: lambda exc: AdapterUnavailable(exc.message)}

    def __init__(self, provider: HttpWallet, webhook_secret: str | None = None, clock=time.time,
                 replay_window: int = REPLAY_WINDOW_SECONDS):
        self.provider = provider
        self.webhook_secret = webhook_secret
        self.clock = clock
        self.replay_window = replay_window

    def handle_webhook(self, request: WebhookRequest) -> WebhookUpdate:
        """Verify the provider's callback and normalise it. Same verifier UPI uses, different headers."""
        verify_signature(request.raw, request.headers, self.webhook_secret,
                         timestamp_header="X-Wallet-Timestamp", signature_header="X-Wallet-Signature",
                         label="wallet", now=self.clock, window=self.replay_window)
        try:
            body = json.loads(request.raw or b"{}")
        except ValueError:
            raise WebhookRejected(400, "INVALID_JSON", "body is not JSON") from None
        if not isinstance(body, dict):
            raise WebhookRejected(400, "INVALID_JSON", "body must be a JSON object")
        event_id = str(body.get("event_id") or "")
        wallet_id = str(body.get("wallet_transaction_id") or "")
        state = body.get("status")
        if not event_id or not wallet_id or state not in ("SUCCESS", "FAILURE"):
            raise WebhookRejected(400, "INVALID_PAYLOAD",
                                  "event_id, wallet_transaction_id and a known status are required")
        if state == "SUCCESS":
            result = MethodResult(status="SETTLED", method_reference=wallet_id)
        else:
            result = MethodResult(status="FAILED", method_reference=wallet_id, error={
                "error_code": "WALLET_DECLINED", "error_message": body.get("reason") or "the wallet declined",
                "error_category": "HARD_DECLINE", "retryable": False})
        return WebhookUpdate(event_id=event_id, result=result)

    def send(self, request: MethodRequest) -> MethodResult:
        token = request.details.get("wallet_token")
        if not token:
            # First-time customer: hand them to the provider's UI. PENDING until its webhook (Step 12b).
            reply = self.provider.pay(amount=request.amount, currency=request.currency,
                                      merchant_transaction_id=str(request.transaction_id))
            return MethodResult(status="PENDING", method_reference=reply.get("wallet_transaction_id"),
                                next_action={"type": "WALLET_REDIRECT", "url": reply["action_url"]})
        try:
            reply = self.provider.debit(
                wallet_token=token, amount=request.amount,
                currency=request.currency, merchant_transaction_id=str(request.transaction_id))
        except WalletDeclined as declined:
            return MethodResult(status="FAILED", error={
                "error_code": declined.code, "error_message": declined.message,
                "error_category": declined.category, "retryable": declined.retryable})
        # A closed-loop transfer: the money is already at the provider, so a debit that succeeds has settled.
        return MethodResult(status="SETTLED", method_reference=reply.get("wallet_transaction_id"))

    def status(self, transaction_id, reference: str | None = None) -> MethodResult:
        from app.application.methods import UnsupportedOperation
        if not reference:
            raise UnsupportedOperation("WALLET status needs the provider reference stored with the transaction")
        try:
            reply = self.provider.status(reference)
        except WalletDeclined as declined:
            return MethodResult(status="FAILED", error={
                "error_code": declined.code, "error_message": declined.message,
                "error_category": declined.category, "retryable": declined.retryable})
        state = reply.get("status")
        if state == "SUCCESS":
            return MethodResult(status="SETTLED", method_reference=reply.get("wallet_transaction_id"))
        if state == "FAILURE":
            return MethodResult(status="FAILED", method_reference=reply.get("wallet_transaction_id"), error={
                "error_code": "WALLET_DECLINED", "error_message": "the provider reported a failure",
                "error_category": "HARD_DECLINE", "retryable": False})
        return MethodResult(status="PENDING", method_reference=reply.get("wallet_transaction_id"))
