"""Inbound UPI webhooks (Step 10B): verify, deduplicate, then let the engine change state.

The order matters and is deliberate:

1. the adapter verifies the signature and timestamp over the **raw bytes** (only it knows the signing scheme);
2. the delivery id is claimed in the database — an atomic insert, so two workers receiving the same retry
   cannot both apply it;
3. the payment is resolved from the network reference and the change goes through `apply_method_result`,
   the same call the poller and the synchronous path use, so the audit row and webhook outbox are identical.

The handler never writes transaction state itself. An adapter that wrote state would bypass the state machine,
the audit trail and the idempotency key — which is the whole reason the boundary exists.
"""
import logging
from dataclasses import dataclass
from typing import Mapping, Protocol
from uuid import UUID

from app.application.methods import MethodResult, PaymentMethodAdapter, WebhookRequest
from app.application.transactions import apply_method_result

log = logging.getLogger(__name__)


class WebhookEventStore(Protocol):
    def claim(self, provider: str, event_id: str) -> bool:
        """True if this delivery is new; False if it was already applied. Must be atomic."""


class WebhookTransactions(Protocol):
    def by_method_reference(self, reference: str, method: str | None = None) -> tuple[UUID, UUID, str] | None: ...

    def finish(self, transaction_id: UUID, terminal_id: UUID, result: MethodResult | None, status: str,
               error: dict | None, store_response: bool) -> dict: ...


@dataclass(frozen=True)
class WebhookOutcome:
    duplicate: bool
    applied: bool
    status: str | None = None
    reason: str | None = None  # why nothing was applied, when a signed webhook was still acknowledged


class WebhookHandler:
    """One class for every provider: the security and dedup are identical, only the adapter differs."""

    def __init__(self, adapter: PaymentMethodAdapter, transactions: WebhookTransactions,
                 events: WebhookEventStore, provider: str = "upi"):
        self.adapter = adapter
        self.transactions = transactions
        self.events = events
        self.provider = provider

    def handle(self, raw: bytes, headers: Mapping[str, str]) -> WebhookOutcome:
        """Raises WebhookRejected if the callback cannot be trusted. Returns an outcome otherwise."""
        update = self.adapter.handle_webhook(
            WebhookRequest(raw=raw, headers={key.lower(): value for key, value in headers.items()}))

        if not self.events.claim(self.provider, update.event_id):
            # At-least-once delivery: the same SUCCESS arriving twice must settle once.
            return WebhookOutcome(duplicate=True, applied=False, status=None)

        reference = update.result.method_reference or ""
        found = self.transactions.by_method_reference(reference)
        if found is None:
            # Signed, fresh, but about a payment we do not know. Acknowledge (the provider must stop retrying)
            # and leave a trail: this is a configuration or routing bug, not something to answer 4xx for.
            log.warning("%s webhook for unknown reference %s (event %s)", self.provider.upper(), reference,
                        update.event_id)
            return WebhookOutcome(duplicate=False, applied=False, reason="unknown transaction")

        transaction_id, terminal_id, _current = found
        apply_method_result(self.transactions, transaction_id, terminal_id, update.result)
        return WebhookOutcome(duplicate=False, applied=True, status=update.result.status)


# Kept for the call sites and tests written before wallets arrived.
UpiWebhookHandler = WebhookHandler
