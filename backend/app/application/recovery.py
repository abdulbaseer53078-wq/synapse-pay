"""Recovery sweeps (PR 3): payments a crash or a lost answer left half-done. Run by `python -m app.jobs sweep`.

UPI and wallet payments stuck in PENDING are already resolved by the upi-poll job, which asks the provider. These
cover the two cases it can't:

* A request that died before reaching the network. Its idempotency key stays IN_FLIGHT, so every retry gets "still
  processing" forever. If the payment is still INITIATED nothing was sent, so it is failed (retryable) and its key
  released, and the client's retry with the same key is processed fresh. A PENDING payment may have been sent:
  freeing its key could charge twice, so it is left to the PENDING sweeps.
* A card payment whose outcome is unknown and whose in-line reversal failed. There is no card status inquiry; the
  card service's durable reversal queue keeps sending the reversal, and this resolves the payment once it lands.

Every resolution goes through `finish(..., expected=...)`: the state machine decides, and a payment that moved on
meanwhile (sent, or answered) is left alone.
"""
import logging
from typing import Protocol
from uuid import UUID

from app.application.methods import MethodResult, PaymentMethodAdapter
from app.application.transactions import TransactionRepository, apply_method_result, system_error

log = logging.getLogger(__name__)

STUCK_AFTER_SECONDS = 300


class ReversalStates(Protocol):
    def reversal_state(self, transaction_id: UUID) -> str | None:
        """PENDING, REVERSED, NOT_AT_HOST or MANUAL; None if the card service never queued one."""


class RecoveryRepository(TransactionRepository, Protocol):
    def stuck_in_flight(self, older_than_seconds: int, limit: int = 50) -> list[tuple[UUID, UUID]]: ...
    def stale_pending(self, method: str, older_than_seconds: int,
                      limit: int = 50) -> list[tuple[UUID, UUID, str | None]]: ...


def sweep_async_pending(repo: RecoveryRepository, sweeps: list[tuple[str, PaymentMethodAdapter]],
                        older_than_seconds: int) -> int:
    """The upi-poll job's pass (Steps 10A, 12b): ask the provider for the authoritative status of payments a lost
    webhook left PENDING, and apply it through the same call the webhook uses. Still pending is a valid answer."""
    polled = 0
    for method, adapter in sweeps:
        for transaction_id, terminal_id, reference in repo.stale_pending(method, older_than_seconds):
            polled += 1
            result = adapter.status(transaction_id, reference)
            if result.status != "PENDING":
                apply_method_result(repo, transaction_id, terminal_id, result)
    return polled


def sweep_stuck_keys(repo: RecoveryRepository, older_than_seconds: int = STUCK_AFTER_SECONDS) -> int:
    swept = 0
    for transaction_id, terminal_id in repo.stuck_in_flight(older_than_seconds):
        error = system_error("INTERNAL_ERROR", "the request stopped before reaching the payment network; nothing "
                             "was charged, so it is safe to retry with the same idempotency key", True)
        repo.finish(transaction_id, terminal_id, None, "FAILED", error, store_response=False, expected="INITIATED")
        swept += 1
    return swept


def sweep_card_pending(repo: RecoveryRepository, cards: ReversalStates,
                       older_than_seconds: int = STUCK_AFTER_SECONDS) -> int:
    resolved = 0
    for transaction_id, terminal_id, _ in repo.stale_pending("CARD", older_than_seconds):
        if terminal_id is None:
            continue  # shortcut: online (payment intent) card payments resolve through their own writer; add when needed
        state = cards.reversal_state(transaction_id)
        if state in ("REVERSED", "NOT_AT_HOST"):
            # Reversed, or the host never had it: either way the customer wasn't charged, and a retry is safe.
            error = {"error_code": "HOST_TIMEOUT", "error_category": "SYSTEM_ERROR", "retryable": True,
                     "error_message": "the acquirer didn't answer in time; the attempt was reversed, so the "
                                      "customer was not charged"}
            result = MethodResult(status="FAILED", error=error,
                                  reversal="REVERSED" if state == "REVERSED" else "NOT_NEEDED")
            repo.finish(transaction_id, terminal_id, result, "FAILED", error, store_response=False,
                        expected="PENDING")
            resolved += 1
        elif state == "MANUAL" or state is None:
            # No automatic answer exists: the acquirer's clearing file, read by a person, settles it.
            log.warning("card payment %s stuck PENDING; reversal %s: needs reconciliation", transaction_id,
                        state or "never queued")
    return resolved
