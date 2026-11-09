"""After the sale (PR 4): refunds, captures and voids, initiated by the merchant's server.

A refund is reserved in the database before the network is asked, then completed together with the payment's
status, the audit trail and the ledger. If the network's answer is lost, the refund stays PENDING and
`resolve_pending` sends it again under the same refund id, which the network treats as the same refund.
"""
from typing import Protocol
from uuid import UUID

from app.application.methods import CapabilityNotSupported, MethodRegistry, OutcomeUnknown, UnsupportedOperation
from app.application.registration import Conflict, NotFound
from app.domain.state_machine import transition


class RefundStore(Protocol):
    def reserve(self, merchant_id: UUID, transaction_id: UUID, amount: int, reason: str | None,
                idempotency_key: UUID): ...
    def complete(self, refund_id: UUID, network_reference: str | None): ...
    def fail(self, refund_id: UUID, error: dict): ...
    def stale_pending(self, older_than_seconds: int, limit: int = 50) -> list: ...
    def payment(self, merchant_id: UUID, transaction_id: UUID) -> tuple | None: ...
    def settle_hold(self, merchant_id: UUID, transaction_id: UUID, target: str,
                    network_reference: str | None) -> dict: ...


def _not_supported(method: str, operation: str) -> CapabilityNotSupported:
    return CapabilityNotSupported(f"{method} payments can't be {operation} yet", code="OPERATION_NOT_SUPPORTED")


class RefundService:
    def __init__(self, store: RefundStore, methods: MethodRegistry):
        self.store = store
        self.methods = methods

    # --- refunds ---------------------------------------------------------------------------------------------

    def refund(self, merchant_id: UUID, transaction_id: UUID, amount: int, reason: str | None,
               idempotency_key: UUID) -> tuple[object, bool]:
        """(refund, created). A replayed key returns the refund it made, whatever state it reached."""
        payment = self.store.payment(merchant_id, transaction_id)
        if payment is None:
            raise NotFound("transaction not found", code="TRANSACTION_NOT_FOUND")
        _status, total, method = payment[0], payment[1], payment[2]
        capabilities = self.methods.for_method(method).capabilities()
        if not capabilities.supports_refund:
            raise _not_supported(method, "refunded")
        if amount < total and not capabilities.supports_partial_refund:
            raise CapabilityNotSupported(f"{method} payments can only be refunded in full",
                                         code="OPERATION_NOT_SUPPORTED")
        refund, created = self.store.reserve(merchant_id, transaction_id, amount, reason, idempotency_key)
        if created:
            refund = self._send(refund)
        return refund, created

    def resolve_pending(self, older_than_seconds: int = 60) -> int:
        """Recovery: re-send refunds whose answer never came back. Safe, because the refund id is the network's
        idempotency key: a refund the network already made is answered, not made again."""
        stale = self.store.stale_pending(older_than_seconds)
        for refund in stale:
            self._send(refund)
        return len(stale)

    def _send(self, refund):
        adapter = self.methods.for_method(refund.payment_method)
        try:
            result = adapter.refund(refund.transaction_id, refund.amount, refund.payment_reference,
                                    refund_id=f"rfnd_{refund.refund_id.hex}")
        except UnsupportedOperation as exc:  # nothing was sent: release the reservation
            return self.store.fail(refund.refund_id, {"error_code": "OPERATION_NOT_SUPPORTED",
                                                      "error_message": exc.message, "error_category": "VALIDATION_ERROR",
                                                      "retryable": False})
        except Exception:  # noqa: BLE001  timeout, lost connection, a 5xx: it may have been made. Stay PENDING.
            return refund
        if result.status == "FAILED":
            return self.store.fail(refund.refund_id, result.error or {
                "error_code": "REFUND_DECLINED", "error_message": "the network declined the refund",
                "error_category": "HARD_DECLINE", "retryable": False})
        if result.status == "PENDING":
            return refund
        return self.store.complete(refund.refund_id, result.method_reference)

    # --- capture and void ------------------------------------------------------------------------------------

    def capture(self, merchant_id: UUID, transaction_id: UUID) -> dict:
        """AUTHORIZED -> CAPTURED, the whole authorized amount, which posts the SALE."""
        return self._settle_hold(merchant_id, transaction_id, "CAPTURED", "captured",
                                 lambda adapter, txn, amount, ref: adapter.capture(txn, amount))

    def void(self, merchant_id: UUID, transaction_id: UUID) -> dict:
        """AUTHORIZED -> VOIDED: the hold is released and no money moved, so nothing is posted to the ledger."""
        return self._settle_hold(merchant_id, transaction_id, "VOIDED", "voided",
                                 lambda adapter, txn, amount, ref: adapter.void(txn, ref))

    def _settle_hold(self, merchant_id, transaction_id, target, verb, call) -> dict:
        payment = self.store.payment(merchant_id, transaction_id)
        if payment is None:
            raise NotFound("transaction not found", code="TRANSACTION_NOT_FOUND")
        status, amount, method, reference, _terminal = payment
        decision = transition(status, target)
        if decision == "reject":
            raise Conflict(f"a {status} transaction can't be {verb}", code={"CAPTURED": "TRANSACTION_NOT_CAPTURABLE", "VOIDED": "TRANSACTION_NOT_VOIDABLE"}[target])
        if decision == "noop":  # already done: capturing twice is the same capture
            return self.store.settle_hold(merchant_id, transaction_id, target, None)
        try:
            result = call(self.methods.for_method(method), transaction_id, amount, reference)
        except UnsupportedOperation:
            raise _not_supported(method, verb) from None
        except OutcomeUnknown:
            raise Conflict(f"the network didn't answer; the transaction stays {status}, retry the {verb[:-1]}",
                           code="OUTCOME_UNKNOWN") from None
        if result.status != target:
            raise Conflict(f"the network refused: {(result.error or {}).get('error_message', result.status)}",
                           code="NETWORK_REFUSED")
        return self.store.settle_hold(merchant_id, transaction_id, target, result.method_reference)
