"""The OFFLINE pseudo-adapter (Stage 1, Step 13).

This is not a rail: no money moves "offline" here. It exists so the registry can publish the limits the SDK
must enforce before a terminal loses connectivity — `offline_limits` in the capability descriptor is the only
way the terminal can know, because the cloud has not seen the payment yet.

An OFFLINE transaction is never initiated through this adapter. The sync endpoint re-submits each queued item
to its underlying rail, so the transaction is recorded against the rail that actually moved the money and the
normal idempotency, authorization and audit paths apply.
"""
from app.application.methods import CapabilityDescriptor, DisputeRules, Transition, UnsupportedOperation
from app.infrastructure.methods.base import BaseMethodAdapter

OFFLINE_CAPABILITIES = CapabilityDescriptor(
    payment_method="OFFLINE",
    supports_chargeback=False,
    supports_recurring=False,
    supports_offline=True,
    supports_refund=False,  # v1: an offline sale that synced is refunded through its rail's rules
    supports_partial_refund=False,
    supports_partial_capture=False,
    settlement_timeline="T+1_on_sync",
    auth_type="local_fraud_screening",
    is_synchronous=True,  # the terminal answers immediately; the cloud decides later
    dispute_rules=DisputeRules(framework="NONE", dispute_window_days=0),
    transitions=(
        Transition("INITIATED", "PENDING_OFFLINE"),
        Transition("PENDING_OFFLINE", "PENDING"),
        Transition("PENDING_OFFLINE", "FAILED"),
    ),
    offline_limits={"max_per_txn": 500_000, "currency": "INR", "max_age_minutes": 1440},
)


class OfflineMethodAdapter(BaseMethodAdapter):
    method = "OFFLINE"
    CAPABILITIES = OFFLINE_CAPABILITIES

    def send(self, request):
        raise UnsupportedOperation("offline sales are submitted through POST /api/v1/transactions/sync")
