"""The transaction state machine: which status changes are legal. Every writer of `transactions.status` asks this
first, so a late or wrong answer (a FAILED webhook for a payment already SETTLED) can never overwrite a final one.

Pure rules, no I/O. Card success is PENDING → CAPTURED (or AUTHORIZED for manual capture); UPI and QR success is
PENDING → SETTLED. PENDING → PENDING is legal: an unknown outcome or an asynchronous collect finishes as PENDING.
"""
from typing import Literal

VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "INITIATED": frozenset({"PENDING", "FAILED"}),
    "PENDING": frozenset({"PENDING", "AUTHORIZED", "CAPTURED", "SETTLED", "FAILED"}),
    "AUTHORIZED": frozenset({"CAPTURED", "VOIDED", "FAILED"}),
    "CAPTURED": frozenset({"SETTLED", "REFUNDED", "PARTIALLY_REFUNDED"}),
    "SETTLED": frozenset({"REFUNDED", "PARTIALLY_REFUNDED"}),
    "PARTIALLY_REFUNDED": frozenset({"PARTIALLY_REFUNDED", "REFUNDED"}),
    "FAILED": frozenset(),
    "VOIDED": frozenset(),
    "REFUNDED": frozenset(),
}


def transition(current: str, new: str) -> Literal["apply", "noop", "reject"]:
    """apply: write it. noop: the same final answer again (a re-sent success), nothing to do. reject: illegal."""
    if new in VALID_TRANSITIONS.get(current, frozenset()):
        return "apply"
    return "noop" if new == current else "reject"
