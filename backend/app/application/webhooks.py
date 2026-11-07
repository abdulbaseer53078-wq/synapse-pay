"""Webhooks (spec: transactionStatus): the final TransactionResponse, POSTed to the request's webhook_url,
signed with X-Signature = lowercase hex HMAC-SHA256(merchant's webhook secret, raw body).

Status changes write the webhook into an outbox in the same database transaction, so a committed payment
always gets its webhook; a dispatcher delivers due ones with exponential backoff.
"""
import hashlib
import hmac
from datetime import timedelta

MAX_ATTEMPTS = 12
FINAL_STATUSES = frozenset({"AUTHORIZED", "CAPTURED", "FAILED", "SETTLED", "VOIDED", "REFUNDED",
                            "PARTIALLY_REFUNDED"})


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def backoff(attempts: int) -> timedelta:
    """Delay before the next try after `attempts` failures: 10 s, 20 s, 40 s ... capped at 1 hour."""
    return timedelta(seconds=min(10 * 2 ** max(attempts - 1, 0), 3600))
