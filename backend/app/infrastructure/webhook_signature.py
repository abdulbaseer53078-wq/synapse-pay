"""Shared HMAC verification for inbound provider callbacks (Step 12b).

Two providers now sign callbacks, and signature verification is the last logic that should exist twice: a fix
applied to one copy and not the other is a vulnerability, not a bug. The only per-provider difference is the
header names, so they are parameters.

The signature covers `<timestamp>.<raw body>`. Signing the body alone would let a captured signature be
replayed forever by pairing it with a fresh timestamp header; binding them means the whole thing expires
together.
"""
import hashlib
import hmac
import time

from app.application.methods import WebhookRejected

REPLAY_WINDOW_SECONDS = 300


def verify_signature(raw: bytes, headers: dict, secret: str | None, *, timestamp_header: str,
                     signature_header: str, label: str, now=None, window: int = REPLAY_WINDOW_SECONDS) -> None:
    """Raise WebhookRejected unless `raw` carries a fresh, correctly signed payload. Never returns a value."""
    clock = now or time.time
    if not secret:
        # Fail closed: an unconfigured deployment must not accept unsigned callbacks.
        raise WebhookRejected(503, "WEBHOOK_NOT_CONFIGURED",
                              f"this deployment has no {label} webhook secret configured")
    timestamp = headers.get(timestamp_header.lower())
    signature = headers.get(signature_header.lower())
    if not timestamp or not signature:
        raise WebhookRejected(401, "MISSING_SIGNATURE", f"{timestamp_header} and {signature_header} are required")
    try:
        sent_at = int(timestamp)
    except ValueError:
        raise WebhookRejected(400, "INVALID_TIMESTAMP", f"{timestamp_header} must be unix seconds") from None
    if abs(int(clock()) - sent_at) > window:
        raise WebhookRejected(400, "STALE_TIMESTAMP", f"timestamp is more than {window}s from now")
    expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.strip().lower()):  # constant time: no byte-by-byte oracle
        raise WebhookRejected(401, "BAD_SIGNATURE", "signature does not match the body")
