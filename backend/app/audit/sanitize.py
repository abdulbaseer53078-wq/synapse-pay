"""PAN / PII masking (Step 7.5).

The audit log is read by support staff and auditors. Whatever is in it is, by definition, readable by anyone
with `audit:read` — so card data must never reach it. Two independent defences:

1. Key rules — a field named `pan`, `cvv`, `pin_block`, `encrypted_card_data` … is masked whatever it holds.
2. Value rules — any 13–19 digit run that passes the Luhn check is a card number, whatever field it is in.

The second rule is the one that matters: it catches a PAN a caller put in `metadata.note` because nobody told
them not to. Masking keeps the first six and last four (PCI DSS allows displaying BIN + last4); anything that
looks like a secret (CVV, PIN block, track data) is removed entirely rather than partially shown.

Deliberately *not* preserved: the raw value anywhere, including the hash. A hash of a PAN is still a PAN
oracle for a 16-digit space.
"""
import re

# Matched against lowercased key names. Deliberately broad: a false positive only loses an audit detail,
# a false negative leaks card data.
_SECRET_KEYS = re.compile(
    r"(cvv|cvc|cvv2|csc|pin|pin_block|pinblock|track[ _]?[12]?|track_data|magstripe|"
    r"encrypted_card|encrypted_pan|card_number|pan|account_number|iban)", re.IGNORECASE)

# A PAN in a string field: 13–19 digits, optionally spaced or dashed.
_PAN_LIKE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_DIGITS = re.compile(r"\D")

REMOVED = "[redacted]"


def luhn_ok(digits: str) -> bool:
    """The card-number checksum. Random digit runs almost never pass it, which keeps false positives low."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def mask_pan(digits: str) -> str:
    """`4111111111111111` → `************1111`. BIN is available from the transactions table, not from here."""
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def _mask_value(value: str) -> str:
    """Mask any Luhn-valid PAN inside a free-text value, leaving the rest of the text readable."""

    def replace(match: re.Match) -> str:
        digits = _DIGITS.sub("", match.group(0))
        return mask_pan(digits) if luhn_ok(digits) else match.group(0)

    return _PAN_LIKE.sub(replace, value)


def sanitize(value, _depth: int = 0):
    """Recursively mask a JSON-shaped value. Returns a new structure; the input is never mutated."""
    if _depth > 32:
        return REMOVED
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_KEYS.search(key):
                clean[key] = REMOVED
            else:
                clean[key] = sanitize(item, _depth + 1)
        return clean
    if isinstance(value, (list, tuple)):
        return [sanitize(item, _depth + 1) for item in value]
    if isinstance(value, str):
        return _mask_value(value)
    return value
