"""Canonicalisation and verification for offline sync items (Step 13, contract 1.8.0).

A signature cannot cover the object that carries it, so both sides sign the item *without* the signature
field: keys sorted alphabetically, compact JSON, UTF-8. Every other serialisation — pretty-printed, insertion
order, floats reformatted — produces different bytes and fails, which is the point: there is one encoding, and
it is written down in the contract rather than emerging from whatever each language's JSON encoder happens to
do.

Verification reuses the certificate authority's existing check against the terminal's registration key, so
there is no second signing scheme for a terminal to get wrong.
"""
import base64
import binascii
import json

SIGNATURE_FIELD = "signature"


class OfflineSignatureInvalid(Exception):
    """The item is not provably the one the terminal queued. Never recoverable by retrying."""


def canonical_item(item: dict) -> bytes:
    """The exact bytes both sides sign: the item minus its signature, sorted keys, compact JSON, UTF-8."""
    body = {key: value for key, value in item.items() if key != SIGNATURE_FIELD}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_item(item: dict, public_key_pem: str, verify) -> None:
    """Raise OfflineSignatureInvalid unless the item's signature covers its canonical bytes.

    `verify(public_key_pem, message, signature) -> bool` is the CA's existing signature check.
    """
    encoded = item.get(SIGNATURE_FIELD)
    if not isinstance(encoded, str) or not encoded:
        raise OfflineSignatureInvalid("the item carries no signature")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OfflineSignatureInvalid("signature is not valid base64") from exc
    if not verify(public_key_pem, canonical_item(item), signature):
        raise OfflineSignatureInvalid("signature does not verify against the terminal's certificate")
