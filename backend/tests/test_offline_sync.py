"""The canonical offline-item signature (Step 13): the rule that stops a tampered local queue."""
import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.application.offline_sync import OfflineSignatureInvalid, canonical_item, verify_item

ITEM = {"offline_reference": "11111111-1111-4111-8111-111111111111",
        "local_timestamp": "2026-11-07T14:00:00Z", "amount": 250000, "currency": "INR",
        "payment_method": "CARD", "terminal_id": "t1", "merchant_id": "m1",
        "idempotency_key": "22222222-2222-4222-8222-222222222222", "method_details": {"a": 1}}


def _key():
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return private, pem


def _sign(private, item: dict) -> str:
    signature = private.sign(canonical_item(item), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()


def _verify(pem, message, signature):
    try:
        serialization.load_pem_public_key(pem.encode()).verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _signed_item():
    private, pem = _key()
    return {**ITEM, "signature": _sign(private, ITEM)}, pem


def test_a_signed_item_verifies():
    item, pem = _signed_item()
    verify_item(item, pem, _verify)  # no raise


def test_the_signature_is_not_part_of_the_signed_bytes():
    item, _ = _signed_item()
    assert b"signature" not in canonical_item(item)


def test_reordering_keys_does_not_change_the_signature():
    """Sorted keys mean a client cannot break its own signature by serialising in a different order."""
    item, pem = _signed_item()
    reordered = {key: item[key] for key in reversed(list(item))}
    assert canonical_item(reordered) == canonical_item(item)
    verify_item(reordered, pem, _verify)


def test_an_inflated_amount_fails_verification():
    """The attack this exists for: edit the local queue, change 250000 to 25000000, sync."""
    item, pem = _signed_item()
    tampered = {**item, "amount": 25_000_000}
    with pytest.raises(OfflineSignatureInvalid, match="does not verify"):
        verify_item(tampered, pem, _verify)


def test_a_different_terminals_key_fails():
    item, _ = _signed_item()
    _, other_pem = _key()
    with pytest.raises(OfflineSignatureInvalid):
        verify_item(item, other_pem, _verify)


@pytest.mark.parametrize("broken", [{}, {"signature": ""}, {"signature": "not base64!"}])
def test_missing_or_malformed_signatures_are_rejected(broken):
    _, pem = _key()
    with pytest.raises(OfflineSignatureInvalid):
        verify_item({**ITEM, **broken}, pem, _verify)


def test_pretty_printed_json_would_not_match():
    """Why the rule names a serialisation: whitespace changes the bytes and the signature breaks."""
    pretty = json.dumps({k: v for k, v in ITEM.items()}, sort_keys=True, indent=2).encode()
    assert pretty != canonical_item(ITEM)
