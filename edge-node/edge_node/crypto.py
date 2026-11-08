"""Signatures the edge makes and checks: ECDSA P-256 (DER, base64) over canonical JSON — the item without its
"signature" field, keys sorted, no insignificant whitespace, UTF-8. The same bytes the cloud computes (spec 1.8.0),
so any other serialisation simply fails to verify."""
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SIGNATURE = "signature"


def canonical(item: dict) -> bytes:
    body = {k: v for k, v in item.items() if k != SIGNATURE}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(private_key_pem: str, item: dict) -> str:
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return base64.b64encode(key.sign(canonical(item), ec.ECDSA(hashes.SHA256()))).decode()


def verify(public_key_pem: str, item: dict) -> bool:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode())
        key.verify(base64.b64decode(item.get(SIGNATURE) or "", validate=True), canonical(item),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
