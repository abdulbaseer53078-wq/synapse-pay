"""The cloud's offline-rules signing key (Step 20): ECDSA P-256 over the canonical JSON of each rule set.

shortcut: the key is a PEM the process reads at start (EDGE_RULES_KEY_PATH); move it into KMS (asymmetric
ECC_NIST_P256 sign) before production, so no instance ever holds the private key.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class EcdsaRulesSigner:
    def __init__(self, private_key_pem: str):
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("the edge rules signing key must be ECDSA P-256")
        self._key = key
        self.public_key_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message, ec.ECDSA(hashes.SHA256()))  # DER, like every signature in the system
