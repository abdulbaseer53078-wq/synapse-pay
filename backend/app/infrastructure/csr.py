"""Checks every terminal CA applies, whoever signs: what a CSR must be, and how terminal signatures verify."""
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from app.application.registration import InvalidInput


def validated_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    """The CSR, if it parses, its signature is valid, and its key is EC P-256 or RSA >= 2048. Else InvalidInput."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except ValueError:
        raise InvalidInput("csr_pem is not a valid PEM certificate signing request")
    if not csr.is_signature_valid:
        raise InvalidInput("CSR signature is invalid")
    key = csr.public_key()
    if not (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
            or isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048):
        raise InvalidInput("CSR key must be EC P-256 or RSA of at least 2048 bits")
    return csr


def verify_signature(public_key_pem: str, message: bytes, signature: bytes) -> bool:
    key = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True
