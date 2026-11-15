#!/usr/bin/env python3
"""Generate dev keys for local Synapse Pay development into .sandbox/.

Idempotent: does nothing if .sandbox/platform-ca.pem already exists.
Run from anywhere; the repo root is inferred from this file's location.

Requires: cryptography   (pip install cryptography)
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    sys.exit("Install the 'cryptography' package first:  pip install cryptography")

ROOT = Path(__file__).resolve().parents[2]  # …/synapse-pay/
OUT = ROOT / ".sandbox"
PEM = serialization.Encoding.PEM

_now = datetime.now(UTC)
_1y = _now + timedelta(days=365)


def _key_pem(key) -> bytes:
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _ca(name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now - timedelta(minutes=1))
        .not_valid_after(_1y)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(ca_cert, ca_key, name: str, usage, san=None):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now - timedelta(minutes=1))
        .not_valid_after(_1y)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
    return builder.sign(ca_key, hashes.SHA256()), key


def _crl(ca_cert, ca_key) -> bytes:
    """An empty CRL signed by the CA.  FileCertificateAuthority would create one at startup if
    it's missing, but writing it here avoids a startup-time write to the filesystem."""
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(_now - timedelta(minutes=1))
        .next_update(_now + timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )
    return crl.public_bytes(PEM)


def main() -> None:
    if (OUT / "platform-ca.pem").exists():
        print(f"Keys already exist in {OUT}  (delete to regenerate)")
        return

    OUT.mkdir(parents=True, exist_ok=True)

    # --- Acquirer PKI: mock ISO 8583 host <-> card-service mTLS ---
    acq_ca, acq_key = _ca("Mock Acquirer Sandbox CA")
    (OUT / "ca.pem").write_bytes(acq_ca.public_bytes(PEM))
    (OUT / "ca-key.pem").write_bytes(_key_pem(acq_key))

    host_cert, host_key = _leaf(
        acq_ca, acq_key, "localhost", ExtendedKeyUsageOID.SERVER_AUTH, x509.DNSName("localhost")
    )
    (OUT / "host.pem").write_bytes(host_cert.public_bytes(PEM))
    (OUT / "host-key.pem").write_bytes(_key_pem(host_key))

    client_cert, client_key = _leaf(
        acq_ca, acq_key, "synapsepay-card-service", ExtendedKeyUsageOID.CLIENT_AUTH
    )
    (OUT / "client.pem").write_bytes(client_cert.public_bytes(PEM))
    (OUT / "client-key.pem").write_bytes(_key_pem(client_key))

    # Checkout key (card-service HSM uses this for checkout session tokens)
    (OUT / "checkout-key.pem").write_bytes(_key_pem(ec.generate_private_key(ec.SECP256R1())))

    # --- Platform CA: signs terminal certificates; backend uses it for mTLS gateway ---
    plat_ca, plat_key = _ca("Synapse Pay Sandbox Terminal CA")
    (OUT / "platform-ca.pem").write_bytes(plat_ca.public_bytes(PEM))
    (OUT / "platform-ca-key.pem").write_bytes(_key_pem(plat_key))
    (OUT / "platform-crl.pem").write_bytes(_crl(plat_ca, plat_key))

    # --- JWT keypair: signs merchant and admin access tokens ---
    jwt = ec.generate_private_key(ec.SECP256R1())
    (OUT / "jwt-key.pem").write_bytes(_key_pem(jwt))
    (OUT / "jwt-public.pem").write_bytes(
        jwt.public_key().public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )

    print(f"Dev keys written to {OUT}")
    print("  platform-ca.pem / platform-ca-key.pem  ->  CA_CERT_PATH / CA_KEY_PATH")
    print("  platform-crl.pem                        ->  CA_CRL_PATH")
    print("  jwt-public.pem                          ->  JWT_PUBLIC_KEY_PATH")


if __name__ == "__main__":
    main()
