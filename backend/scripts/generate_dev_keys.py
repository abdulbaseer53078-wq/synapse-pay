"""
Generate local development keys for the Synapse backend.

Outputs (all in backend/ — the parent of this script's directory):
  dev_ca.key        EC P-256 private key for the dev CA (PEM)
  dev_ca.crt        Self-signed CA certificate (PEM)
  dev_ca.crl        Empty but validly-signed CRL (PEM)
  dev_jwt.key       EC P-256 private key for JWT signing (PEM)
  dev_jwt_pub.pem   Corresponding public key (PEM, SubjectPublicKeyInfo)

Safe to re-run: existing files are left untouched.
"""
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = Path(__file__).parent.parent  # backend/
PEM = serialization.Encoding.PEM


def _write_if_missing(path: Path, data: bytes) -> bool:
    if path.exists():
        print(f"  skip  {path.name}  (already exists)")
        return False
    path.write_bytes(data)
    print(f"  wrote {path.name}")
    return True


def generate() -> None:
    print("Generating dev keys …")

    # ── CA key ────────────────────────────────────────────────────────────────
    ca_key_path = OUT / "dev_ca.key"
    if ca_key_path.exists():
        print(f"  skip  dev_ca.key  (already exists)")
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    else:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        _write_if_missing(ca_key_path, ca_key.private_bytes(
            PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    # ── CA certificate ────────────────────────────────────────────────────────
    ca_cert_path = OUT / "dev_ca.crt"
    if ca_cert_path.exists():
        print(f"  skip  dev_ca.crt  (already exists)")
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    else:
        now = datetime.now(UTC)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synapse Dev CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        _write_if_missing(ca_cert_path, ca_cert.public_bytes(PEM))

    # ── CRL (empty, validly signed) ───────────────────────────────────────────
    crl_path = OUT / "dev_ca.crl"
    if not crl_path.exists():
        now = datetime.now(UTC)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=3650))  # long-lived: dev only
            .sign(ca_key, hashes.SHA256())
        )
        _write_if_missing(crl_path, crl.public_bytes(PEM))
    else:
        print(f"  skip  dev_ca.crl  (already exists)")

    # ── JWT key ───────────────────────────────────────────────────────────────
    jwt_key_path = OUT / "dev_jwt.key"
    if jwt_key_path.exists():
        print(f"  skip  dev_jwt.key  (already exists)")
        jwt_key = serialization.load_pem_private_key(jwt_key_path.read_bytes(), password=None)
    else:
        jwt_key = ec.generate_private_key(ec.SECP256R1())
        _write_if_missing(jwt_key_path, jwt_key.private_bytes(
            PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    _write_if_missing(
        OUT / "dev_jwt_pub.pem",
        jwt_key.public_key().public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    )

    print("Done. Run run_dev.ps1 to start the backend.")


if __name__ == "__main__":
    try:
        generate()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
