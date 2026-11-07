import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.application.registration import CertificateAuthorityUnavailable, IssuedCertificate
from app.domain.terminal import terminal_uri
from app.infrastructure.csr import validated_csr, verify_signature

PEM = serialization.Encoding.PEM
CRL_LIFETIME = timedelta(days=1)  # verifiers reject a stale CRL, so it must be re-signed within this window


class FileCertificateAuthority:
    """Issues terminal certificates from an intermediate CA whose key is read from disk, and publishes
    revocations as a signed CRL file that the mTLS gateway checks.

    shortcut: the CA key sits on disk and the CRL file is rewritten by a single process; move signing to
    AWS Private CA or a KMS/HSM-held key, with its managed CRL/OCSP, before production or multiple instances.
    """

    def __init__(self, cert_path: Path, key_path: Path, crl_path: Path, validity: timedelta = timedelta(days=365)):
        self.ca_certificate_pem = Path(cert_path).read_text()
        self._ca_cert = x509.load_pem_x509_certificate(self.ca_certificate_pem.encode())
        self._ca_key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
        self._crl_path = Path(crl_path)
        self._validity = validity
        if not self._crl_path.exists():
            self._publish_crl([])  # with CRL checking on, a missing CRL fails every handshake

    def revoke(self, serial_number: str) -> None:
        serial = int(serial_number, 16)
        try:
            revoked = list(x509.load_pem_x509_crl(self._crl_path.read_bytes()))
            if any(r.serial_number == serial for r in revoked):
                return
            entry = (x509.RevokedCertificateBuilder().serial_number(serial)
                     .revocation_date(datetime.now(UTC)).build())
            self._publish_crl([*revoked, entry])
        except (OSError, ValueError) as exc:
            raise CertificateAuthorityUnavailable("certificate revocation could not be published") from exc

    def _publish_crl(self, revoked: list[x509.RevokedCertificate]) -> None:
        now = datetime.now(UTC)
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self._ca_cert.subject)
                   .last_update(now).next_update(now + CRL_LIFETIME))
        for entry in revoked:
            builder = builder.add_revoked_certificate(entry)
        crl = builder.sign(self._ca_key, hashes.SHA256())
        tmp = self._crl_path.with_suffix(".tmp")
        tmp.write_bytes(crl.public_bytes(PEM))
        os.replace(tmp, self._crl_path)  # atomic: readers never see a half-written CRL

    def issue(self, csr_pem: str, terminal_id: UUID) -> IssuedCertificate:
        key = validated_csr(csr_pem).public_key()

        # The subject and extensions come from the registry, never from the CSR.
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(terminal_id))]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + self._validity)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(terminal_uri(terminal_id))]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                           critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )
        return IssuedCertificate(
            serial_number=format(cert.serial_number, "x"),
            certificate_pem=cert.public_bytes(PEM).decode(),
            public_key_pem=key.public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            issued_at=now,
            expires_at=now + self._validity,
        )

    def verify_signature(self, public_key_pem: str, message: bytes, signature: bytes) -> bool:
        return verify_signature(public_key_pem, message, signature)
