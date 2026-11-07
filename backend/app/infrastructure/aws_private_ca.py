"""Terminal certificates from AWS Private CA (Stage 4, Step 17.4).

One CA for every region and every API instance: the private key never leaves the CA's HSM, and revocations go
to the CA's CRL in S3 (configured on the CA, see infra/ecs), which every region's gateway reads. That is what
the file-based CA can't do once more than one process runs: each process signed with its own copy of the key
and kept its own CRL, so a terminal revoked in one region still connected in the other.

The registry decides the subject and extensions, never the CSR: issuance uses the APIPassthrough client-auth
template, with the terminal_id as CN and as the URI SAN the gateway reads.
"""
import hashlib
import time
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.application.registration import CertificateAuthorityUnavailable, IssuedCertificate
from app.domain.terminal import terminal_uri
from app.infrastructure.csr import validated_csr, verify_signature

PEM = serialization.Encoding.PEM
CLIENT_AUTH_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate_APIPassthrough/V1"


def _colon_hex(serial_hex: str) -> str:
    """PCA wants serials as colon-separated byte pairs, e.g. 0a:1b:2c."""
    s = serial_hex.lower()
    s = "0" + s if len(s) % 2 else s
    return ":".join(s[i:i + 2] for i in range(0, len(s), 2))


class AwsPrivateCertificateAuthority:
    def __init__(self, ca_arn: str, client=None, validity_days: int = 365,
                 signing_algorithm: str = "SHA256WITHECDSA", poll_seconds: float = 1.0, poll_attempts: int = 30):
        if client is None:
            import boto3  # only this deployment needs it

            client = boto3.client("acm-pca", region_name=ca_arn.split(":")[3])
        self._client = client
        self._arn = ca_arn
        self._validity_days = validity_days
        self._signing_algorithm = signing_algorithm
        self._poll_seconds = poll_seconds
        self._poll_attempts = poll_attempts
        chain = client.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)
        self.ca_certificate_pem = "\n".join(p for p in (chain["Certificate"], chain.get("CertificateChain")) if p)

    def issue(self, csr_pem: str, terminal_id: UUID) -> IssuedCertificate:
        key = validated_csr(csr_pem).public_key()
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            certificate_arn = self._client.issue_certificate(
                CertificateAuthorityArn=self._arn,
                Csr=csr_pem.encode(),
                SigningAlgorithm=self._signing_algorithm,
                TemplateArn=CLIENT_AUTH_TEMPLATE,
                Validity={"Value": self._validity_days, "Type": "DAYS"},
                ApiPassthrough={
                    "Subject": {"CommonName": str(terminal_id)},
                    "Extensions": {"SubjectAlternativeNames": [{"UniformResourceIdentifier": terminal_uri(terminal_id)}]},
                },
                # A retry of the same request gets the same certificate, but a new CSR is a new certificate.
                IdempotencyToken=hashlib.sha256(f"{terminal_id}|{csr_pem}".encode()).hexdigest()[:36],
            )["CertificateArn"]
            pem = self._wait_for(certificate_arn)
        except (BotoCoreError, ClientError) as exc:
            raise CertificateAuthorityUnavailable("the terminal CA couldn't issue the certificate") from exc

        cert = x509.load_pem_x509_certificate(pem.encode())
        return IssuedCertificate(
            serial_number=format(cert.serial_number, "x"),
            certificate_pem=pem,
            public_key_pem=key.public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            issued_at=cert.not_valid_before_utc,
            expires_at=cert.not_valid_after_utc,
        )

    def _wait_for(self, certificate_arn: str) -> str:
        from botocore.exceptions import ClientError

        for _ in range(self._poll_attempts):
            try:
                return self._client.get_certificate(CertificateAuthorityArn=self._arn,
                                                    CertificateArn=certificate_arn)["Certificate"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "RequestInProgressException":
                    raise
                time.sleep(self._poll_seconds)
        raise CertificateAuthorityUnavailable("the terminal CA didn't finish issuing in time")

    def revoke(self, serial_number: str) -> None:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            self._client.revoke_certificate(CertificateAuthorityArn=self._arn,
                                            CertificateSerial=_colon_hex(serial_number),
                                            RevocationReason="UNSPECIFIED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "RequestAlreadyProcessedException":
                return  # already revoked: revocation is idempotent
            raise CertificateAuthorityUnavailable("the terminal CA couldn't revoke the certificate") from exc
        except BotoCoreError as exc:
            raise CertificateAuthorityUnavailable("the terminal CA couldn't revoke the certificate") from exc

    def verify_signature(self, public_key_pem: str, message: bytes, signature: bytes) -> bool:
        return verify_signature(public_key_pem, message, signature)
