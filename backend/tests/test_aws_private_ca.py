"""Step 17.4: terminal certificates from AWS Private CA. botocore's Stubber checks every call against the real
ACM PCA API model, so a wrong parameter name or shape fails here, without AWS."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import boto3
import pytest
from botocore.stub import ANY, Stubber
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.application.registration import CertificateAuthorityUnavailable, InvalidInput
from app.domain.terminal import terminal_uri
from app.infrastructure.aws_private_ca import CLIENT_AUTH_TEMPLATE, AwsPrivateCertificateAuthority, _colon_hex

ARN = "arn:aws:acm-pca:ap-south-1:123456789012:certificate-authority/11111111-2222-3333-4444-555555555555"
CERT_ARN = ARN + "/certificate/abcdef"
PEM = serialization.Encoding.PEM


def _ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SynapsePay Terminal CA")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    return key, cert


def _terminal_csr():
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "whatever-the-device-says")]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(PEM).decode(), key


def _signed(ca, csr_pem, terminal_id):
    """What PCA would return for this CSR: subject and SAN from the passthrough, not the CSR."""
    ca_key, ca_cert = ca
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    now = datetime.now(UTC).replace(microsecond=0)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(terminal_id))]))
            .issuer_name(ca_cert.subject).public_key(csr.public_key()).serial_number(0x0A1B2C)
            .not_valid_before(now).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(terminal_uri(terminal_id))]),
                           critical=False)
            .sign(ca_key, hashes.SHA256())).public_bytes(PEM).decode()


@pytest.fixture
def pca():
    client = boto3.client("acm-pca", region_name="ap-south-1", aws_access_key_id="test", aws_secret_access_key="test")
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


def _authority(pca, ca):
    client, stub = pca
    stub.add_response("get_certificate_authority_certificate",
                      {"Certificate": ca[1].public_bytes(PEM).decode()}, {"CertificateAuthorityArn": ARN})
    return AwsPrivateCertificateAuthority(ARN, client=client, poll_seconds=0)


def test_issues_with_the_registry_subject_and_san_not_the_csrs(pca):
    ca, terminal_id = _ca(), uuid4()
    csr_pem, terminal_key = _terminal_csr()
    authority = _authority(pca, ca)
    _, stub = pca
    stub.add_response("issue_certificate", {"CertificateArn": CERT_ARN}, {
        "CertificateAuthorityArn": ARN, "Csr": csr_pem.encode(), "SigningAlgorithm": "SHA256WITHECDSA",
        "TemplateArn": CLIENT_AUTH_TEMPLATE, "Validity": {"Value": 365, "Type": "DAYS"},
        "ApiPassthrough": {"Subject": {"CommonName": str(terminal_id)},
                           "Extensions": {"SubjectAlternativeNames": [
                               {"UniformResourceIdentifier": terminal_uri(terminal_id)}]}},
        "IdempotencyToken": ANY,
    })
    # Issuance is asynchronous: the first poll finds it still in progress.
    stub.add_client_error("get_certificate", service_error_code="RequestInProgressException",
                          expected_params={"CertificateAuthorityArn": ARN, "CertificateArn": CERT_ARN})
    signed = _signed(ca, csr_pem, terminal_id)
    stub.add_response("get_certificate", {"Certificate": signed},
                      {"CertificateAuthorityArn": ARN, "CertificateArn": CERT_ARN})

    issued = authority.issue(csr_pem, terminal_id)

    assert issued.serial_number == "a1b2c" and issued.certificate_pem == signed
    assert issued.public_key_pem == terminal_key.public_key().public_bytes(
        PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert issued.expires_at - issued.issued_at == timedelta(days=365)
    assert "SynapsePay Terminal CA" in x509.load_pem_x509_certificate(authority.ca_certificate_pem.encode()).subject.rfc4514_string()


def test_a_bad_csr_never_reaches_the_ca(pca):
    authority = _authority(pca, _ca())
    with pytest.raises(InvalidInput):
        authority.issue("-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----\n", uuid4())


def test_ca_failures_surface_as_unavailable(pca):
    authority = _authority(pca, _ca())
    _, stub = pca
    stub.add_client_error("issue_certificate", service_error_code="LimitExceededException")
    with pytest.raises(CertificateAuthorityUnavailable):
        authority.issue(_terminal_csr()[0], uuid4())


def test_revocation_uses_colon_hex_and_is_idempotent(pca):
    authority = _authority(pca, _ca())
    _, stub = pca
    expected = {"CertificateAuthorityArn": ARN, "CertificateSerial": "0a:1b:2c", "RevocationReason": "UNSPECIFIED"}
    stub.add_response("revoke_certificate", {}, expected)
    stub.add_client_error("revoke_certificate", service_error_code="RequestAlreadyProcessedException",
                          expected_params=expected)
    stub.add_client_error("revoke_certificate", service_error_code="ResourceNotFoundException",
                          expected_params=expected)
    authority.revoke("a1b2c")
    authority.revoke("a1b2c")  # already revoked: not an error
    with pytest.raises(CertificateAuthorityUnavailable):
        authority.revoke("a1b2c")


def test_colon_hex_pads_to_whole_bytes():
    assert (_colon_hex("a1b2c"), _colon_hex("FF00"), _colon_hex("1")) == ("0a:1b:2c", "ff:00", "01")
