"""Tests need Postgres: `docker compose up -d db` from the repo root, or set TEST_DATABASE_URL."""
import base64
import os
import re
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
import psycopg
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.config import DEFAULT_APPROVED_MODELS, Settings
from app.main import create_app
from terminal_sim import SimulatedTerminal, register_body, url

MIGRATIONS = Path(__file__).parents[2] / "db" / "migrations"
ADMIN_URL = os.environ.get("TEST_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres")
TEST_DB = os.environ.get("TEST_DB_NAME", "synapse_test")  # set a different name to run suites in parallel
PEM = serialization.Encoding.PEM


@pytest.fixture(scope="session")
def database_url():
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {TEST_DB}")
    url = ADMIN_URL.rsplit("/", 1)[0] + "/" + TEST_DB
    with psycopg.connect(url, autocommit=True) as conn:
        for migration in sorted(MIGRATIONS.glob("*.sql")):
            conn.execute(migration.read_text())
    return url


@pytest.fixture
def db(database_url):
    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute("TRUNCATE merchants, terminals, certificates, heartbeats,"
                     " registration_tokens, activation_challenges, audit_log, certification_profiles CASCADE")
        yield conn


def _key_pem(key) -> bytes:
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture(scope="session")
def ca(tmp_path_factory):
    """(cert, key, crl) paths of a throwaway CA. The CRL file is created by the app's CA on startup."""
    d = tmp_path_factory.mktemp("ca")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SynapsePay Test Intermediate CA")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    (d / "ca.pem").write_bytes(cert.public_bytes(PEM))
    (d / "ca-key.pem").write_bytes(_key_pem(key))
    return d / "ca.pem", d / "ca-key.pem", d / "crl.pem"


@pytest.fixture(scope="session")
def gateway_server_cert(ca, tmp_path_factory):
    """(cert, key) for the stand-in gateway's TLS server, issued by the test CA."""
    d = tmp_path_factory.mktemp("gateway")
    ca_cert = x509.load_pem_x509_certificate(ca[0].read_bytes())
    ca_key = serialization.load_pem_private_key(ca[1].read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            # Strict TLS clients (Python 3.13+ defaults) require the AKI on any non-root certificate.
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (d / "server.pem").write_bytes(cert.public_bytes(PEM))
    (d / "server-key.pem").write_bytes(_key_pem(key))
    return d / "server.pem", d / "server-key.pem"


@pytest.fixture(scope="session")
def jwt_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def settings(database_url, ca, jwt_key):
    public = jwt_key.public_key().public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return Settings(database_url, *ca, public, {name: re.compile(p) for name, p in DEFAULT_APPROVED_MODELS.items()})


@pytest.fixture
def client(settings, db):
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def merchant(db):
    merchant_id = uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    return merchant_id


@pytest.fixture
def terminal(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not on PATH")
    return SimulatedTerminal(tmp_path / "terminal")


@pytest.fixture
def created(client, auth, merchant):
    """A PENDING terminal record, as returned by POST /terminals."""
    r = client.post("/api/v1/terminals", headers=auth(), json={
        "merchant_id": str(merchant), "device_serial": "SN-001", "device_model": "PAX A920 Pro",
        "metadata": {"location": "Till 1"}})
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def registered(client, created, terminal):
    """Registers `created` (→ PENDING_ACTIVATION); saves the certificate as terminal.cert; returns the response."""
    r = client.post(url(created, "register"), json=register_body(created["registration_token"], terminal.csr()))
    assert r.status_code == 200, r.text
    terminal.cert = terminal.dir / "terminal-cert.pem"
    terminal.cert.write_text(r.json()["certificate_pem"])
    return r.json()


@pytest.fixture
def active(client, created, terminal, registered):
    """`created`, taken through activation to ACTIVE."""
    signature = terminal.sign(base64.b64decode(registered["activation_challenge"]))
    assert client.post(url(created, "activate"), json={"signed_challenge": signature}).status_code == 200
    return created


@pytest.fixture
def auth(jwt_key, merchant):
    """Headers carrying an access token; defaults to registry:write for `merchant`."""
    def headers(sub=merchant, scope="registry:write"):
        token = jwt.encode({"sub": str(sub), "scope": scope, "exp": int(time.time()) + 300}, jwt_key, "ES256")
        return {"Authorization": f"Bearer {token}"}
    return headers
