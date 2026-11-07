"""Step 5 end to end: backend → card service (Rust, simulated HSM) → host connector → mock acquirer over
mutual TLS (host-connector/mock_host/mock_host.py). Real processes, real ISO 8583 on the wire.

Needs cargo (builds card-service) and the openssl CLI (terminal fixtures). The mock acquirer picks the outcome
by amount: 5100 declines, 2000 times out, anything else approves."""
import os
import shutil
import statistics
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.infrastructure.card_service_client import HttpCardProcessor
from app.main import create_app
from card_sim import TEST_BDK_HEX, TEST_PAN, encrypted_card, encrypted_pin

ROOT = Path(__file__).parents[2]
PEM = serialization.Encoding.PEM

pytestmark = pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not on PATH (builds card-service)")


def _key_pem(key) -> bytes:
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _issue(ca_cert, ca_key, name: str, usage, san: x509.GeneralName | None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
               .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
    return builder.sign(ca_key, hashes.SHA256()), key


def _acquirer_pki(d: Path) -> None:
    """ca.pem, host.pem/host-key.pem (mock acquirer), client.pem/client-key.pem (card service)."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock Acquirer Test CA")])
    now = datetime.now(UTC)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    (d / "ca.pem").write_bytes(ca.public_bytes(PEM))
    for file, cn, usage, san in (("host", "localhost", ExtendedKeyUsageOID.SERVER_AUTH, x509.DNSName("localhost")),
                                 ("client", "synapsepay-card-service", ExtendedKeyUsageOID.CLIENT_AUTH, None)):
        cert, key = _issue(ca, ca_key, cn, usage, san)
        (d / f"{file}.pem").write_bytes(cert.public_bytes(PEM))
        (d / f"{file}-key.pem").write_bytes(_key_pem(key))


class Process:
    """A child process whose output is collected (to check it never contains card data)."""

    def __init__(self, args, env=None, cwd=None):
        self.proc = subprocess.Popen(args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True)
        self.lines: list[str] = []
        self.ready = threading.Event()
        self.listening: str | None = None
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self):
        for line in self.proc.stdout:
            self.lines.append(line)
            if line.startswith("LISTENING "):
                self.listening = line.split()[1]
                self.ready.set()
        self.ready.set()

    def wait_listening(self, timeout: float) -> str:
        assert self.ready.wait(timeout) and self.listening, "".join(self.lines)
        return self.listening

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    @property
    def output(self) -> str:
        return "".join(self.lines)


@pytest.fixture(scope="session")
def card_service_binary():
    build = subprocess.run(["cargo", "build", "--quiet", "--bin", "card_service"], cwd=ROOT / "card-service",
                           capture_output=True, text=True, timeout=900)
    assert build.returncode == 0, build.stderr
    return ROOT / "card-service" / "target" / "debug" / "card_service"


@pytest.fixture(scope="session")
def acquirer(tmp_path_factory, card_service_binary):
    """(card service URL, mock acquirer process, card service process, audit log path)."""
    d = tmp_path_factory.mktemp("acquirer")
    _acquirer_pki(d)
    dialect = ROOT / "iso8583" / "dialects" / "synthetic-host.json"
    mock = Process([os.environ.get("PYTHON", "python3"), str(ROOT / "host-connector" / "mock_host" / "mock_host.py"),
                    "--dialect", str(dialect), "--cert", str(d / "host.pem"), "--key", str(d / "host-key.pem"),
                    "--client-ca", str(d / "ca.pem"), "--sleep", "5"])
    host_port = mock.wait_listening(10)
    audit = d / "iso-audit.jsonl"
    env = {**os.environ, "SIM_HSM_BDK_HEX": TEST_BDK_HEX, "HOST_ADDR": f"127.0.0.1:{host_port}",
           "HOST_SERVER_NAME": "localhost", "HOST_CA": str(d / "ca.pem"), "HOST_CLIENT_CERT": str(d / "client.pem"),
           "HOST_CLIENT_KEY": str(d / "client-key.pem"), "HOST_DIALECT": str(dialect), "HOST_POOL_SIZE": "4",
           "HOST_TIMEOUT_MS": "1500", "AUDIT_LOG_PATH": str(audit), "CARD_SERVICE_ADDR": "127.0.0.1:0"}
    service = Process([str(card_service_binary)], env=env)
    addr = service.wait_listening(30)
    yield f"http://{addr}", mock, service, audit
    service.stop()
    mock.stop()


@pytest.fixture
def e2e_client(settings, db, acquirer):
    cards = HttpCardProcessor(acquirer[0])
    with TestClient(create_app(settings, cards=cards)) as c:
        yield c
    cards.close()


@pytest.fixture
def ready(db, active):
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', 10000000, 100000000) RETURNING profile_id").fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now()"
               " WHERE terminal_id = %s", (profile_id, active["terminal_id"]))
    return active


@pytest.fixture
def pay(e2e_client, ready, merchant):
    def call(amount, pin=None):
        details = {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA"}
        if pin:
            details["pin_block"] = encrypted_pin(pin)
        body = {"idempotency_key": str(uuid4()), "amount": amount, "currency": "INR", "payment_method": "CARD",
                "method_details": details, "terminal_id": ready["terminal_id"], "merchant_id": str(merchant)}
        r = e2e_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
        assert r.status_code in (201, 400), r.text
        return r
    return call


def test_approval_end_to_end(pay, db):
    r = pay(15000)
    assert r.json()["status"] == "CAPTURED" and r.json()["auth_code"] == "AUTH00", r.text
    assert db.execute("SELECT card_bin, card_last4 FROM transactions").fetchone() == ("411111", "1111")


def test_decline_end_to_end(pay):
    r = pay(5100)
    assert r.json()["status"] == "FAILED" and r.json()["error"]["error_code"] == "INSUFFICIENT_FUNDS"


def test_pin_payment_over_5000_rupees(pay):
    assert pay(600000, pin="1234").json()["status"] == "CAPTURED"


def test_host_timeout_is_reversed_end_to_end(pay, db, acquirer):
    started = time.monotonic()
    r = pay(2000)
    body = r.json()
    assert body["status"] == "FAILED" and body["error"]["error_code"] == "HOST_TIMEOUT", r.text
    assert body["error"]["retryable"] is True
    assert db.execute("SELECT reversal FROM transactions").fetchone() == ("REVERSED",)
    assert time.monotonic() - started < 6
    assert "0400" in acquirer[1].output and "-> reversed" in acquirer[1].output, "the acquirer got the reversal"


def test_undecryptable_card_is_rejected_end_to_end(e2e_client, ready, merchant):
    body = {"idempotency_key": str(uuid4()), "amount": 15000, "currency": "INR", "payment_method": "CARD",
            "method_details": {"encrypted_card_data": encrypted_card(bdk_hex="11" * 32), "card_expiry": "08/28",
                               "card_network": "VISA"},
            "terminal_id": ready["terminal_id"], "merchant_id": str(merchant)}
    r = e2e_client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
    assert r.status_code == 400 and r.json()["error_code"] == "INVALID_REQUEST"


def test_p95_latency_under_2_seconds(pay):
    pay(15000)  # warm up
    times = []
    for _ in range(30):
        started = time.monotonic()
        assert pay(15000).json()["status"] == "CAPTURED"
        times.append(time.monotonic() - started)
    p95 = statistics.quantiles(times, n=20)[-1]
    print(f"card payment latency: median {statistics.median(times) * 1000:.0f} ms, p95 {p95 * 1000:.0f} ms")
    assert p95 < 2.0, f"p95 {p95:.3f}s"


def test_card_number_never_leaves_the_card_service(pay, acquirer):
    pay(15000)
    _, mock, service, audit = acquirer
    assert TEST_PAN not in service.output, "card service output"
    assert TEST_PAN not in audit.read_text(), "ISO 8583 audit log"
    assert '"2":"411111******1111"' in audit.read_text(), "DE 2 is audited masked"
