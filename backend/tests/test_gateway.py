"""Task 2.8 acceptance: the Envoy gateway (gateway/envoy.yaml) in front of the real backend.
Needs Docker. Runs the backend with uvicorn and Envoy in a container, then makes real mTLS requests."""
import base64
import json
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.main import create_app
from terminal_sim import change

ENVOY_IMAGE = "envoyproxy/envoy:v1.31.2"
ENVOY_CONFIG = Path(__file__).parents[2] / "gateway" / "envoy.yaml"
PEM = serialization.Encoding.PEM


def _docker_available() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "info"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker is not running")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def backend_port(settings, db):
    """The app, served over real HTTP for Envoy to reach (same database and CA as `client`)."""
    port = _free_port()
    # 0.0.0.0: on Linux the container reaches the host through the bridge gateway, not the host's loopback
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="0.0.0.0", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, "backend did not start"
        time.sleep(0.05)
    yield port
    server.should_exit = True
    thread.join(timeout=10)


class Envoy:
    def __init__(self, workdir: Path, ca, server_cert, backend_port: int):
        self.dir = workdir / "etc"
        self.dir.mkdir()
        self.ca = ca
        for src, name in [(ca[0], "ca.pem"), (server_cert[0], "server.pem"), (server_cert[1], "server-key.pem")]:
            shutil.copy(src, self.dir / name)
        config = ENVOY_CONFIG.read_text().replace("port_value: 8000", f"port_value: {backend_port}")
        (self.dir / "envoy.yaml").write_text(config)
        self.name = f"synapse-envoy-{uuid4().hex[:8]}"
        self.port = _free_port()
        self.start()

    def start(self):
        shutil.copy(self.ca[2], self.dir / "crl.pem")  # the CA's current CRL, as a deploy would ship it
        subprocess.run(["docker", "run", "-d", "--rm", "--name", self.name, "-p", f"127.0.0.1:{self.port}:8443",
                        "--add-host", "host.docker.internal:host-gateway",  # Docker Desktop has it; Linux doesn't
                        "-v", f"{self.dir}:/etc/synapse:ro", ENVOY_IMAGE, "-c", "/etc/synapse/envoy.yaml",
                        "--log-level", "warn"], check=True, capture_output=True)
        deadline = time.time() + 30
        probe = ssl.create_default_context(cafile=self.ca[0])
        while True:  # a TLS handshake, not a TCP connect: Docker's port proxy accepts before Envoy listens
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1) as raw:
                    probe.wrap_socket(raw, server_hostname="localhost").close()
                return
            except ssl.SSLError as e:
                if not isinstance(e, ssl.SSLEOFError):
                    return  # Envoy answered the handshake (and wants a client certificate)
            except OSError:
                pass
            if time.time() > deadline:
                logs = subprocess.run(["docker", "logs", self.name], capture_output=True, text=True)
                raise AssertionError(f"Envoy did not start:\n{logs.stdout}{logs.stderr}")
            time.sleep(0.2)

    def restart(self):
        """Envoy reads the CRL at startup (see gateway/envoy.yaml)."""
        self.stop()
        self.start()

    def stop(self):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        while subprocess.run(["docker", "inspect", self.name], capture_output=True).returncode == 0:
            time.sleep(0.2)

    def request(self, method: str, path: str, cert: Path, key: Path, **kwargs) -> httpx.Response:
        ctx = ssl.create_default_context(cafile=self.ca[0])
        ctx.load_cert_chain(cert, key)
        with httpx.Client(verify=ctx, timeout=10) as http:
            return http.request(method, f"https://localhost:{self.port}{path}", **kwargs)


@pytest.fixture
def envoy(tmp_path, ca, gateway_server_cert, backend_port):
    gw = Envoy(tmp_path, ca, gateway_server_cert, backend_port)
    yield gw
    gw.stop()


def _terminal_path(created, rest="") -> str:
    return f"/api/v1/terminals/{created['terminal_id']}{rest}"


def _reached_backend(r: httpx.Response) -> bool:
    # The backend asks for a bearer token; the gateway never does. So 401 means the request got through.
    return r.status_code == 401 and r.json()["error_message"] == "missing bearer token"


def test_active_terminal_passes(active, terminal, envoy):
    r = envoy.request("GET", _terminal_path(active), terminal.cert, terminal.key)
    assert _reached_backend(r), r.text


def test_suspended_terminal_is_rejected_with_403(client, active, terminal, envoy, auth):
    change(client, active, "suspend", auth())
    r = envoy.request("GET", _terminal_path(active), terminal.cert, terminal.key)
    assert r.status_code == 403 and "SUSPENDED" in r.json()["error_message"], r.text


def test_suspended_terminal_can_still_send_heartbeats(client, active, terminal, envoy, auth):
    change(client, active, "suspend", auth())
    raw = json.dumps({"sent_at": datetime.now(UTC).isoformat(), "connectivity_type": "ETHERNET",
                      "latency_ms": 5, "firmware_version": "2.4.1"}).encode()
    r = envoy.request("POST", _terminal_path(active, "/heartbeat"), terminal.cert, terminal.key, content=raw,
                      headers={"Content-Type": "application/json", "X-Signature": terminal.sign(raw)})
    assert r.status_code == 200 and r.json()["status"] == "SUSPENDED", r.text


def test_revoked_certificate_is_rejected_at_the_tls_layer(client, active, terminal, envoy, auth):
    assert _reached_backend(envoy.request("GET", _terminal_path(active), terminal.cert, terminal.key))
    change(client, active, "revoke", auth(), "stolen")
    envoy.restart()  # deploy the new CRL
    with pytest.raises(httpx.TransportError):  # handshake fails: no HTTP status at all
        envoy.request("GET", _terminal_path(active), terminal.cert, terminal.key)


def test_certificate_from_unknown_ca_is_rejected(active, terminal, envoy, tmp_path):
    # Same key and subject as the real terminal, but signed by a CA the platform doesn't trust.
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    real = x509.load_pem_x509_certificate(terminal.cert.read_bytes())
    now = datetime.now(UTC)
    rogue = (x509.CertificateBuilder().subject_name(real.subject)
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")]))
             .public_key(real.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + timedelta(days=1))
             .add_extension(real.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False)
             .sign(rogue_key, hashes.SHA256()))
    rogue_cert = tmp_path / "rogue.pem"
    rogue_cert.write_bytes(rogue.public_bytes(PEM))
    with pytest.raises(httpx.TransportError):
        envoy.request("GET", _terminal_path(active), rogue_cert, terminal.key)


def test_certificate_cannot_be_used_for_another_terminal(active, terminal, envoy):
    r = envoy.request("GET", f"/api/v1/terminals/{uuid4()}", terminal.cert, terminal.key)
    assert r.status_code == 403 and "different terminal" in r.json()["error_message"]


def test_platform_cert_without_terminal_identity_is_rejected(active, envoy, ca, tmp_path):
    # A genuine client certificate from the platform CA, but with no terminal URI SAN.
    ca_key = serialization.load_pem_private_key(ca[1].read_bytes(), password=None)
    issuer = x509.load_pem_x509_certificate(ca[0].read_bytes()).subject
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ops")]))
            .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (tmp_path / "ops.pem").write_bytes(cert.public_bytes(PEM))
    (tmp_path / "ops-key.pem").write_bytes(key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                                             serialization.NoEncryption()))
    r = envoy.request("GET", "/api/v1/terminals", tmp_path / "ops.pem", tmp_path / "ops-key.pem")
    assert r.status_code == 403 and "no terminal identity" in r.json()["error_message"]


def test_spoofed_client_cert_header_is_ignored(client, active, terminal, envoy, auth):
    change(client, active, "suspend", auth())
    other = f"URI=urn:synapsepay:terminal:{uuid4()}"
    r = envoy.request("GET", _terminal_path(active), terminal.cert, terminal.key,
                      headers={"X-Forwarded-Client-Cert": other})
    assert r.status_code == 403 and "SUSPENDED" in r.json()["error_message"]


def test_internal_endpoints_are_not_routed(active, terminal, envoy):
    r = envoy.request("GET", "/internal/gateway/authz/api/v1/terminals", terminal.cert, terminal.key)
    assert r.status_code == 404
