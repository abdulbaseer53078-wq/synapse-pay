"""Task 2.3 acceptance: a terminal simulated with the openssl CLI goes through create → register → activate."""
import base64
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from terminal_sim import HARDWARE_ID, SE_ID, SimulatedTerminal, openssl, register_body, status_of, url


def test_full_flow(client, db, created, terminal, ca):
    assert created["status"] == "PENDING"

    r = client.post(url(created, "register"), json=register_body(created["registration_token"], terminal.csr()))
    assert r.status_code == 200, r.text
    reg = r.json()
    cert = x509.load_pem_x509_certificate(reg["certificate_pem"].encode())
    cert.verify_directly_issued_by(x509.load_pem_x509_certificate(ca[0].read_bytes()))
    assert cert.subject.rfc4514_string() == f"CN={created['terminal_id']}"
    assert status_of(db, created) == "PENDING_ACTIVATION"

    signature = terminal.sign(base64.b64decode(reg["activation_challenge"]))
    r = client.post(url(created, "activate"), json={"signed_challenge": signature})
    assert r.status_code == 200, r.text
    row = db.execute("SELECT status, activated_at, secure_element_id FROM terminals WHERE terminal_id = %s",
                     (created["terminal_id"],)).fetchone()
    assert row[0] == "ACTIVE" and row[1] is not None and row[2] == SE_ID


def test_csr_with_invalid_signature_is_rejected(client, db, created, terminal):
    pem = terminal.csr()
    der = bytearray(x509.load_pem_x509_csr(pem.encode()).public_bytes(Encoding.DER))
    der[-1] ^= 0x01  # corrupt the last byte of the signature
    tampered = openssl("req", "-inform", "DER", "-outform", "PEM", input=bytes(der)).decode()

    r = client.post(url(created, "register"), json=register_body(created["registration_token"], tampered))
    assert r.status_code == 400 and r.json()["error_message"] == "CSR signature is invalid"
    assert status_of(db, created) == "PENDING"
    # A rejected attempt doesn't burn the token.
    r = client.post(url(created, "register"), json=register_body(created["registration_token"], pem))
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("hardware_id, fingerprint", [
    ("SUNMI-P2-0A1B2C3D", None),          # consistent hash, but hardware of a different model
    (HARDWARE_ID, "0" * 64),              # hash doesn't match the reported parts
])
def test_fingerprint_not_matching_model_is_rejected(client, db, created, terminal, hardware_id, fingerprint):
    body = register_body(created["registration_token"], terminal.csr(), hardware_id, fingerprint)
    r = client.post(url(created, "register"), json=body)
    assert r.status_code == 403 and r.json()["error_code"] == "FORBIDDEN"
    # A wrong device rejects the terminal for good (PENDING → REJECTED, by SYSTEM).
    assert status_of(db, created) == "REJECTED"
    r = client.post(url(created, "register"), json=register_body(created["registration_token"], terminal.csr()))
    assert r.status_code == 401


def test_rejection_needs_a_valid_token(client, db, created, terminal):
    body = register_body("not-the-token", terminal.csr(), fingerprint="0" * 64)
    assert client.post(url(created, "register"), json=body).status_code == 401
    assert status_of(db, created) == "PENDING"


def test_reused_registration_token_is_rejected(client, created, terminal):
    body = register_body(created["registration_token"], terminal.csr())
    assert client.post(url(created, "register"), json=body).status_code == 200
    r = client.post(url(created, "register"), json=body)
    assert r.status_code == 401 and r.json()["error_code"] == "UNAUTHENTICATED"


def test_activation_with_bad_signature_is_rejected(client, db, created, terminal, tmp_path):
    reg = client.post(url(created, "register"), json=register_body(created["registration_token"], terminal.csr())).json()
    challenge = base64.b64decode(reg["activation_challenge"])

    other_key = SimulatedTerminal(tmp_path / "other")
    for signature in (terminal.sign(challenge + b"x"), other_key.sign(challenge)):
        r = client.post(url(created, "activate"), json={"signed_challenge": signature})
        assert r.status_code == 401 and r.json()["error_code"] == "UNAUTHENTICATED"
    assert status_of(db, created) == "PENDING_ACTIVATION"


def test_create_terminal_validation(client, auth, merchant, created):
    body = {"merchant_id": str(merchant), "device_serial": "SN-002", "device_model": "PAX A920 Pro"}
    assert client.post("/api/v1/terminals", json=body).status_code == 401
    assert client.post("/api/v1/terminals", headers=auth(scope="transactions:read"), json=body).status_code == 403
    other = {**body, "merchant_id": "00000000-0000-0000-0000-000000000001"}
    assert client.post("/api/v1/terminals", headers=auth(), json=other).status_code == 403
    r = client.post("/api/v1/terminals", headers=auth(), json={**body, "device_model": "Unknown X1"})
    assert r.status_code == 422
    r = client.post("/api/v1/terminals", headers=auth(), json={**body, "device_serial": "SN-001"})
    assert r.status_code == 409


def test_db_constraints(db):
    """Runs the SQL constraint test for the schema migrations."""
    db.execute((Path(__file__).parents[2] / "db" / "tests" / "001_terminal_registry_test.sql").read_text())
