"""Task 2.4 acceptance: transitions are enforced, revocation reaches the CA and the gateway, changes are audited."""
from uuid import uuid4

import psycopg
import pytest
from cryptography import x509

from app.application.registration import CertificateAuthorityUnavailable
from gateway import mtls_handshake_accepted
from terminal_sim import ADMIN, change, register_body, status_of, url


def crl_serials(ca) -> set[int]:
    return {r.serial_number for r in x509.load_pem_x509_crl(ca[2].read_bytes())}


def test_transitions_are_enforced(client, db, active, auth):
    merchant, admin = auth(), auth(sub=ADMIN, scope="registry:admin")

    assert change(client, active, "reinstate", admin).status_code == 409        # ACTIVE can't be reinstated
    assert change(client, active, "suspend", merchant).json()["status"] == "SUSPENDED"
    assert change(client, active, "suspend", merchant).status_code == 409       # already suspended
    assert change(client, active, "reinstate", merchant).status_code == 403     # admin only
    assert change(client, active, "reinstate", admin).json()["status"] == "ACTIVE"
    assert change(client, active, "decommission", admin).status_code == 403     # merchant only

    assert change(client, active, "revoke", admin, "key compromise").json()["status"] == "REVOKED"
    for action, headers in [("reinstate", admin), ("suspend", merchant), ("revoke", merchant),
                            ("decommission", merchant)]:
        r = change(client, active, action, headers)
        assert r.status_code == 409, f"{action} on REVOKED: {r.status_code}"
    assert status_of(db, active) == "REVOKED"


def test_merchants_only_see_their_own_terminals(client, db, active, auth):
    stranger = uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (stranger,))
    assert change(client, active, "suspend", auth(sub=stranger)).status_code == 404
    assert change(client, active, "suspend", auth(scope="transactions:read")).status_code == 403
    assert change(client, active, "suspend", {}).status_code == 401
    assert status_of(db, active) == "ACTIVE"


def test_pending_terminal_cannot_be_suspended_or_revoked(client, created, auth):
    assert change(client, created, "suspend", auth()).status_code == 409
    assert change(client, created, "revoke", auth()).status_code == 409


def test_revocation_propagates_to_ca_and_gateway(client, db, active, terminal, auth, ca, gateway_server_cert):
    handshake = lambda: mtls_handshake_accepted(ca[0], ca[2], *gateway_server_cert, terminal.cert, terminal.key)
    serial = x509.load_pem_x509_certificate(terminal.cert.read_bytes()).serial_number
    assert handshake(), "a valid terminal certificate should pass mTLS"

    assert change(client, active, "revoke", auth(), "device stolen").status_code == 200
    assert serial in crl_serials(ca)
    assert not handshake(), "a revoked certificate must fail mTLS"
    revoked_at, reason = db.execute("SELECT revoked_at, revocation_reason FROM certificates WHERE terminal_id = %s",
                                    (active["terminal_id"],)).fetchone()
    assert revoked_at is not None and reason == "device stolen"


@pytest.mark.parametrize("action, start", [("decommission", "ACTIVE"), ("revoke", "SUSPENDED"),
                                           ("decommission", "SUSPENDED")])
def test_every_certificate_holding_state_can_lose_its_certificate(client, db, active, terminal, auth, ca, action, start):
    if start == "SUSPENDED":
        change(client, active, "suspend", auth())
    assert change(client, active, action, auth()).status_code == 200
    assert x509.load_pem_x509_certificate(terminal.cert.read_bytes()).serial_number in crl_serials(ca)


def test_revoking_before_activation(client, db, created, registered, terminal, auth, ca):
    assert change(client, created, "revoke", auth(), "device lost in transit").json()["status"] == "REVOKED"
    assert x509.load_pem_x509_certificate(terminal.cert.read_bytes()).serial_number in crl_serials(ca)


def test_ca_failure_leaves_terminal_unchanged(client, db, active, terminal, auth, ca, monkeypatch):
    def unavailable(serial):
        raise CertificateAuthorityUnavailable("certificate revocation could not be published")
    monkeypatch.setattr(client.app.state.registration.ca, "revoke", unavailable)

    r = change(client, active, "revoke", auth())
    assert r.status_code == 503 and r.json()["retryable"] is True
    assert status_of(db, active) == "ACTIVE"
    assert db.execute("SELECT revoked_at FROM certificates WHERE terminal_id = %s",
                      (active["terminal_id"],)).fetchone()[0] is None
    assert db.execute("SELECT count(*) FROM audit_log WHERE action = 'revoke'").fetchone()[0] == 0


def test_status_changes_are_audited(client, db, active, auth, merchant):
    change(client, active, "suspend", auth(), "investigating")
    change(client, active, "reinstate", auth(sub=ADMIN, scope="registry:admin"))
    rows = db.execute("SELECT action, actor_type, actor_id, from_status, to_status, reason FROM audit_log"
                      " WHERE entity_id = %s ORDER BY audit_id", (active["terminal_id"],)).fetchall()
    tid = active["terminal_id"]
    assert rows == [
        ("create", "MERCHANT", str(merchant), None, "PENDING", None),
        ("register", "TERMINAL", tid, "PENDING", "PENDING_ACTIVATION", None),
        ("activate", "TERMINAL", tid, "PENDING_ACTIVATION", "ACTIVE", None),
        ("suspend", "MERCHANT", str(merchant), "ACTIVE", "SUSPENDED", "investigating"),
        ("reinstate", "ADMIN", ADMIN, "SUSPENDED", "ACTIVE", None),
    ]
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        db.execute("UPDATE audit_log SET reason = 'edited'")
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        db.execute("DELETE FROM audit_log")


def test_rejection_is_audited(client, db, created, terminal):
    client.post(url(created, "register"),
                json=register_body(created["registration_token"], terminal.csr(), fingerprint="0" * 64))
    assert db.execute("SELECT actor_type, to_status FROM audit_log WHERE action = 'reject'").fetchone() \
        == ("SYSTEM", "REJECTED")
