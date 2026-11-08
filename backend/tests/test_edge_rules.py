"""Step 20, cloud side: registering an edge node, its signed offline rules, and the gateway's edge identity."""
import base64
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.application.offline_sync import canonical_item
from app.domain.edge import EDGE_URI_PREFIX
from app.main import create_app

ADMIN = "admin-ops-1"
LIMITS = {"per_transaction": 200_000, "per_day": 1_000_000, "max_age_minutes": 4320}


@pytest.fixture(scope="module")
def rules_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def edge_client(settings, db, rules_key):
    pem = rules_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
    with TestClient(create_app(replace(settings, edge_rules_signing_key=pem,
                                       routing_rules={"CARD": ("acquirer_a", "acquirer_b")}))) as c:
        yield c


def csr() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    req = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "edge")])).sign(key, hashes.SHA256()))
    return req.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def edge(edge_client, auth, merchant):
    r = edge_client.post("/api/v1/edge-nodes", headers=auth(sub=ADMIN, scope="registry:admin"),
                         json={"merchant_id": str(merchant), "csr_pem": csr(), "offline_limits": LIMITS})
    assert r.status_code == 201, r.text
    return r.json()


def rules(client, edge_node_id):
    return client.get("/internal/v1/edge/rules", headers={"x-edge-node-id": edge_node_id})


def verify(body: dict, public_key_pem: str) -> bool:
    key = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        key.verify(base64.b64decode(body["signature"]), canonical_item(body), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def test_registered_edge_gets_a_certificate_with_its_edge_identity(edge):
    cert = x509.load_pem_x509_certificate(edge["certificate_pem"].encode())
    uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(u.value) for u in uris] == [f"{EDGE_URI_PREFIX}{edge['edge_node_id']}"]
    assert edge["rules_public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_rules_are_signed_and_bound_to_the_edge_and_merchant(edge_client, edge, merchant):
    r = rules(edge_client, edge["edge_node_id"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert verify(body, edge["rules_public_key_pem"])
    assert (body["edge_node_id"], body["merchant_id"], body["rules_version"]) == (edge["edge_node_id"], str(merchant), 1)
    assert body["offline_limits"] == LIMITS
    assert body["routing_rules"] == {"CARD": ["acquirer_a", "acquirer_b"]}
    issued = datetime.fromisoformat(body["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    assert expires - issued == timedelta(hours=72)
    # Room for Steps 22 and 23, signed from day one.
    assert set(body["fraud_thresholds"]) == {"blocklist", "blocklist_key", "max_txns_per_hour", "high_risk_amount"}
    assert body["token_index"] == {"entries": [], "revocations": []}
    # Any edit breaks the signature.
    assert not verify({**body, "offline_limits": {**LIMITS, "per_transaction": 9_999_999}}, edge["rules_public_key_pem"])


def test_changing_limits_moves_the_version_forward_and_is_audited(edge_client, edge, auth, db):
    admin = auth(sub=ADMIN, scope="registry:admin")
    url = f"/api/v1/edge-nodes/{edge['edge_node_id']}/offline-limits"
    r = edge_client.put(url, headers=admin, json={"per_transaction": 100_000, "per_day": 500_000})
    assert r.status_code == 200 and r.json()["rules_version"] == 2, r.text
    body = rules(edge_client, edge["edge_node_id"]).json()
    assert body["rules_version"] == 2 and body["offline_limits"]["per_transaction"] == 100_000
    assert [a for (a,) in db.execute("SELECT action FROM audit_log WHERE entity_type = 'edge_node' ORDER BY audit_id")] \
        == ["edge.register", "edge.update_limits"]
    bad = edge_client.put(url, headers=admin, json={"per_transaction": 500_000, "per_day": 100_000})
    assert bad.status_code == 400


def test_who_may_do_what(edge_client, edge, auth, merchant):
    body = {"merchant_id": str(merchant), "csr_pem": csr(), "offline_limits": LIMITS}
    assert edge_client.post("/api/v1/edge-nodes", headers=auth(), json=body).status_code == 403  # merchant token
    assert edge_client.post("/api/v1/edge-nodes", json=body).status_code == 401
    assert edge_client.get("/internal/v1/edge/rules").status_code == 401
    assert rules(edge_client, "00000000-0000-0000-0000-000000000000").status_code == 404


def test_rules_need_the_signing_key(client, edge_client, edge):
    assert rules(client, edge["edge_node_id"]).status_code == 503  # `client` has no signing key configured


def authz(client, path, uri):
    return client.get(f"/internal/gateway/authz/{path}", headers={"x-forwarded-client-cert": f"Hash=ab;URI={uri}"})


def test_gateway_admits_an_edge_only_to_the_edge_api(edge_client, edge, db):
    uri = f"{EDGE_URI_PREFIX}{edge['edge_node_id']}"
    ok = authz(edge_client, "internal/v1/edge/rules", uri)
    assert ok.status_code == 200
    assert (ok.headers["x-edge-node-id"], ok.headers["x-terminal-id"]) == (edge["edge_node_id"], "-")
    assert authz(edge_client, "api/v1/transactions", uri).status_code == 403
    db.execute("UPDATE edge_nodes SET status = 'REVOKED'")
    assert authz(edge_client, "internal/v1/edge/rules", uri).status_code == 403


def test_terminals_cannot_reach_the_edge_api(edge_client):
    r = authz(edge_client, "internal/v1/edge/rules", "urn:synapsepay:terminal:00000000-0000-0000-0000-000000000001")
    assert r.status_code == 403


def test_offline_sync_is_open_to_both_edges_and_terminals(edge_client, edge, active):
    edge_uri = f"{EDGE_URI_PREFIX}{edge['edge_node_id']}"
    ok = authz(edge_client, "api/v1/transactions/sync", edge_uri)
    assert ok.status_code == 200 and ok.headers["x-terminal-id"] == "-"
    assert authz(edge_client, "api/v1/transactions", edge_uri).status_code == 403
    terminal = authz(edge_client, "api/v1/transactions/sync", f"urn:synapsepay:terminal:{active['terminal_id']}")
    assert terminal.status_code == 200, terminal.text
