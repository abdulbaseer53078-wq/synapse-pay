"""Task 2.7 acceptance: tenant isolation, pagination, complete and ordered status history."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from terminal_sim import ADMIN, change, url

BASE = "/api/v1/terminals"


def admin_audit(db):
    return db.execute("SELECT actor_id, entity_type, action FROM audit_log WHERE actor_type = 'ADMIN'"
                      " AND to_status IS NULL ORDER BY audit_id").fetchall()


def test_merchant_cannot_read_another_merchants_terminal(client, db, active, merchant, auth):
    other = uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (other,))
    stranger = auth(sub=other, scope="registry:read registry:write")
    for path in ("", "/certificates", "/heartbeats", "/events"):
        r = client.get(f"{BASE}/{active['terminal_id']}{path}", headers=stranger)
        assert r.status_code == 404 and r.json()["error_code"] == "TERMINAL_NOT_FOUND", path
        assert client.get(f"{BASE}/{active['terminal_id']}{path}", headers=auth()).status_code == 200, path
    r = client.patch(f"{BASE}/{active['terminal_id']}", headers=stranger, json={"metadata": {"x": "y"}})
    assert r.status_code == 404
    assert db.execute("SELECT metadata FROM terminals").fetchone()[0] == {"location": "Till 1"}
    assert client.get(BASE, headers=stranger).json() == {"data": [], "next_cursor": None}
    assert client.get(BASE, headers=stranger, params={"merchant_id": str(merchant)}).status_code == 403
    assert client.get(f"{BASE}/{active['terminal_id']}").status_code == 401


def test_admin_override_is_logged(client, db, active, merchant, auth):
    admin = auth(sub=ADMIN, scope="registry:admin")
    assert client.get(f"{BASE}/{active['terminal_id']}", headers=admin).json()["terminal_id"] == active["terminal_id"]
    assert client.get(BASE, headers=admin).status_code == 400  # must name the merchant
    r = client.get(BASE, headers=admin, params={"merchant_id": str(merchant)})
    assert [t["terminal_id"] for t in r.json()["data"]] == [active["terminal_id"]]
    assert admin_audit(db) == [(ADMIN, "terminal", "read"), (ADMIN, "merchant", "list_terminals")]
    client.get(f"{BASE}/{active['terminal_id']}", headers=auth())  # a merchant's own read isn't an override
    assert len(admin_audit(db)) == 2


def test_pagination(client, db, merchant, auth):
    ids = sorted(str(db.execute("INSERT INTO terminals (merchant_id, device_serial, device_model)"
                                " VALUES (%s, %s, 'PAX A920 Pro') RETURNING terminal_id",
                                (merchant, f"SN-{i}")).fetchone()[0]) for i in range(5))
    seen, cursor, pages = [], None, 0
    while True:
        r = client.get(BASE, headers=auth(), params={"limit": 2, **({"cursor": cursor} if cursor else {})})
        assert r.status_code == 200, r.text
        seen += [t["terminal_id"] for t in r.json()["data"]]
        pages += 1
        cursor = r.json()["next_cursor"]
        if cursor is None:
            break
    assert seen == ids and pages == 3
    # Exactly one page's worth: no empty trailing page.
    assert client.get(BASE, headers=auth(), params={"limit": 5}).json()["next_cursor"] is None


def test_list_filters(client, db, active, merchant, auth):
    db.execute("INSERT INTO terminals (merchant_id, device_serial, device_model) VALUES (%s, 'SN-P', 'PAX A920 Pro')",
               (merchant,))
    only = lambda **p: [t["status"] for t in client.get(BASE, headers=auth(), params=p).json()["data"]]
    assert sorted(only()) == ["ACTIVE", "PENDING"]
    assert only(status="ACTIVE") == ["ACTIVE"]
    assert only(health_state="HEALTHY") == []
    assert sorted(only(health_state="UNREACHABLE")) == ["ACTIVE", "PENDING"]
    assert client.get(BASE, headers=auth(), params={"status": "BOGUS"}).status_code == 400


def test_status_history_is_complete_and_ordered(client, db, active, auth, terminal):
    admin = auth(sub=ADMIN, scope="registry:admin")
    change(client, active, "suspend", auth(), "investigating")
    client.get(f"{BASE}/{active['terminal_id']}", headers=admin)  # an audited read, not a status change
    change(client, active, "reinstate", admin)
    change(client, active, "revoke", auth(), "stolen")
    r = client.get(url(active, "events"), headers=auth())
    events = [(e["action"], e["from_status"], e["to_status"], e["actor_type"], e["reason"]) for e in r.json()["data"]]
    assert events == [
        ("create", None, "PENDING", "MERCHANT", None),
        ("register", "PENDING", "PENDING_ACTIVATION", "TERMINAL", None),
        ("activate", "PENDING_ACTIVATION", "ACTIVE", "TERMINAL", None),
        ("suspend", "ACTIVE", "SUSPENDED", "MERCHANT", "investigating"),
        ("reinstate", "SUSPENDED", "ACTIVE", "ADMIN", None),
        ("revoke", "ACTIVE", "REVOKED", "MERCHANT", "stolen"),
    ]
    times = [e["occurred_at"] for e in r.json()["data"]]
    assert times == sorted(times)
    assert all("actor_id" not in e for e in r.json()["data"])  # don't expose admin identities to merchants


def test_certificate_history(client, active, auth):
    certs = client.get(url(active, "certificates"), headers=auth()).json()["data"]
    assert len(certs) == 1 and certs[0]["current"] is True and certs[0]["revoked_at"] is None
    change(client, active, "revoke", auth(), "stolen")
    certs = client.get(url(active, "certificates"), headers=auth()).json()["data"]
    assert certs[0]["revoked_at"] is not None and certs[0]["revocation_reason"] == "stolen"


def test_recent_heartbeats(client, db, active, auth):
    now = datetime.now(UTC)
    for i in range(3):
        db.execute("INSERT INTO heartbeats (terminal_id, sent_at, received_at, signature_valid, connectivity_type,"
                   " latency_ms, firmware_version) VALUES (%s, %s, %s, true, 'ETHERNET', %s, '2.4.1')",
                   (active["terminal_id"], now + timedelta(seconds=i), now + timedelta(seconds=i), i))
    r = client.get(url(active, "heartbeats"), headers=auth(), params={"limit": 2})
    assert [h["latency_ms"] for h in r.json()["data"]] == [2, 1]  # newest first
    assert client.get(url(active, "heartbeats"), headers=auth(), params={"limit": 1001}).status_code == 400


def test_patch_updates_metadata_only(client, db, active, auth):
    r = client.patch(f"{BASE}/{active['terminal_id']}", headers=auth(), json={"metadata": {"location": "Till 2"}})
    assert r.status_code == 200 and r.json()["metadata"] == {"location": "Till 2"}
    r = client.patch(f"{BASE}/{active['terminal_id']}", headers=auth(), json={"device_model": "Sunmi P2"})
    assert r.status_code == 400
    assert client.get(f"{BASE}/{active['terminal_id']}", headers=auth()).json()["device_model"] == "PAX A920 Pro"
