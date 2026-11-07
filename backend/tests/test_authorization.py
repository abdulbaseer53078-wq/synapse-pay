"""Task 2.6 acceptance: the routing engine's transaction-time authorization check."""
from uuid import uuid4

import pytest

from terminal_sim import ADMIN, change, url

PER_TRANSACTION = 500000


@pytest.fixture
def ready(db, active):
    """`active`, heard from just now, on a profile certified for CARD and UPI."""
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD,UPI}', now() + interval '1 year', %s, 2000000) RETURNING profile_id",
        (PER_TRANSACTION,)).fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now()"
               " WHERE terminal_id = %s", (profile_id, active["terminal_id"]))
    return {**active, "profile_id": str(profile_id)}


@pytest.fixture
def check(client, auth):
    routing_engine = auth(sub="routing-engine", scope="registry:authorize")

    def call(created, method="CARD", amount=1000, headers=routing_engine):
        return client.get(url(created, "authorization"), headers=headers,
                          params={"payment_method": method, "amount": amount})
    return call


def denied(r, reason):
    assert r.status_code == 200, r.text
    body = r.json()
    return body["authorized"] is False and body["reason"] == reason


def test_active_healthy_certified_terminal_is_authorized(check, ready):
    r = check(ready)
    assert r.status_code == 200, r.text
    body = r.json()
    expires_at = body["certification"].pop("expires_at")
    assert expires_at and body == {
        "terminal_id": ready["terminal_id"], "authorized": True, "status": "ACTIVE", "health_state": "HEALTHY",
        "certification": {"profile_id": ready["profile_id"], "certified_for": ["CARD", "UPI"]},
        "limits": {"per_transaction": PER_TRANSACTION, "per_day": 2000000}, "reason": None}


def test_suspension_applies_to_the_next_call(check, ready, client, auth):
    assert check(ready).json()["authorized"] is True
    change(client, ready, "suspend", auth())
    r = check(ready)
    assert denied(r, "TERMINAL_NOT_ACTIVE")
    assert r.json()["status"] == "SUSPENDED" and r.json()["status_changed_at"]
    assert "limits" not in r.json()
    change(client, ready, "reinstate", auth(sub=ADMIN, scope="registry:admin"))
    assert check(ready).json()["authorized"] is True


def test_unreachable_terminal_is_rejected(check, ready, db):
    # No refresh-health run: authorization computes health from last_heartbeat_at itself.
    db.execute("UPDATE terminals SET last_heartbeat_at = now() - interval '5 minutes 1 second'"
               " WHERE terminal_id = %s", (ready["terminal_id"],))
    assert denied(check(ready), "TERMINAL_UNREACHABLE")


def test_degraded_terminal_is_still_authorized(check, ready, db):
    db.execute("UPDATE terminals SET last_heartbeat_at = now() - interval '2 minutes'"
               " WHERE terminal_id = %s", (ready["terminal_id"],))
    r = check(ready)
    assert r.json()["authorized"] is True and r.json()["health_state"] == "DEGRADED"


def test_expired_certification_is_rejected(check, ready, db):
    db.execute("UPDATE certification_profiles SET expires_at = now() - interval '1 second'")
    assert denied(check(ready), "CERTIFICATION_EXPIRED")


def test_method_not_certified_is_rejected(check, ready, db):
    assert denied(check(ready, method="WALLET"), "METHOD_NOT_CERTIFIED")
    db.execute("UPDATE terminals SET certification_profile_id = NULL")
    assert denied(check(ready), "METHOD_NOT_CERTIFIED")


def test_amount_over_per_transaction_limit_is_rejected(check, ready):
    assert check(ready, amount=PER_TRANSACTION).json()["authorized"] is True
    assert denied(check(ready, amount=PER_TRANSACTION + 1), "LIMIT_EXCEEDED")


def test_uncertified_firmware_is_rejected(check, ready, db):
    db.execute("UPDATE terminals SET firmware_version = '9.9.9'")  # e.g. a version de-certified after install
    assert denied(check(ready), "FIRMWARE_UNCERTIFIED")


def test_request_validation(check, ready, auth):
    r = check({"terminal_id": uuid4()})
    assert r.status_code == 404 and r.json()["error_code"] == "TERMINAL_NOT_FOUND"
    assert check(ready, headers={}).status_code == 401
    assert check(ready, headers=auth(scope="registry:write")).status_code == 403
    assert check(ready, method="CHEQUE").status_code == 400
    assert check(ready, amount=0).status_code == 400
