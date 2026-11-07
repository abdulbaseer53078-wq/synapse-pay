"""Task 2.5 acceptance: signed heartbeats update health; unsigned and replayed ones are rejected;
firmware changes are re-certified; silent terminals become UNREACHABLE."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from app import jobs
from terminal_sim import SimulatedTerminal, change, status_of, url


def heartbeat_body(firmware="2.4.1", sent_at=None, **overrides) -> bytes:
    body = {"sent_at": (sent_at or datetime.now(UTC)).isoformat(), "connectivity_type": "CELLULAR",
            "latency_ms": 42, "firmware_version": firmware, "battery_level": 80, **overrides}
    return json.dumps(body).encode()


def send(client, created, raw: bytes, signer: SimulatedTerminal | None):
    headers = {"Content-Type": "application/json"}
    if signer:
        headers["X-Signature"] = signer.sign(raw)
    return client.post(url(created, "heartbeat"), content=raw, headers=headers)


def terminal_row(db, created):
    return db.execute("SELECT status, health_state, last_heartbeat_at, firmware_version FROM terminals"
                      " WHERE terminal_id = %s", (created["terminal_id"],)).fetchone()


def heartbeat_count(db, created):
    return db.execute("SELECT count(*) FROM heartbeats WHERE terminal_id = %s",
                      (created["terminal_id"],)).fetchone()[0]


def test_signed_heartbeat_updates_health(client, db, active, terminal):
    assert terminal_row(db, active)[1] == "UNREACHABLE"  # never heard from yet
    r = send(client, active, heartbeat_body(), terminal)
    assert r.status_code == 200, r.text
    assert r.json() == {"terminal_id": active["terminal_id"], "status": "ACTIVE", "health_state": "HEALTHY"}
    status, health, last_heartbeat_at, _ = terminal_row(db, active)
    assert health == "HEALTHY" and last_heartbeat_at is not None
    assert heartbeat_count(db, active) == 1


def test_unsigned_or_badly_signed_heartbeat_is_rejected(client, db, active, terminal, tmp_path):
    raw = heartbeat_body()
    assert send(client, active, raw, signer=None).status_code == 401
    assert send(client, active, raw, signer=SimulatedTerminal(tmp_path / "impostor")).status_code == 401
    # Signed, then altered in transit.
    tampered = {"X-Signature": terminal.sign(raw), "Content-Type": "application/json"}
    r = client.post(url(active, "heartbeat"), content=raw.replace(b"42", b"43"), headers=tampered)
    assert r.status_code == 401
    assert heartbeat_count(db, active) == 0 and terminal_row(db, active)[1] == "UNREACHABLE"


@pytest.mark.parametrize("offset", [timedelta(seconds=-61), timedelta(seconds=61), timedelta(hours=-1)])
def test_heartbeat_outside_window_is_rejected(client, db, active, terminal, offset):
    r = send(client, active, heartbeat_body(sent_at=datetime.now(UTC) + offset), terminal)
    assert r.status_code == 401 and "window" in r.json()["error_message"]
    assert heartbeat_count(db, active) == 0


def test_replayed_heartbeat_inside_window_is_rejected(client, db, active, terminal):
    raw = heartbeat_body()
    signature = terminal.sign(raw)
    headers = {"X-Signature": signature, "Content-Type": "application/json"}
    assert client.post(url(active, "heartbeat"), content=raw, headers=headers).status_code == 200
    r = client.post(url(active, "heartbeat"), content=raw, headers=headers)
    assert r.status_code == 401 and "replayed" in r.json()["error_message"]
    assert heartbeat_count(db, active) == 1


def test_certified_firmware_change_is_accepted(client, db, active, terminal):
    assert send(client, active, heartbeat_body(firmware="2.5.0"), terminal).json()["status"] == "ACTIVE"
    assert terminal_row(db, active)[3] == "2.5.0"


def test_uncertified_firmware_change_suspends(client, db, active, terminal):
    r = send(client, active, heartbeat_body(firmware="9.9.9"), terminal)
    assert r.status_code == 200 and r.json()["status"] == "SUSPENDED"
    assert terminal_row(db, active)[0] == "SUSPENDED" and terminal_row(db, active)[3] == "9.9.9"
    assert db.execute("SELECT actor_type, action, reason FROM audit_log WHERE to_status = 'SUSPENDED'"
                      ).fetchone() == ("SYSTEM", "suspend", "UNCERTIFIED_FIRMWARE")
    # A suspended terminal keeps reporting in.
    later = heartbeat_body(firmware="9.9.9", sent_at=datetime.now(UTC) + timedelta(seconds=1))
    assert send(client, active, later, terminal).json()["status"] == "SUSPENDED"


def test_revoked_terminal_heartbeat_is_logged_without_state_change(client, db, active, terminal, auth):
    send(client, active, heartbeat_body(), terminal)
    change(client, active, "revoke", auth(), "stolen")
    before = terminal_row(db, active)
    later = heartbeat_body(firmware="9.9.9", sent_at=datetime.now(UTC) + timedelta(seconds=1))
    r = send(client, active, later, terminal)
    assert r.status_code == 200 and r.json()["status"] == "REVOKED"
    assert terminal_row(db, active) == before and heartbeat_count(db, active) == 2


def test_heartbeat_before_activation_is_rejected(client, db, created, registered, terminal):
    assert send(client, created, heartbeat_body(), terminal).status_code == 409
    assert heartbeat_count(db, created) == 0


@pytest.mark.parametrize("silent_for, expected", [
    (timedelta(seconds=30), "HEALTHY"),
    (timedelta(minutes=2), "DEGRADED"),
    (timedelta(minutes=5, seconds=1), "UNREACHABLE"),
])
def test_silent_terminal_health_is_recomputed(client, db, active, terminal, silent_for, expected,
                                              database_url, monkeypatch):
    send(client, active, heartbeat_body(), terminal)
    db.execute("UPDATE terminals SET last_heartbeat_at = now() - %s WHERE terminal_id = %s",
               (silent_for, active["terminal_id"]))
    monkeypatch.setenv("DATABASE_URL", database_url)
    jobs.main(["refresh-health"])
    assert terminal_row(db, active)[1] == expected
