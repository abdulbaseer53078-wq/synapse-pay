"""Step 26 gate: the certification registry decides, per exact firmware, scheme and acquirer, whether a terminal
may take a payment; a firmware change blocks it until that version is certified, and a downgrade suspends it."""
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.application.certification import CertificationMatrix, snapshot
from app.domain.certification import Certification, below_minimum, version_key
from test_authorization import check, denied, ready  # noqa: F401  (fixtures)
from test_cascade_e2e import cards, routed_client, routed_settings  # noqa: F401  (fixtures)
from test_heartbeat import heartbeat_body, send
from terminal_sim import ADMIN

PAX = "PAX A920 Pro"


@pytest.fixture
def admin(client, auth):
    headers = auth(sub=ADMIN, scope="registry:admin certification:run")

    def certify(firmware, scheme="VISA", acquirer="acquirer_a", **fields):
        # Step 27: approval needs a passing harness run for this firmware and scheme.
        client.post("/api/v1/certification-runs", headers=headers, json={
            "device_model": PAX, "firmware_version": firmware, "driver": "software",
            "report": {"cases": [{"id": "fixture", "scheme": scheme, "passed": True}]}})
        return client.post("/api/v1/certifications", headers=headers, json={
            "device_model": PAX, "firmware_version": firmware, "scheme": scheme, "acquirer_id": acquirer,
            "certificate_number": "VISA-L3-2026-0412",
            "valid_until": (datetime.now(UTC) + timedelta(days=365)).isoformat(), **fields})

    certify.headers = headers
    return certify


def eventually(probe, seconds=3.0):
    """The matrix reloads on the change's NOTIFY, a few milliseconds after commit."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(0.02)
    return probe()


def authorized(r):
    return r.status_code == 200 and r.json()["authorized"] is True


def test_firmware_update_blocks_until_that_exact_version_is_certified(client, check, ready, admin, db, terminal):
    assert authorized(check(ready))
    # The terminal installs 2.6.0 and says so in its next heartbeat. It stays ACTIVE: nothing is wrong with the
    # device, but every payment is refused until a scheme certifies 2.6.0.
    r = send(client, ready, heartbeat_body(firmware="2.6.0"), terminal)
    assert r.status_code == 200 and r.json()["status"] == "ACTIVE"
    assert denied(check(ready), "FIRMWARE_UNCERTIFIED")
    assert db.execute("SELECT from_status, to_status FROM audit_log WHERE action = 'firmware_change'").fetchone() \
        == ("2.4.1", "2.6.0")

    # A neighbouring version is not enough: matching is exact.
    assert admin("2.6.1").status_code == 201
    time.sleep(0.2)
    assert denied(check(ready), "FIRMWARE_UNCERTIFIED")

    created = admin("2.6.0")
    assert created.status_code == 201, created.text
    assert eventually(lambda: authorized(check(ready))), "certifying 2.6.0 unblocks the next payment"
    assert db.execute("SELECT actor_id, payload->>'certificate_number' FROM audit_log"
                      " WHERE action = 'certification.create' AND entity_id = %s",
                      (created.json()["certification_id"],)).fetchone() == (ADMIN, "VISA-L3-2026-0412")


def test_expired_or_suspended_certification_is_refused(client, check, ready, admin, db):
    db.execute("DELETE FROM certifications WHERE device_model = %s AND firmware_version = '2.4.1'", (PAX,))
    cert = admin("2.4.1").json()
    assert eventually(lambda: authorized(check(ready)))

    patch = lambda body: client.patch(f"/api/v1/certifications/{cert['certification_id']}",  # noqa: E731
                                      headers=admin.headers, json=body)
    assert patch({"status": "SUSPENDED"}).json()["status"] == "SUSPENDED"
    assert eventually(lambda: denied(check(ready), "CERTIFICATION_EXPIRED"))
    assert patch({"status": "ACTIVE"}).status_code == 200
    assert eventually(lambda: authorized(check(ready)))
    assert patch({"valid_until": (datetime.now(UTC) + timedelta(seconds=1)).isoformat()}).status_code == 200
    time.sleep(1.1)
    assert denied(check(ready), "CERTIFICATION_EXPIRED"), "expiry applies without anyone touching the row"


def test_certification_is_per_scheme(check, ready, admin, db):
    db.execute("DELETE FROM certifications WHERE device_model = %s AND firmware_version = '2.4.1'", (PAX,))
    assert admin("2.4.1", scheme="NPCI_UPI", acquirer="psp_upi_1").status_code == 201
    assert eventually(lambda: authorized(check(ready, method="UPI")))
    assert denied(check(ready, method="CARD"), "FIRMWARE_UNCERTIFIED"), "UPI certification says nothing about cards"


def test_a_downgrade_below_the_minimum_secure_firmware_suspends(client, check, ready, admin, db, terminal):
    r = client.put(f"/api/v1/device-models/{PAX}/minimum-firmware", headers=admin.headers,
                   json={"minimum_secure_firmware": "2.4.1"})
    assert r.status_code == 200, r.text
    assert admin("2.3.9").status_code == 201  # certified once, but below the floor now
    matrix = client.app.state.authorization.certification
    assert eventually(lambda: matrix.is_downgrade(PAX, "2.3.9"))
    r = send(client, ready, heartbeat_body(firmware="2.3.9"), terminal)
    assert r.json()["status"] == "SUSPENDED"
    assert db.execute("SELECT actor_type, reason FROM audit_log WHERE action = 'suspend'").fetchone() \
        == ("SYSTEM", "FIRMWARE_DOWNGRADE")
    assert denied(check(ready), "TERMINAL_NOT_ACTIVE")


def test_routing_only_asks_acquirers_certified_for_the_firmware(routed_client, ready, merchant, cards, db):
    from test_observability import pay
    # 2.4.1 is certified with psp_2 only; the rule prefers psp_1.
    db.execute("DELETE FROM certifications WHERE acquirer_id = 'psp_1'")
    routed_client.app.state.authorization.certification.reload()
    assert pay(routed_client, ready, merchant).status_code == 201
    assert [r.host_hint for r in cards.received] == [["psp_2"]]

    db.execute("DELETE FROM certifications WHERE acquirer_id = 'psp_2'")
    routed_client.app.state.authorization.certification.reload()
    body = pay(routed_client, ready, merchant).json()
    assert body["status"] == "FAILED" and "METHOD_NOT_CERTIFIED" in body["error"]["error_message"]
    assert len(cards.received) == 1, "nothing was sent to an uncertified acquirer"


def test_admin_api_rules(client, admin, auth):
    assert admin("2.7.0").status_code == 201
    assert admin("2.7.0").status_code == 409, "one row per model, firmware, scheme and acquirer"
    assert admin("2.7.x").status_code == 400, "no wildcards"
    assert admin("2.7.1", valid_until="2020-01-01T00:00:00Z").status_code == 400
    assert client.post("/api/v1/certifications", headers=auth(scope="registry:write"), json={}).status_code == 403
    listed = client.get("/api/v1/certifications", headers=admin.headers,
                        params={"device_model": PAX, "firmware_version": "2.7.0"}).json()["certifications"]
    assert [(c["scheme"], c["acquirer_id"]) for c in listed] == [("VISA", "acquirer_a")]
    assert client.patch(f"/api/v1/certifications/{uuid4()}", headers=admin.headers,
                        json={"status": "SUSPENDED"}).status_code == 404


# --- the matrix itself ----------------------------------------------------------------------------------------

def _cert(firmware="2.4.1", scheme="VISA", acquirer="acquirer_a", status="ACTIVE", days=30):
    now = datetime.now(UTC)
    return Certification(uuid4(), PAX, firmware, scheme, acquirer, "X", status, now - timedelta(days=1),
                         now + timedelta(days=days))


class Store:
    def __init__(self, rows=(), minimums=None, broken=False):
        self.rows, self.minimums, self.broken = list(rows), minimums or {}, broken

    def load(self):
        if self.broken:
            raise ConnectionError("database down")
        return snapshot(self.rows, self.minimums)


def test_fails_closed_before_loading_and_after_a_failed_reload():
    matrix = CertificationMatrix(Store([_cert()]))
    assert matrix.denial(PAX, "2.4.1", "CARD", "VISA") == "FIRMWARE_UNCERTIFIED", "not loaded yet"
    matrix.reload()
    assert matrix.denial(PAX, "2.4.1", "CARD", "VISA") is None
    matrix.store.broken = True
    with pytest.raises(ConnectionError):
        matrix.reload()
    assert matrix.denial(PAX, "2.4.1", "CARD", "VISA") == "FIRMWARE_UNCERTIFIED"
    assert matrix.acquirers(PAX, "2.4.1", "CARD", "VISA") == frozenset()


def test_the_check_is_well_under_5_ms():
    rows = [_cert(f"2.{minor}.{patch}", scheme, f"acq_{a}") for minor in range(10) for patch in range(10)
            for scheme in ("VISA", "MASTERCARD", "RUPAY", "NPCI_UPI") for a in range(5)]
    matrix = CertificationMatrix(Store(rows, {PAX: "2.0.0"}))
    matrix.reload()
    start = time.perf_counter()
    for _ in range(1000):
        assert matrix.denial(PAX, "2.9.9", "CARD", "RUPAY") is None
    per_check_ms = (time.perf_counter() - start) * 1000 / 1000
    assert per_check_ms < 5, f"{per_check_ms:.4f} ms per check"


def test_versions_compare_numerically_and_unknown_formats_fail_closed():
    assert version_key("v2.1.4") == (2, 1, 4) and version_key("2.1.x") is None
    assert below_minimum("2.9.0", "2.10.0") and not below_minimum("2.10.0", "2.9.0")
    assert not below_minimum("2.4", "2.4.0") and below_minimum("2.3.99", "2.4")
    assert below_minimum("beta-7", "2.4.0"), "can't prove an unreadable version isn't a downgrade"
    assert not below_minimum("anything", None)
