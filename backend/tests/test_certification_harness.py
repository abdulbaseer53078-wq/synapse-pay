"""Step 27 gate: the certification matrix runs through the real stack (backend → card service → ISO 8583 over
mutual TLS) against the strict scheme simulator. Firmware that passes can be approved; firmware with a chip-data
bug fails the run and can't be.

Needs cargo (builds card-service). Set CERT_REPORT_DIR to keep the reports (CI uploads them)."""
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.infrastructure.card_service_client import HttpCardProcessor
from app.main import create_app
from card_sim import TEST_BDK_HEX, encrypted_card, encrypted_pin
from e2e_stack import ROOT, Process, _acquirer_pki, needs_cargo
from terminal_sim import ADMIN
from test_transactions_e2e import ready  # noqa: F401  (fixture)

sys.path.insert(0, str(ROOT / "certification"))
from harness import MATRIX, SoftwareTerminal, run  # noqa: E402

pytestmark = needs_cargo
PAX = "PAX A920 Pro"


@pytest.fixture(scope="module")
def scheme_host(tmp_path_factory, card_service_binary):
    """(card service URL, evidence log): the card service in front of the scheme simulator instead of mock_host."""
    d = tmp_path_factory.mktemp("scheme")
    _acquirer_pki(d)
    dialect = ROOT / "iso8583" / "dialects" / "synthetic-host.json"
    evidence = d / "evidence.jsonl"
    sim = Process([os.environ.get("PYTHON", sys.executable), str(ROOT / "certification" / "scheme_sim.py"),
                   "--dialect", str(dialect), "--cert", str(d / "host.pem"), "--key", str(d / "host-key.pem"),
                   "--client-ca", str(d / "ca.pem"), "--evidence", str(evidence)])
    env = {**os.environ, "SIM_HSM_BDK_HEX": TEST_BDK_HEX, "HOST_ADDR": f"127.0.0.1:{sim.wait_listening(10)}",
           "HOST_SERVER_NAME": "localhost", "HOST_CA": str(d / "ca.pem"), "HOST_CLIENT_CERT": str(d / "client.pem"),
           "HOST_CLIENT_KEY": str(d / "client-key.pem"), "HOST_DIALECT": str(dialect), "HOST_POOL_SIZE": "2",
           "HOST_TIMEOUT_MS": "1500", "AUDIT_LOG_PATH": str(d / "iso-audit.jsonl"), "CARD_SERVICE_ADDR": "127.0.0.1:0"}
    service = Process([str(card_service_binary)], env=env)
    yield f"http://{service.wait_listening(30)}", evidence
    service.stop()
    sim.stop()


@pytest.fixture
def lab(settings, db, ready, merchant, scheme_host, auth):  # noqa: F811
    """run(firmware, tamper) -> (report, recorded run); certify(firmware, scheme) -> response."""
    cards = HttpCardProcessor(scheme_host[0])
    headers = auth(sub=ADMIN, scope="registry:admin certification:run")
    with TestClient(create_app(settings, cards=cards)) as client:
        def post(body):
            r = client.post("/api/v1/transactions", json=body, headers={"x-terminal-id": ready["terminal_id"]})
            return r.status_code, r.json()

        def run_matrix(firmware, tamper=None):
            terminal = SoftwareTerminal(post, ready["terminal_id"], str(merchant), PAX, firmware, encrypted_card,
                                        encrypted_pin, tamper)
            report = run(terminal, scheme_host[1])
            if os.environ.get("CERT_REPORT_DIR"):
                out = Path(os.environ["CERT_REPORT_DIR"]) / f"{firmware}.json"
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(report, indent=2))
            recorded = client.post("/api/v1/certification-runs", headers=headers, json={
                "device_model": PAX, "firmware_version": firmware, "driver": terminal.name, "report": report})
            assert recorded.status_code == 201, recorded.text
            return report, recorded.json()

        def certify(firmware, scheme):
            return client.post("/api/v1/certifications", headers=headers, json={
                "device_model": PAX, "firmware_version": firmware, "scheme": scheme, "acquirer_id": "acquirer_lab",
                "certificate_number": f"{scheme}-L3-LAB", "valid_until": "2030-01-01T00:00:00Z"})

        yield run_matrix, certify
    cards.close()


def failures(report):
    return {c["id"]: (c["expect"], c["got"], [f for e in c["evidence"] for f in e["findings"]])
            for c in report["cases"] if not c["passed"]}


def test_certified_firmware_passes_the_matrix_and_can_be_approved(lab):
    run_matrix, certify = lab
    report, recorded = run_matrix("2.6.0")
    assert report["passed"], failures(report)
    assert len(report["cases"]) == len(json.loads(MATRIX.read_text())["cases"]) >= 10
    assert recorded["passed"] and recorded["schemes"] == ["AMEX", "MASTERCARD", "RUPAY", "VISA"]
    assert certify("2.6.0", "VISA").status_code == 201
    assert certify("2.6.0", "NPCI_UPI").json()["error_code"] == "CERTIFICATION_RUN_REQUIRED", "the run had no UPI"


def test_firmware_that_drops_the_cryptogram_fails_and_cannot_be_approved(lab):
    run_matrix, certify = lab
    report, recorded = run_matrix("2.6.1", tamper=lambda tags: tags.pop("9F26"))
    failed = failures(report)
    # Every case is refused at DE 55, except the bad card number (the card service refuses it first) and the
    # expired card (refused for its expiry before the chip data is read, as it should be).
    assert set(failed) == {c["id"] for c in report["cases"]} - {"visa-invalid-card-number", "mastercard-expired-card"}
    assert all(f == ["DE 55: tag 9F26 missing"] for _, _, f in failed.values()), failed
    assert not recorded["passed"]
    r = certify("2.6.1", "VISA")
    assert r.status_code == 409 and r.json()["error_code"] == "CERTIFICATION_RUN_REQUIRED"


def test_a_later_failing_run_blocks_approval(lab):
    run_matrix, certify = lab
    run_matrix("2.6.2")
    run_matrix("2.6.2", tamper=lambda tags: tags.update({"9F02": "000000000001"}))
    assert certify("2.6.2", "VISA").status_code == 409


def test_reports_carry_no_card_data(lab):
    run_matrix, _ = lab
    report, _ = run_matrix("2.6.3")
    text = json.dumps(report)
    for case in json.loads(MATRIX.read_text())["cases"]:
        assert case["pan"] not in text
    chip = [e["fields"]["55"] for c in report["cases"] for e in c["evidence"] if "55" in e["fields"]]
    assert chip and all(len(pair) == 2 and isinstance(pair[1], int) for tags in chip for pair in tags), \
        "DE 55 is evidenced as [tag, length] pairs, never values"
    assert all("14" not in e["fields"] for c in report["cases"] for e in c["evidence"]), "expiry is left out"
