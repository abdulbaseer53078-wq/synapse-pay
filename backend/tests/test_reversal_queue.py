"""PR 3 gate: a reversal the card service owes survives a restart and reaches the acquirer, quoting the original.

The real card service in front of the mock acquirer (mock_host.py), behind a FaultProxy, with the queue in its
own Postgres database. The acquirer approves the purchase but its answers are swallowed, so the purchase times out
and every in-line reversal fails too. The card service is then restarted, the network heals, and the queue alone
must send the reversal. The mock answers a reversal "00" only if its DE 90 quotes the MTI and STAN of a request it
really received, so "reversed" proves the original was restored from the database, not rebuilt.

Needs cargo (builds card-service) and Postgres."""
import os
import re
import sys
import time
from uuid import uuid4

import psycopg
import pytest

from app.application.transactions import CardRequest
from app.infrastructure.card_service_client import HttpCardProcessor
from card_sim import TEST_BDK_HEX, TEST_PAN, encrypted_card
from conftest import ADMIN_URL
from e2e_stack import ROOT, Process, _acquirer_pki, needs_cargo
from fault_proxy import FaultProxy

pytestmark = needs_cargo
QUEUE_DB = os.environ.get("TEST_DB_NAME", "synapse_test") + "_cardsvc"


@pytest.fixture
def lab(tmp_path, card_service_binary):
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {QUEUE_DB} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {QUEUE_DB}")
    queue_url = ADMIN_URL.rsplit("/", 1)[0] + "/" + QUEUE_DB
    _acquirer_pki(tmp_path)
    dialect = ROOT / "iso8583" / "dialects" / "synthetic-host.json"
    mock = Process([os.environ.get("PYTHON", sys.executable), str(ROOT / "host-connector" / "mock_host" / "mock_host.py"),
                    "--dialect", str(dialect), "--cert", str(tmp_path / "host.pem"), "--key", str(tmp_path / "host-key.pem"),
                    "--client-ca", str(tmp_path / "ca.pem")])
    proxy = FaultProxy(int(mock.wait_listening(10)))
    env = {**os.environ, "SIM_HSM_BDK_HEX": TEST_BDK_HEX, "HOSTS": "psp_1", "PSP_1_ADDR": f"127.0.0.1:{proxy.port}",
           "HOST_SERVER_NAME": "localhost", "HOST_CA": str(tmp_path / "ca.pem"),
           "HOST_CLIENT_CERT": str(tmp_path / "client.pem"), "HOST_CLIENT_KEY": str(tmp_path / "client-key.pem"),
           "HOST_DIALECT": str(dialect), "HOST_POOL_SIZE": "1", "HOST_TIMEOUT_MS": "1000",
           "AUDIT_LOG_PATH": str(tmp_path / "iso-audit.jsonl"), "CARD_SERVICE_ADDR": "127.0.0.1:0",
           "VAULT_DATABASE_URL": queue_url, "CARD_DATA_STORAGE": "sandbox", "REVERSAL_RETRY_MS": "300"}
    services = []

    def start():
        service = Process([str(card_service_binary)], env=env)
        services.append(service)
        return service, f"http://{service.wait_listening(30)}"

    yield {"start": start, "proxy": proxy, "mock": mock, "queue_url": queue_url}
    for service in services:
        service.stop()
    proxy.close()
    mock.stop()


def reversal_state(url, transaction_id):
    r = HttpCardProcessor(url).client.get(f"/card/reversals/{transaction_id}")
    return r.json().get("state") if r.status_code == 200 else r.json()["error"]


def test_an_owed_reversal_survives_a_restart_and_quotes_the_original(lab):
    service, url = lab["start"]()
    transaction_id = uuid4()
    lab["proxy"].swallow()  # the acquirer gets everything; nothing it says comes back
    cards = HttpCardProcessor(url)
    result = cards.process(CardRequest(
        transaction_id=transaction_id, kind="PURCHASE", amount=4400, currency="INR",
        acquirer_terminal_id="TERM0001", acquirer_merchant_id="MERCHANT0000001",
        encrypted_card_data=encrypted_card(), card_expiry="08/28", pin_block=None, host_hint=["psp_1"]))
    cards.close()
    assert (result.status, result.reversal) == ("PENDING", "FAILED"), result
    assert reversal_state(url, transaction_id) == "PENDING"
    (purchase_stan,) = re.findall(r"^0200 stan=(\d{6}) amount=4400 -> approve", lab["mock"].output, re.M)

    # The process that owed the reversal dies; its memory of the original goes with it.
    service.stop()
    lab["proxy"].heal()
    service, url = lab["start"]()

    deadline = time.monotonic() + 20
    while reversal_state(url, transaction_id) == "PENDING" and time.monotonic() < deadline:
        time.sleep(0.2)
    assert reversal_state(url, transaction_id) == "REVERSED", service.output[-3000:]
    assert re.search(r"^0400 stan=\d{6} amount=4400 -> reversed", lab["mock"].output, re.M), lab["mock"].output

    with psycopg.connect(lab["queue_url"]) as db:
        row = db.execute("SELECT original_stan, sealed_pan, response_code, attempts FROM pending_reversals"
                         " WHERE transaction_id = %s", (str(transaction_id),)).fetchone()
    assert row[0] == purchase_stan, "the queue saved the purchase's own STAN"
    assert row[1] is None and row[2] == "00" and row[3] >= 1, "card data is wiped once the reversal is done"
    assert all(TEST_PAN not in s.output for s in (service, lab["mock"])), "no card number in any log"


def test_a_purchase_that_never_left_queues_nothing(lab):
    """Refused before sending: nothing reached the acquirer, so there is nothing to reverse or queue."""
    service, url = lab["start"]()
    transaction_id = uuid4()
    lab["proxy"].refuse()
    cards = HttpCardProcessor(url)
    result = cards.process(CardRequest(
        transaction_id=transaction_id, kind="PURCHASE", amount=4500, currency="INR",
        acquirer_terminal_id="TERM0001", acquirer_merchant_id="MERCHANT0000001",
        encrypted_card_data=encrypted_card(), card_expiry="08/28", pin_block=None, host_hint=["psp_1"]))
    cards.close()
    assert result.status == "FAILED" and result.reversal == "NOT_NEEDED", result
    assert reversal_state(url, transaction_id) == "NOT_QUEUED"


def test_card_data_storage_is_frozen_unless_explicitly_sandboxed(card_service_binary, tmp_path):
    """F-16: storing card data waits for the PCI review. Asking for it without CARD_DATA_STORAGE=sandbox must stop
    startup, never quietly run with (or without) it."""
    import subprocess
    env = {k: v for k, v in os.environ.items() if k != "CARD_DATA_STORAGE"}
    env.update({"SIM_HSM_BDK_HEX": TEST_BDK_HEX, "VAULT_IN_MEMORY": "1", "CARD_SERVICE_ADDR": "127.0.0.1:0",
                "AUDIT_LOG_PATH": str(tmp_path / "audit.jsonl")})
    run = subprocess.run([str(card_service_binary)], env=env, capture_output=True, text=True, timeout=30)
    assert run.returncode == 2 and "frozen pending PCI review" in run.stderr, run.stderr
