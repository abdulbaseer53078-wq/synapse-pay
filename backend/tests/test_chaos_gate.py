"""Step 19, the chaos gate: break the network, the acquirers and the "region" on purpose, and prove every payment
settles exactly once with an audit trail that tells the truth.

The real stack: Python engine → card service (Rust fleet) → two mock ISO 8583 acquirers, psp_1 and psp_2, each
behind a FaultProxy that can refuse connections or swallow the host's answers. Each scenario uses its own amount,
so the acquirers' own logs show exactly what each was asked to charge.

    Scenario 1  the terminal's network drops mid-payment; it resends the same bytes another way
    Scenario 2  psp_1 is dead: the cascade moves to psp_2. 2b: psp_1 approves then goes dark: the payment stays
                PENDING and psp_2 is never asked (the Step 19 double-charge fix)
    Scenario 3  the card service, offered [psp_1, psp_2], answers via psp_2; the audit records asked vs host
    Scenario 4  both acquirers are dead: a clean, retryable FAILED, nothing left PENDING
    Scenario 5  the "region" serving the API dies; a load balancer moves traffic to the other one

Local stand-ins, not the real thing: Scenario 5 moves stateless API instances that share one database. Region
failover with database promotion is the Step 17.6 game day (infra/game-day/), run in staging.
"""
import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from app.application.transactions import CardRequest, CardResult, parse_public_id
from app.infrastructure.card_service_client import HttpCardProcessor
from app.main import create_app
from card_sim import TEST_BDK_HEX, encrypted_card
from e2e_stack import ROOT, Process, _acquirer_pki, needs_cargo
from fault_proxy import FailoverProxy, FaultProxy

pytestmark = needs_cargo
HOSTS = ("psp_1", "psp_2")
SLOW_APPROVAL = 2000  # the mock acquirers answer this amount after --sleep seconds (1 s here): a slow approval


# --- the stack ---------------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stack(tmp_path_factory, card_service_binary):
    d = tmp_path_factory.mktemp("chaos")
    _acquirer_pki(d)
    dialect = ROOT / "iso8583" / "dialects" / "synthetic-host.json"
    mock_cmd = [os.environ.get("PYTHON", sys.executable), str(ROOT / "host-connector" / "mock_host" / "mock_host.py"),
                "--dialect", str(dialect), "--cert", str(d / "host.pem"), "--key", str(d / "host-key.pem"),
                "--client-ca", str(d / "ca.pem"), "--sleep", "1"]
    mocks = {h: Process(mock_cmd) for h in HOSTS}
    proxies = {h: FaultProxy(int(mocks[h].wait_listening(10))) for h in HOSTS}
    env = {**os.environ, "SIM_HSM_BDK_HEX": TEST_BDK_HEX, "HOSTS": ",".join(HOSTS),
           **{f"{h.upper()}_ADDR": f"127.0.0.1:{proxies[h].port}" for h in HOSTS},
           "HOST_SERVER_NAME": "localhost", "HOST_CA": str(d / "ca.pem"), "HOST_CLIENT_CERT": str(d / "client.pem"),
           "HOST_CLIENT_KEY": str(d / "client-key.pem"), "HOST_DIALECT": str(dialect), "HOST_POOL_SIZE": "2",
           "HOST_TIMEOUT_MS": "1500", "AUDIT_LOG_PATH": str(d / "iso-audit.jsonl"), "CARD_SERVICE_ADDR": "127.0.0.1:0"}
    service = Process([str(card_service_binary)], env=env)
    url = f"http://{service.wait_listening(30)}"
    yield {"url": url, "mocks": mocks, "proxies": proxies}
    service.stop()
    for h in HOSTS:
        proxies[h].close()
        mocks[h].stop()


def fleet_status(stack) -> dict:
    return {h["host_id"]: h["status"] for h in httpx.get(f"{stack['url']}/internal/v1/hosts/health").json()}


def wait_for(stack, expected: dict, timeout: float = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fleet_status(stack) == expected:
            return
        time.sleep(0.2)
    raise AssertionError(f"fleet never reached {expected}: {fleet_status(stack)}")


@pytest.fixture
def healthy(stack):
    """Every scenario starts with both acquirers healthy, and leaves them healed."""
    for proxy in stack["proxies"].values():
        proxy.heal()
    wait_for(stack, {"psp_1": "UP", "psp_2": "UP"})
    yield stack
    for proxy in stack["proxies"].values():
        proxy.heal()


def charged(stack, host: str, amount: int) -> int:
    """How many purchases of `amount` the acquirer approved: its own log, not ours."""
    return sum(1 for line in stack["mocks"][host].lines
               if line.startswith(("0100 ", "0200 ")) and f"amount={amount} ->" in line
               and line.rstrip().endswith(("approve", "timeout")))


def engine(settings, stack, cards=None, hosts=HOSTS):
    """The Python engine routing CARD to `hosts`, with a health snapshot saying they're all up: Python only learns
    of an outage when the card service tells it, which is the path these scenarios exercise."""
    routed = replace(settings, card_service_url=stack["url"], routing_rules={"CARD": tuple(hosts)},
                     card_hosts=tuple(hosts), health_poll_seconds=3600)
    app = create_app(routed, cards=cards or HttpCardProcessor(stack["url"]))

    def install_snapshot():
        app.state.health.registry.card_source = lambda: [{"host_id": h, "status": "UP", "latency_ms": 20}
                                                         for h in hosts]
        app.state.health.refresh()
    return app, install_snapshot


@pytest.fixture
def ready(db, active):
    (profile_id,) = db.execute(
        "INSERT INTO certification_profiles (certified_for, expires_at, per_transaction_limit, per_day_limit)"
        " VALUES ('{CARD}', now() + interval '1 year', 1000000, 2000000) RETURNING profile_id").fetchone()
    db.execute("UPDATE terminals SET certification_profile_id = %s, last_heartbeat_at = now() WHERE terminal_id = %s",
               (profile_id, active["terminal_id"]))
    return active


def body(ready, merchant, amount: int) -> dict:
    return {"idempotency_key": str(uuid4()), "amount": amount, "currency": "INR", "payment_method": "CARD",
            "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA"},
            "terminal_id": ready["terminal_id"], "merchant_id": str(merchant)}


def attempts(db, out: dict) -> list[dict]:
    transaction_id = parse_public_id(out["transaction_id"], "txn_")
    (payload,) = db.execute("SELECT payload FROM audit_log WHERE entity_id = %s AND action = 'transaction.finish'",
                            (transaction_id,)).fetchone()
    return payload["attempts"]


@contextmanager
def serve(app):
    """The app on a real port, so clients can reach it through proxies."""
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "API didn't start"
    try:
        yield server, server.servers[0].sockets[0].getsockname()[1]
    finally:
        server.should_exit = True
        thread.join(15)


def settle(url: str, raw: bytes, terminal_id: str, deadline: float = 30) -> httpx.Response:
    """What a terminal does: send the same bytes until a final answer (409 + retryable means still processing)."""
    end = time.monotonic() + deadline
    while True:
        try:
            r = httpx.post(f"{url}/api/v1/transactions", content=raw, timeout=10,
                           headers={"content-type": "application/json", "x-terminal-id": terminal_id})
            if not (r.status_code == 409 and r.json().get("retryable")) and r.status_code < 500:
                return r
        except httpx.TransportError:
            pass
        assert time.monotonic() < end, "no final answer"
        time.sleep(0.2)


# --- the scenarios -----------------------------------------------------------------------------------------------

def test_1_network_drop_mid_payment_settles_once(settings, healthy, ready, merchant, db):
    """Wi-Fi dies while the acquirer is still deciding; the terminal resends the identical bytes over cellular."""
    app, install = engine(settings, healthy)
    with serve(app) as (_, port):
        install()
        wifi, cellular = FaultProxy(port), FaultProxy(port)
        raw = json.dumps(body(ready, merchant, SLOW_APPROVAL)).encode()
        first = threading.Thread(target=lambda: settle(f"http://127.0.0.1:{wifi.port}", raw, ready["terminal_id"], 3))
        first.start()
        time.sleep(0.3)  # the request has reached the API, which is waiting on the slow acquirer
        cut = time.monotonic()
        wifi.refuse()
        response = settle(f"http://127.0.0.1:{cellular.port}", raw, ready["terminal_id"])
        elapsed = time.monotonic() - cut
        first.join(5)
        wifi.close()
        cellular.close()

    assert response.status_code == 201 and response.json()["status"] == "CAPTURED", response.text
    assert elapsed < 1 + 1.0, f"settled {elapsed:.2f} s after the drop (acquirer takes 1 s)"
    key = json.loads(raw)["idempotency_key"]
    assert db.execute("SELECT count(*) FROM transactions WHERE idempotency_key = %s", (key,)).fetchone()[0] == 1
    assert charged(healthy, "psp_1", SLOW_APPROVAL) + charged(healthy, "psp_2", SLOW_APPROVAL) == 1


def test_2_dead_primary_acquirer_cascades_to_the_backup(settings, healthy, ready, merchant, db):
    healthy["proxies"]["psp_1"].refuse()
    wait_for(healthy, {"psp_1": "DOWN", "psp_2": "UP"})
    app, install = engine(settings, healthy)
    with TestClient(app) as client:
        install()
        r = client.post("/api/v1/transactions", json=body(ready, merchant, 4100),
                        headers={"x-terminal-id": ready["terminal_id"]})

    assert r.status_code == 201 and r.json()["status"] == "CAPTURED", r.text
    trail = attempts(db, r.json())
    assert [(a["asked"], a["host"], a["status"]) for a in trail] == [("psp_1", "psp_1", "FAILED"),
                                                                   ("psp_2", "psp_2", "CAPTURED")]
    assert trail[0]["retryable"] is True and trail[0]["error"]
    assert (charged(healthy, "psp_1", 4100), charged(healthy, "psp_2", 4100)) == (0, 1)


def test_2b_primary_approves_then_goes_dark_no_double_charge(settings, healthy, ready, merchant, db):
    """psp_1 receives the purchase and approves it, but its answer, and its reversal, never get back. The outcome
    is unknown, so asking psp_2 could charge the customer twice: the payment must stay PENDING instead."""
    # psp_1's connections echo together every 30 s, and a swallowed echo holds its connection for 5 s. A purchase
    # that lands then finds no free connection, is never sent, and safely goes to psp_2 instead. That run is not
    # this scenario, so it is checked for a single charge and the scenario is tried again with a new amount.
    for amount in (4200, 4201, 4202):
        healthy["proxies"]["psp_1"].swallow()
        app, install = engine(settings, healthy)
        with TestClient(app) as client:
            install()
            r = client.post("/api/v1/transactions", json=body(ready, merchant, amount),
                            headers={"x-terminal-id": ready["terminal_id"]})
        assert r.status_code in (200, 201), r.text
        if charged(healthy, "psp_1", amount) or r.json()["status"] == "PENDING":
            break
        assert r.json()["status"] == "CAPTURED" and charged(healthy, "psp_2", amount) == 1, r.text
        healthy["proxies"]["psp_1"].heal()
        wait_for(healthy, {"psp_1": "UP", "psp_2": "UP"})

    trail = attempts(db, r.json())
    assert r.json()["status"] == "PENDING", (r.text, trail)
    assert [(a["asked"], a["status"], a["retryable"]) for a in trail] == [("psp_1", "PENDING", False)]
    assert charged(healthy, "psp_1", amount) == 1, "psp_1 really approved it: reconciliation must settle it"
    assert charged(healthy, "psp_2", amount) == 0, "psp_2 was asked too: a double charge"


def test_3_the_card_service_reports_the_host_that_answered(healthy):
    """Offered [psp_1, psp_2] with psp_1 dead, the fleet answers via psp_2 and says so."""
    healthy["proxies"]["psp_1"].refuse()
    wait_for(healthy, {"psp_1": "DOWN", "psp_2": "UP"})
    cards = HttpCardProcessor(healthy["url"])
    try:
        result = cards.process(CardRequest(
            transaction_id=uuid4(), kind="PURCHASE", amount=4300, currency="INR", acquirer_terminal_id="TERM0001",
            acquirer_merchant_id="MERCHANT0000001", encrypted_card_data=encrypted_card(), card_expiry="08/28",
            pin_block=None, host_hint=list(HOSTS)))
    finally:
        cards.close()
    assert (result.status, result.host_used) == ("CAPTURED", "psp_2")
    assert (charged(healthy, "psp_1", 4300), charged(healthy, "psp_2", 4300)) == (0, 1)


def test_3_the_audit_records_asked_and_answered(settings, ready, merchant, db):
    """When the card service answers via another host than the one asked, the trail keeps both."""
    class AnsweredByBackup:
        def process(self, request):
            assert request.host_hint == ["psp_1"]
            return CardResult(status="CAPTURED", method_reference="ref_b", auth_code="A1", error=None,
                              reversal="NOT_NEEDED", card_bin="411111", card_last4="1111", host_used="psp_2")

    app, install = engine(settings, {"url": "http://unused"}, cards=AnsweredByBackup(), hosts=("psp_1",))
    with TestClient(app) as client:
        install()
        r = client.post("/api/v1/transactions", json=body(ready, merchant, 4310),
                        headers={"x-terminal-id": ready["terminal_id"]})
    assert r.status_code == 201, r.text
    assert [(a["asked"], a["host"], a["status"]) for a in attempts(db, r.json())] == [("psp_1", "psp_2", "CAPTURED")]


def test_4_every_acquirer_down_fails_cleanly(settings, healthy, ready, merchant, db):
    for proxy in healthy["proxies"].values():
        proxy.refuse()
    wait_for(healthy, {"psp_1": "DOWN", "psp_2": "DOWN"})
    app, install = engine(settings, healthy)
    with TestClient(app) as client:
        install()
        r = client.post("/api/v1/transactions", json=body(ready, merchant, 4400),
                        headers={"x-terminal-id": ready["terminal_id"]})

    out = r.json()
    assert out["status"] == "FAILED", r.text
    assert out["error"]["error_category"] == "SYSTEM_ERROR" and out["error"]["retryable"] is True
    trail = attempts(db, out)
    assert [(a["asked"], a["status"]) for a in trail] == [("psp_1", "FAILED"), ("psp_2", "FAILED")]
    transaction_id = parse_public_id(out["transaction_id"], "txn_")
    assert db.execute("SELECT status FROM transactions WHERE transaction_id = %s",
                      (transaction_id,)).fetchone()[0] == "FAILED", "nothing may be left PENDING"
    assert charged(healthy, "psp_1", 4400) + charged(healthy, "psp_2", 4400) == 0


def test_5_region_loss_moves_traffic_and_keeps_answers(settings, healthy, ready, merchant, db):
    """Two API instances ("regions") on one database behind a failover load balancer. The first dies; new
    payments settle in the second, and a retry of a payment the first acknowledged replays the same answer."""
    mumbai_app, install_m = engine(settings, healthy)
    hyderabad_app, install_h = engine(settings, healthy)
    with serve(hyderabad_app) as (_, hyd_port):
        install_h()
        with serve(mumbai_app) as (_, mum_port):
            install_m()
            lb = FailoverProxy([mum_port, hyd_port])
            url = f"http://127.0.0.1:{lb.port}"
            before = json.dumps(body(ready, merchant, 4500)).encode()
            acked = settle(url, before, ready["terminal_id"])
            assert acked.status_code == 201 and lb.served_by[-1] == mum_port
        # Mumbai is gone.
        outage = time.monotonic()
        after = settle(url, json.dumps(body(ready, merchant, 4501)).encode(), ready["terminal_id"])
        failover_s = time.monotonic() - outage
        replay = settle(url, before, ready["terminal_id"])
        lb.close()

    assert after.status_code == 201 and after.json()["status"] == "CAPTURED", after.text
    assert lb.served_by[-1] == hyd_port, "the load balancer moved traffic to the surviving region"
    assert failover_s < 2.5, f"took {failover_s:.2f} s"
    assert replay.json()["transaction_id"] == acked.json()["transaction_id"], "the acknowledged payment survived"
    assert charged(healthy, "psp_1", 4500) + charged(healthy, "psp_2", 4500) == 1
    assert charged(healthy, "psp_1", 4501) + charged(healthy, "psp_2", 4501) == 1
