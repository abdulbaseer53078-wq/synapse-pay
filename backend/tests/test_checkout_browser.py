"""Step 6 end to end, in a real browser (headless Chromium):

    merchant server (Node SDK) creates the intent
      → merchant page (web SDK, another origin) mounts Synapse's card frame, the customer types a card
      → the frame encrypts it to the HSM's checkout key and confirms
      → backend → card service (real, simulated HSM + 3-D Secure) → mock acquirer over mutual TLS
      → the bank's OTP page when asked → result on the merchant page → signed webhook to the merchant.

Needs cargo, node/npm and Playwright's Chromium; skipped otherwise."""
import json
import os
import shutil
import subprocess
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import uvicorn
from psycopg_pool import ConnectionPool

from app.infrastructure.card_service_client import HttpCardProcessor
from app.infrastructure.postgres_api_keys import create_merchant
from app.main import create_app
from card_sim import encrypted_card
from e2e_stack import ROOT, needs_cargo
from test_payment_intents import Receiver

playwright = pytest.importorskip("playwright.sync_api")
pytestmark = [needs_cargo, pytest.mark.skipif(shutil.which("npm") is None, reason="npm not on PATH")]

FRICTIONLESS, CHALLENGE = "4242424242424242", "4111111111111111"
CARD_FRAME = 'iframe[title="Secure card payment form"]'


def _npm_build(package: Path) -> None:
    for args in (["npm", "install", "--silent", "--no-audit", "--no-fund"], ["npm", "run", "build", "--silent"]):
        done = subprocess.run(args, cwd=package, capture_output=True, text=True, timeout=600)
        assert done.returncode == 0, done.stdout + done.stderr


@pytest.fixture(scope="session")
def sdks():
    _npm_build(ROOT / "sdks" / "node")
    _npm_build(ROOT / "sdks" / "web")
    return ROOT / "sdks"


def node_sdk(sdks: Path, script: str, **env) -> dict:
    """Runs `script` with `synapse` = the Node SDK; prints JSON."""
    prelude = (f"import SynapsePay from {json.dumps(str(sdks / 'node' / 'dist' / 'index.js'))};"
               "const synapse = new SynapsePay(process.env.KEY, { apiBase: process.env.API });")
    done = subprocess.run(["node", "--input-type=module", "-e", prelude + script], capture_output=True, text=True,
                          timeout=60, env={**os.environ, **env})
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.fixture
def live(settings, db, acquirer):
    """The backend on a real port, talking to the real card service. Yields (api base URL, app)."""
    app = create_app(settings, cards=HttpCardProcessor(acquirer[0]))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    # The API is "localhost"; the merchant page is "127.0.0.1": two origins, as in production.
    yield f"http://localhost:{port}", app
    server.should_exit = True
    thread.join(5)


PAGE = """<!doctype html><meta charset="utf-8"><title>Shop</title>
<div id="card"></div><button id="pay">Pay</button><pre id="result"></pre>
<script src="/synapsepay.js"></script><script src="/page.js"></script>"""

PAGE_JS = """
const q = new URLSearchParams(location.search);
const synapse = SynapsePay({ apiBase: q.get("api") });
const secret = q.get("secret");
const show = (r) => { document.getElementById("result").textContent = JSON.stringify(
  { status: r.paymentIntent && r.paymentIntent.status, error: r.error && r.error.code, last4: r.paymentIntent &&
    r.paymentIntent.card && r.paymentIntent.card.last4 }); };
if (q.get("mode") === "terminal") {
  synapse.waitForTerminalPayment(secret, { intervalMs: 200 }).then(show);
} else {
  const card = synapse.mountCard("#card", { onChange: (e) => { document.body.dataset.complete = e.complete; } });
  card.ready.then(() => { document.body.dataset.ready = "1"; });
  document.getElementById("pay").onclick = async () => show(await synapse.confirmCardPayment(secret, card));
}
"""


@pytest.fixture
def shop(tmp_path, sdks):
    """The merchant's site on its own origin, loading the web SDK bundle."""
    (tmp_path / "index.html").write_text(PAGE)
    (tmp_path / "page.js").write_text(PAGE_JS)
    shutil.copy(sdks / "web" / "dist" / "synapsepay.js", tmp_path / "synapsepay.js")
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(_Quiet, directory=str(tmp_path)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


class _Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture
def account(database_url, db):
    with ConnectionPool(database_url, min_size=1, max_size=1) as pool:
        return create_merchant(pool)


@pytest.fixture(scope="session")
def browser():
    with playwright.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def create_intent(sdks, live, account, **params) -> dict:
    return node_sdk(sdks, f"console.log(JSON.stringify(await synapse.paymentIntents.create({json.dumps(params)})));",
                    KEY=account["secret_key"], API=live[0])


def open_checkout(browser, shop, live, intent):
    page = browser.new_page()
    requests = []
    page.on("request", lambda r: requests.append(r.post_data or ""))
    page.goto(f"{shop}/index.html?api={live[0]}&secret={intent['client_secret']}")
    page.wait_for_selector("body[data-ready='1']", timeout=10_000)
    return page, requests


def type_card(page, number, expiry="12 / 30", cvc="123"):
    frame = page.frame_locator(CARD_FRAME)
    frame.locator("#number").fill(number)
    frame.locator("#expiry").fill(expiry)
    frame.locator("#cvc").fill(cvc)
    page.wait_for_selector("body[data-complete='true']", timeout=5_000)


def result(page) -> dict:
    page.wait_for_function("document.getElementById('result').textContent.length > 0", timeout=20_000)
    return json.loads(page.inner_text("#result"))


def test_card_payment_with_otp_and_signed_webhook(browser, shop, live, account, sdks, db):
    receiver = Receiver()
    try:
        intent = create_intent(sdks, live, account, amount=15000, webhook_url=receiver.url)
        page, requests = open_checkout(browser, shop, live, intent)

        # The merchant's page can't look inside Synapse's card frame.
        assert page.evaluate("() => { try { return document.querySelector('iframe').contentDocument === null; }"
                             " catch (e) { return true; } }")
        type_card(page, CHALLENGE)
        page.click("#pay")

        # The bank asks for an OTP (3-D Secure, as for most Indian cards).
        bank = page.frame_locator('iframe[title="Bank verification"]')
        bank.locator("#otp").fill("123456")
        bank.locator("#submit").click()
        assert result(page) == {"status": "SUCCEEDED", "last4": "1111"}

        assert not any(CHALLENGE in body for body in requests), "the card number never left the frame in clear"
        assert any('"encrypted_card_data":"sp2.' in body for body in requests)
        assert db.execute("SELECT status, channel FROM transactions").fetchone() == ("CAPTURED", "ONLINE")

        # The merchant's server gets a webhook it can verify with the Node SDK.
        assert live[1].state.webhooks.deliver_due() == 1
        headers, body = receiver.requests[0]
        signature = headers.get("x-signature") or headers.get("X-Signature")
        event = node_sdk(sdks, "console.log(JSON.stringify(synapse.webhooks.constructEvent("
                               "process.env.BODY, process.env.SIG, process.env.SECRET)));",
                         KEY=account["secret_key"], API=live[0], BODY=body.decode(), SIG=signature,
                         SECRET=account["webhook_secret"])
        assert event["status"] == "CAPTURED" and event["payment_intent_id"] == intent["id"]
    finally:
        receiver.close()


def test_frictionless_card_payment(browser, shop, live, account, sdks):
    intent = create_intent(sdks, live, account, amount=15000)
    page, _ = open_checkout(browser, shop, live, intent)
    type_card(page, FRICTIONLESS)
    page.click("#pay")
    assert result(page) == {"status": "SUCCEEDED", "last4": "4242"}


def test_declined_card_lets_the_customer_retry(browser, shop, live, account, sdks):
    intent = create_intent(sdks, live, account, amount=5100)  # the mock bank declines ₹51.00
    page, _ = open_checkout(browser, shop, live, intent)
    type_card(page, FRICTIONLESS)
    page.click("#pay")
    assert result(page) == {"status": "REQUIRES_PAYMENT_METHOD", "error": "ERR_CARD_DECLINED", "last4": "4242"}


def test_incomplete_card_is_caught_in_the_frame(browser, shop, live, account, sdks):
    intent = create_intent(sdks, live, account, amount=15000)
    page, requests = open_checkout(browser, shop, live, intent)
    page.frame_locator(CARD_FRAME).locator("#number").fill("4242 4242 4242 4241")  # fails the Luhn check
    page.click("#pay")
    assert result(page)["error"] == "ERR_CARD_INCOMPLETE"
    assert not any("confirm" in body or "sp2." in body for body in requests), "nothing was sent"


def test_web_pos_takes_payment_on_a_terminal(browser, shop, live, account, sdks, active, db):
    db.execute("INSERT INTO certification_profiles (profile_id, certified_for, expires_at, per_transaction_limit,"
               " per_day_limit) VALUES (gen_random_uuid(), '{CARD}', now() + interval '1 year', 10000000, 100000000)")
    db.execute("UPDATE terminals SET merchant_id = %s, last_heartbeat_at = now(),"
               " certification_profile_id = (SELECT profile_id FROM certification_profiles LIMIT 1)"
               " WHERE terminal_id = %s", (account["merchant_id"], active["terminal_id"]))
    intent = create_intent(sdks, live, account, amount=15000, terminal_id=active["terminal_id"])

    page = browser.new_page()
    page.goto(f"{shop}/index.html?api={live[0]}&secret={intent['client_secret']}&mode=terminal")

    # The terminal (simulated here; the gateway would set x-terminal-id from its certificate) picks the job up
    # and the customer taps their card.
    terminal = {"x-terminal-id": active["terminal_id"]}
    job = httpx.get(f"{live[0]}/api/v1/terminals/{active['terminal_id']}/checkout", params={"wait": 5},
                    headers=terminal).json()
    assert job["payment_intent_id"] == intent["id"] and job["amount"] == 15000
    paid = httpx.post(f"{live[0]}/api/v1/transactions", headers=terminal, json={
        "idempotency_key": str(uuid4()), "amount": job["amount"], "currency": "INR", "payment_method": "CARD",
        "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA"},
        "terminal_id": active["terminal_id"], "merchant_id": account["merchant_id"],
        "payment_intent_id": job["payment_intent_id"]}, timeout=20)
    assert paid.status_code == 201 and paid.json()["status"] == "CAPTURED", paid.text
    assert result(page)["status"] == "SUCCEEDED"
