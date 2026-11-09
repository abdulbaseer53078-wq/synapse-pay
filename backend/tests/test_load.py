"""PR 9: the load test (loadtest/load-test.js) against the real stack. Opt-in: LOAD_TEST=1 (needs Docker for k6).

Starts the API on a real port in front of the card service and the mock acquirer (the e2e `acquirer` fixture),
registers an active, certified terminal, then runs k6 and fails on its thresholds (p95 < 500 ms, < 1 % errors).
The summary lands in $LOAD_TEST_OUT (default: the test's tmp dir). Takes about 3.5 minutes.

LOAD_TEST_EXTERNAL_K6=1, for hosts where this process can't reach Docker: the test writes $LOAD_TEST_OUT/k6.env and
waits; run loadtest/run-k6.sh <LOAD_TEST_OUT> from a shell that can, and the test reads its summary."""
import functools
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from psycopg_pool import ConnectionPool

import app.main as app_main
from app.infrastructure.card_service_client import HttpCardProcessor
from app.main import create_app
from card_sim import encrypted_card
from e2e_stack import ROOT, Process, needs_cargo
from test_chaos_gate import serve
from test_transactions_e2e import ready  # noqa: F401  (fixture)

K6_IMAGE = "grafana/k6:1.0.0"
pytestmark = [needs_cargo, pytest.mark.skipif(not os.environ.get("LOAD_TEST"), reason="opt-in: set LOAD_TEST=1")]


@pytest.fixture(scope="session")
def card_service_binary():
    """LOAD_RELEASE=1: the card service as it runs in production (a debug build measures the compiler, not us)."""
    release = bool(os.environ.get("LOAD_RELEASE"))
    build = subprocess.run(["cargo", "build", "--quiet", "--bin", "card_service", *(["--release"] if release else [])],
                           cwd=ROOT / "card-service", capture_output=True, text=True, timeout=1800)
    assert build.returncode == 0, build.stderr
    return ROOT / "card-service" / os.environ.get("CARGO_TARGET_DIR", "target") / ("release" if release else "debug")         / "card_service"


@contextmanager
def api_processes(settings, ca, card_url, workers, tmp_path):
    """LOAD_WORKERS=N: the API as deployed, `uvicorn --factory` with N worker processes, from the environment."""
    jwt = tmp_path / "jwt.pem"
    jwt.write_text(settings.jwt_public_key)
    env = {**os.environ, "DATABASE_URL": settings.database_url, "CA_CERT_PATH": str(ca[0]), "CA_KEY_PATH": str(ca[1]),
           "CA_CRL_PATH": str(ca[2]), "JWT_PUBLIC_KEY_PATH": str(jwt), "CARD_SERVICE_URL": card_url,
           "WEBHOOK_INTERVAL_SECONDS": "0", "ALLOW_INSECURE_WEBHOOKS": "1"}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    api = Process([sys.executable, "-m", "uvicorn", "app.main:create_app", "--factory", "--host", "127.0.0.1",
                   "--port", str(port), "--workers", str(workers), "--log-level", "warning"],
                  env=env, cwd=ROOT / "backend")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health/live", timeout=1).status_code == 200:
                break
        except httpx.TransportError:
            time.sleep(0.3)
    else:
        raise AssertionError(f"API didn't start:\n{api.output}")
    try:
        yield port
    finally:
        api.stop()
        (tmp_path / "api.txt").write_text(api.output)  # a worker that died says why here
        if os.environ.get("LOAD_TEST_OUT"):
            (Path(os.environ["LOAD_TEST_OUT"]) / "api.txt").write_text(api.output)


@contextmanager
def heartbeating(db, terminal_id):
    """A real terminal heartbeats every few seconds; without it, authorization refuses the terminal as UNREACHABLE
    a couple of minutes into the run, and the test measures that instead of payments."""
    stop = threading.Event()

    def beat():
        while not stop.wait(20):
            db.execute("UPDATE terminals SET last_heartbeat_at = now() WHERE terminal_id = %s", (terminal_id,))

    thread = threading.Thread(target=beat, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(5)


def test_card_payments_at_100_tps(settings, ca, db, ready, merchant, acquirer, tmp_path, monkeypatch):  # noqa: F811
    # ~180,000 sales of ₹100 must not hit the terminal's daily limit: that would be a test artefact, not a bottleneck.
    db.execute("UPDATE certification_profiles SET per_day_limit = 1000000000000, per_transaction_limit = 100000000")
    if os.environ.get("LOAD_DB_POOL"):  # an experiment knob: the API's Postgres pool size, without editing main.py
        size = int(os.environ["LOAD_DB_POOL"])
        monkeypatch.setattr(app_main, "ConnectionPool", functools.partial(ConnectionPool, min_size=size, max_size=size))
    cards = HttpCardProcessor(acquirer[0])
    out = Path(os.environ.get("LOAD_TEST_OUT", tmp_path))
    out.mkdir(parents=True, exist_ok=True)
    for stale in ("summary.json", "k6.env", "k6.exit", "k6.txt"):
        (out / stale).unlink(missing_ok=True)
    try:
        workers = int(os.environ.get("LOAD_WORKERS", "0"))
        server = (api_processes(settings, ca, acquirer[0], workers, tmp_path) if workers
                  else serve(create_app(settings, cards=cards)))
        with server as started, heartbeating(db, ready["terminal_id"]):
            port = started if workers else started[1]
            k6_env = {"API_URL": f"http://host.docker.internal:{port}", "TERMINAL_ID": ready["terminal_id"],
                      "MERCHANT_ID": str(merchant), "ENVELOPE": encrypted_card(),
                      **{k: os.environ[k] for k in ("RAMP", "RAMP2", "HOLD") if k in os.environ}}  # shorter stages
            if os.environ.get("LOAD_TEST_EXTERNAL_K6"):
                # Where this process can't reach Docker: publish the target, wait for k6 to be run by hand.
                (out / "k6.env").write_text("".join(f"{k}={v}\n" for k, v in k6_env.items()))
                deadline = time.monotonic() + 900
                while not (out / "k6.exit").exists() and time.monotonic() < deadline:
                    time.sleep(1)
                passed = (out / "k6.exit").exists() and (out / "k6.exit").read_text().strip() == "0"
                log = (out / "k6.txt").read_text() if (out / "k6.txt").exists() else ""
            else:
                # k6 runs from its pinned image: nothing to install, and the same on CI and a laptop.
                run = subprocess.run(["docker", "run", "--rm", "-v", f"{ROOT / 'loadtest'}:/scripts:ro",
                                      "-v", f"{out}:/out", *[a for k, v in k6_env.items() for a in ("-e", f"{k}={v}")],
                                      K6_IMAGE, "run", "--quiet", "--summary-export", "/out/summary.json",
                                      "/scripts/load-test.js"], capture_output=True, text=True, timeout=600)
                passed, log = run.returncode == 0, run.stdout + run.stderr
                (out / "k6.txt").write_text(log)
    finally:
        cards.close()
    summary = json.loads((out / "summary.json").read_text())
    m = summary["metrics"]
    print(f"\n{m['http_reqs']['rate']:.0f} req/s, p95 {m['http_req_duration']['p(95)']:.0f} ms, "
          f"failed {m['http_req_failed']['value']:.2%}")
    assert passed, f"k6 thresholds failed:\n{log[-4000:]}"
