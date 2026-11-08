"""PR 9: the load test (loadtest/load-test.js) against the real stack. Opt-in: LOAD_TEST=1 (needs Docker for k6).

Starts the API on a real port in front of the card service and the mock acquirer (the e2e `acquirer` fixture),
registers an active, certified terminal, then runs k6 and fails on its thresholds (p95 < 500 ms, < 1 % errors).
The summary lands in $LOAD_TEST_OUT (default: the test's tmp dir). Takes about 3.5 minutes.

LOAD_TEST_EXTERNAL_K6=1, for hosts where this process can't reach Docker: the test writes $LOAD_TEST_OUT/k6.env and
waits; run loadtest/run-k6.sh <LOAD_TEST_OUT> from a shell that can, and the test reads its summary."""
import functools
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from psycopg_pool import ConnectionPool

import app.main as app_main
from app.infrastructure.card_service_client import HttpCardProcessor
from app.main import create_app
from card_sim import encrypted_card
from e2e_stack import ROOT, needs_cargo
from test_chaos_gate import serve
from test_transactions_e2e import ready  # noqa: F401  (fixture)

K6_IMAGE = "grafana/k6:1.0.0"
pytestmark = [needs_cargo, pytest.mark.skipif(not os.environ.get("LOAD_TEST"), reason="opt-in: set LOAD_TEST=1")]


def test_card_payments_at_100_tps(settings, db, ready, merchant, acquirer, tmp_path, monkeypatch):  # noqa: F811
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
        with serve(create_app(settings, cards=cards)) as (_, port):
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
