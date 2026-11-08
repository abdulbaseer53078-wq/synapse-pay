"""Self-test for region_chaos.py: the driver must measure downtime correctly and catch lost payments.

A fake two-region cluster sits behind one URL (the "DNS"). Each region applies the cloud's idempotency rules. The
failover hook takes region A down, waits, then makes B active with a copy of A's data, optionally minus the most
recent records, as an unplanned failover loses the replication lag.

    python -m unittest test_region_chaos   (from infra/game-day; standard library only)
"""
import json
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import region_chaos


class Region:
    def __init__(self, records=None):
        self.records = dict(records or {})  # idempotency_key -> (body, response); insertion-ordered

    def handle(self, body: bytes) -> tuple[int, dict]:
        key = json.loads(body)["idempotency_key"]
        if key in self.records:
            stored_body, response = self.records[key]
            if stored_body != body:
                return 409, {"error_code": "IDEMPOTENCY_KEY_CONFLICT", "retryable": False}
            return 201, response  # replay
        response = {"transaction_id": f"txn_{uuid.uuid4().hex}", "status": "CAPTURED"}
        self.records[key] = (body, response)
        return 201, response


class Cluster:
    """Region A active; fail_over() takes it down for `outage` seconds, then promotes B."""

    def __init__(self):
        self.active = Region()
        self.down = False
        self.lock = threading.Lock()
        cluster = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                with cluster.lock:
                    status, payload = (503, {"retryable": True}) if cluster.down else cluster.active.handle(body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def fail_over(self, outage: float, lose_last: int = 0) -> None:
        with self.lock:
            self.down = True
            survived = list(self.active.records.items())
            if lose_last:
                survived = survived[:-lose_last]  # the replication lag never reached B
        time.sleep(outage)
        with self.lock:
            self.active = Region(dict(survived))
            self.down = False

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def config(url, **overrides):
    base = dict(url=url, body={"amount": 15000, "currency": "INR", "payment_method": "CARD"}, duration=3,
                failover_at=1, rate=20, mode="switchover", max_downtime=2, timeout=1, grace=5)
    return region_chaos.Config(**{**base, **overrides})


class RegionChaosTest(unittest.TestCase):
    def setUp(self):
        region_chaos.RETRY_EVERY = 0.1  # terminals resend every second; keep the test fast
        self.cluster = Cluster()
        self.addCleanup(self.cluster.close)

    def test_clean_switchover_passes_and_measures_downtime(self):
        report = region_chaos.run(config(self.cluster.url), lambda: self.cluster.fail_over(outage=1.0))
        self.assertTrue(report.ok, report.failures)
        self.assertEqual(report.payments, report.acknowledged)
        self.assertEqual((report.lost, report.unresolved), ([], []))
        self.assertGreaterEqual(report.downtime, 1.0)
        self.assertLess(report.downtime, 1.5)

    def test_lost_replication_window_is_caught_as_lost_payments(self):
        report = region_chaos.run(config(self.cluster.url, mode="failover"),
                                  lambda: self.cluster.fail_over(outage=0.5, lose_last=3))
        self.assertFalse(report.ok)
        self.assertEqual(len(report.lost), 3, "the 3 acknowledged payments B never received were charged again")
        self.assertTrue(all(l["acknowledged"] != l["after_failover"] for l in report.lost))
        self.assertIn("double charge", report.failures[0])

    def test_slow_switchover_fails_on_downtime(self):
        report = region_chaos.run(config(self.cluster.url, max_downtime=1), lambda: self.cluster.fail_over(outage=1.5))
        self.assertFalse(report.ok)
        self.assertEqual(report.lost, [])
        self.assertTrue(any("downtime" in f for f in report.failures), report.failures)

    def test_unplanned_failover_reports_downtime_without_failing_on_it(self):
        report = region_chaos.run(config(self.cluster.url, mode="failover", max_downtime=1),
                                  lambda: self.cluster.fail_over(outage=1.5))
        self.assertTrue(report.ok, report.failures)
        self.assertGreaterEqual(report.downtime, 1.5)

    def test_payments_never_answered_are_unresolved(self):
        report = region_chaos.run(config(self.cluster.url, grace=0.5),
                                  lambda: self.cluster.fail_over(outage=4))  # still down when the run ends
        self.assertFalse(report.ok)
        self.assertTrue(report.unresolved)


if __name__ == "__main__":
    unittest.main()
