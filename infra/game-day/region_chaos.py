#!/usr/bin/env python3
"""Region chaos test driver (Stage 4, Task 17.6). Standard library only. Run it in staging, never in production.

Sends transactions continuously to the global URL the way terminals do (any failure: resend the same idempotency
key and body until a final answer), triggers the failover partway through, then checks the money:

  1. No acknowledged payment lost. Every request that got a 2xx is re-sent with its key and body after the
     failover. The cloud must replay the same transaction_id. A new one means the payment was lost with the old
     region and has just been processed again: a lost acknowledgement *and* a second charge.
  2. Exactly one outcome per payment. Nothing is still in doubt at the end.
  3. Downtime, the longest stretch in which every attempt failed, is under --max-downtime for a planned
     `switchover`. For an unplanned `failover`, promotion is a human decision (docs/step17.md), so downtime is
     measured and reported, not failed.

    python region_chaos.py --url https://api.staging.synapsepay.example --body body.json \\
        --cert terminal.pem --key terminal-key.pem --duration 600 --failover-at 120 \\
        --mode switchover --failover-cmd "./switchover.sh"

--body is a TransactionRequest JSON without idempotency_key (the driver adds a fresh one per payment).
Without --failover-cmd, the driver prints when to fail over and an operator does it by hand.
Exit status: 0 if every check passed, 1 otherwise. A JSON report goes to --report.
"""
import argparse
import json
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable

RETRY_EVERY = 1.0  # seconds between resends of an in-doubt payment, like a terminal


@dataclass
class Config:
    url: str  # base URL; POSTs go to {url}/api/v1/transactions
    body: dict
    duration: float = 600
    failover_at: float = 120
    rate: float = 5  # new payments per second
    mode: str = "switchover"  # or "failover"
    max_downtime: float = 120
    timeout: float = 5
    grace: float = 300  # after duration: how long in-doubt payments keep being resent
    headers: dict = field(default_factory=dict)
    ssl_context: ssl.SSLContext | None = None


@dataclass
class Payment:
    key: str
    body: bytes
    ack: dict | None = None  # first 2xx response
    final_status: int | None = None
    attempts: int = 0


@dataclass
class Report:
    payments: int = 0
    acknowledged: int = 0
    rejected: int = 0  # final non-2xx answers (e.g. a decline): an outcome, not a failure of the failover
    unresolved: list = field(default_factory=list)
    lost: list = field(default_factory=list)
    downtime: float = 0.0
    downtime_window: tuple | None = None
    failures: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


class Driver:
    def __init__(self, config: Config):
        self.c = config
        self.payments: list[Payment] = []
        self.events: list[tuple[float, bool]] = []  # (time, attempt succeeded) for every attempt
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def post(self, p: Payment) -> tuple[int | None, dict | None]:
        """One attempt. (status, json) or (None, None) on a network error or timeout."""
        req = urllib.request.Request(f"{self.c.url}/api/v1/transactions", data=p.body, method="POST",
                                     headers={"Content-Type": "application/json", **self.c.headers})
        try:
            with urllib.request.urlopen(req, timeout=self.c.timeout, context=self.c.ssl_context) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            with e:  # close it: a long game day would otherwise leak a socket per error
                try:
                    return e.code, json.loads(e.read() or b"{}")
                except ValueError:
                    return e.code, {}
        except (OSError, ValueError):
            return None, None

    @staticmethod
    def retryable(status: int | None, body: dict | None) -> bool:
        if status is None or status >= 500 or status == 429:
            return True
        return status == 409 and bool((body or {}).get("retryable"))  # same request still processing

    def settle(self, p: Payment, deadline: float) -> None:
        """Send until a final answer or the deadline, like a terminal that never changes the payload."""
        while time.monotonic() < deadline:
            status, body = self.post(p)
            now = time.monotonic()
            with self.lock:
                p.attempts += 1
                self.events.append((now, status is not None and 200 <= status < 300))
            if not self.retryable(status, body):
                p.final_status = status
                if 200 <= status < 300:
                    p.ack = body
                return
            time.sleep(RETRY_EVERY)

    def run(self, failover: Callable[[], None]) -> Report:
        start = time.monotonic()
        stop_new = start + self.c.duration
        deadline = stop_new + self.c.grace
        workers = []
        trigger = threading.Timer(self.c.failover_at, failover)
        trigger.daemon = True
        trigger.start()
        interval = 1 / self.c.rate
        next_at = start
        while time.monotonic() < stop_new:
            body = {**self.c.body, "idempotency_key": str(uuid.uuid4())}
            p = Payment(body["idempotency_key"], json.dumps(body).encode())
            self.payments.append(p)
            t = threading.Thread(target=self.settle, args=(p, deadline), daemon=True)
            t.start()
            workers.append(t)
            next_at += interval
            time.sleep(max(0.0, next_at - time.monotonic()))
        trigger.join()
        for t in workers:
            t.join(max(0.0, deadline - time.monotonic()))
        return self.verify()

    def downtime(self) -> tuple[float, tuple | None]:
        """Longest window from the last success before a failed attempt to the next success."""
        worst, window, last_ok, failed_since = 0.0, None, None, False
        for at, ok in sorted(self.events):
            if ok:
                if failed_since and last_ok is not None and at - last_ok > worst:
                    worst, window = at - last_ok, (last_ok, at)
                last_ok, failed_since = at, False
            else:
                failed_since = True
        return worst, window

    def verify(self) -> Report:
        r = Report(payments=len(self.payments))
        for p in self.payments:
            if p.ack is not None:
                r.acknowledged += 1
            elif p.final_status is not None:
                r.rejected += 1
            else:
                r.unresolved.append(p.key)
        # Replay every acknowledged payment: the cloud must answer with the transaction it acknowledged.
        for p in self.payments:
            if p.ack is None:
                continue
            status, body = self.post(p)
            for _ in range(10):
                if not self.retryable(status, body):
                    break
                time.sleep(RETRY_EVERY)
                status, body = self.post(p)
            if not (status and 200 <= status < 300) or (body or {}).get("transaction_id") != p.ack.get("transaction_id"):
                r.lost.append({"idempotency_key": p.key, "acknowledged": p.ack.get("transaction_id"),
                               "after_failover": (body or {}).get("transaction_id"), "status": status})
        r.downtime, r.downtime_window = self.downtime()
        if r.lost:
            r.failures.append(f"{len(r.lost)} acknowledged payment(s) lost and processed again (double charge)")
        if r.unresolved:
            r.failures.append(f"{len(r.unresolved)} payment(s) never reached a final answer")
        if self.c.mode == "switchover" and r.downtime > self.c.max_downtime:
            r.failures.append(f"downtime {r.downtime:.1f} s exceeds {self.c.max_downtime:.0f} s")
        return r


def run(config: Config, failover: Callable[[], None]) -> Report:
    return Driver(config).run(failover)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Region failover chaos test (Task 17.6)")
    p.add_argument("--url", required=True)
    p.add_argument("--body", required=True, help="TransactionRequest JSON file, without idempotency_key")
    p.add_argument("--duration", type=float, default=600)
    p.add_argument("--failover-at", type=float, default=120)
    p.add_argument("--rate", type=float, default=5)
    p.add_argument("--mode", choices=["switchover", "failover"], default="switchover")
    p.add_argument("--max-downtime", type=float, default=120)
    p.add_argument("--failover-cmd", help="shell command that performs the failover; omit to do it by hand")
    p.add_argument("--header", action="append", default=[], help="extra header, 'Name: value' (repeatable)")
    p.add_argument("--cert", help="client certificate (PEM), e.g. a staging terminal's")
    p.add_argument("--key", help="client certificate key (PEM)")
    p.add_argument("--ca", help="CA bundle for the server certificate")
    p.add_argument("--report", default="region-chaos-report.json")
    a = p.parse_args(argv)

    context = ssl.create_default_context(cafile=a.ca) if a.url.startswith("https") else None
    if context and a.cert:
        context.load_cert_chain(a.cert, a.key)
    with open(a.body, encoding="utf-8") as f:
        body = json.load(f)
    headers = dict(h.split(":", 1) for h in a.header)
    config = Config(a.url.rstrip("/"), body, a.duration, a.failover_at, a.rate, a.mode, a.max_downtime,
                    headers={k.strip(): v.strip() for k, v in headers.items()}, ssl_context=context)

    def failover():
        print(f"[{a.failover_at:.0f} s] failing over ({a.mode})", flush=True)
        if a.failover_cmd:
            done = subprocess.run(a.failover_cmd, shell=True)
            print(f"failover command exited {done.returncode}", flush=True)
        else:
            print(">>> FAIL OVER NOW: follow docs/step17.md; the driver keeps sending <<<", flush=True)

    report = run(config, failover)
    with open(a.report, "w", encoding="utf-8") as f:
        json.dump({**report.__dict__, "ok": report.ok}, f, indent=2, default=str)
    print(f"payments {report.payments}, acknowledged {report.acknowledged}, rejected {report.rejected}, "
          f"lost {len(report.lost)}, unresolved {len(report.unresolved)}, downtime {report.downtime:.1f} s")
    for failure in report.failures:
        print(f"FAIL: {failure}")
    print("PASS" if report.ok else "FAILED")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
