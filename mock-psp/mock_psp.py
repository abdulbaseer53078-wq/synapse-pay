"""A mock UPI PSP: the UPI analogue of host-connector/mock_host.

Deterministic and offline, so the adapter's tests never depend on a real PSP's uptime, rate limits or webhook
timing. Amounts drive the outcome, the way mock_host.py does for ISO 8583:

  amount % 1000 == 100   → the collect ultimately FAILS (e.g. ₹51.00)
  amount % 1000 == 200   → it stays PENDING forever (a collect nobody answers: the polling fallback's case)
  otherwise              → it SUCCEEDS

Every collect is answered PENDING, because that is what a real PSP does: the customer has not entered their PIN
yet. The outcome is decided by status polls and by trigger-webhook, which is what the adapter is built around.

Run: python mock_psp.py [--port 0] [--secret s3cret]
Prints "LISTENING <port>" once bound, which is how the tests find it.
"""
import argparse
import hashlib
import hmac
import json
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VPA = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9]+$")
ACCOUNTS = {"asha@okhdfcbank": "Asha Menon", "ravi@okaxis": "Ravi Krishnan", "invalid@upi": None}

_lock = threading.Lock()
_collects: dict[str, dict] = {}
_secret = "s3cret"


def _outcome_for(amount: int) -> str:
    if amount % 1000 == 100:
        return "FAILURE"
    if amount % 1000 == 200:
        return "PENDING"  # never resolves on its own: exercises the poller
    return "SUCCESS"


def _signed(body: bytes) -> str:
    return hmac.new(_secret.encode(), body, hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass  # quiet: the tests read stdout only for LISTENING

    def _send(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        if self.path == "/mock/state":
            with _lock:
                return self._send(200, {"collects": list(_collects.values())})
        if self.path.startswith("/psp/v1/status/"):
            psp_id = self.path.rsplit("/", 1)[-1]
            with _lock:
                record = _collects.get(psp_id)
            if record is None:
                return self._send(404, {"error": {"code": "TRANSACTION_NOT_FOUND",
                                                  "message": f"no such psp_transaction_id: {psp_id}"}})
            return self._send(200, record)
        self._send(404, {"error": {"code": "NOT_FOUND", "message": self.path}})

    def do_POST(self):
        try:
            body = self._read()
        except ValueError:
            return self._send(400, {"error": {"code": "BAD_JSON", "message": "body is not JSON"}})

        if self.path == "/psp/v1/validate-vpa":
            vpa = str(body.get("vpa") or "")
            if not VPA.match(vpa):
                return self._send(400, {"error": {"code": "VPA_MALFORMED", "message": "not a VPA"}})
            name = ACCOUNTS.get(vpa)
            if name is None:
                return self._send(404, {"error": {"code": "VPA_NOT_FOUND",
                                                  "message": "no account is registered to this VPA"}})
            return self._send(200, {"vpa": vpa, "name": name, "status": "VALID"})

        if self.path == "/psp/v1/collect":
            amount = body.get("amount")
            vpa = str(body.get("vpa") or "")
            merchant_txn = str(body.get("merchant_transaction_id") or "")
            if not isinstance(amount, int) or amount <= 0 or not merchant_txn:
                return self._send(400, {"error": {"code": "BAD_COLLECT",
                                                  "message": "amount and merchant_transaction_id are required"}})
            if not VPA.match(vpa) or ACCOUNTS.get(vpa) is None:
                # A real PSP answers 404 for a VPA that cannot receive a collect.
                return self._send(404, {"error": {"code": "VPA_NOT_FOUND",
                                                  "message": "no account is registered to this VPA"}})
            psp_id = f"psp_{uuid.uuid4().hex}"
            record = {
                "psp_transaction_id": psp_id, "merchant_transaction_id": merchant_txn, "vpa": vpa,
                "amount": amount, "currency": body.get("currency", "INR"), "status": "PENDING",
                "reason": None, "created_at": time.time(),
            }
            with _lock:
                _collects[psp_id] = record
            return self._send(200, record)

        if self.path == "/psp/v1/refund":
            psp_id, amount = body.get("psp_transaction_id"), body.get("amount")
            with _lock:
                record = _collects.get(psp_id)
                if record is None:
                    return self._send(404, {"error": {"code": "TRANSACTION_NOT_FOUND", "message": psp_id}})
                # Only a settled collect can be refunded; a fresh PENDING one is a 409, as a real PSP answers.
                if record["status"] != "SUCCESS":
                    return self._send(409, {"error": {"code": "NOT_SETTLED",
                                                      "message": "only a successful collect can be refunded"}})
                if not isinstance(amount, int) or amount <= 0 or amount > record["amount"]:
                    return self._send(400, {"error": {"code": "BAD_REFUND",
                                                      "message": "amount must be between 1 and the original"}})
            return self._send(200, {"refund_id": f"rfnd_{uuid.uuid4().hex}", "psp_transaction_id": psp_id,
                                    "amount": amount, "status": "SUCCESS"})

        if self.path == "/mock/outcome":
            psp_id, status = body.get("psp_transaction_id"), body.get("status")
            if status not in ("SUCCESS", "FAILURE"):
                return self._send(400, {"error": {"code": "BAD_STATUS", "message": "SUCCESS or FAILURE"}})
            with _lock:
                record = _collects.get(psp_id)
                if record is None:
                    return self._send(404, {"error": {"code": "TRANSACTION_NOT_FOUND", "message": psp_id}})
                record["status"] = status
                record["reason"] = body.get("reason") or ("SUCCESS" if status == "SUCCESS" else "INSUFFICIENT_FUNDS")
            return self._send(200, record)

        if self.path == "/mock/advance":
            # The natural outcome of a collect: what a status poll would eventually see.
            psp_id = body.get("psp_transaction_id")
            with _lock:
                record = _collects.get(psp_id)
                if record is None:
                    return self._send(404, {"error": {"code": "TRANSACTION_NOT_FOUND", "message": psp_id}})
                outcome = _outcome_for(record["amount"])
                if outcome != "PENDING":
                    record["status"] = outcome
                    record["reason"] = "SUCCESS" if outcome == "SUCCESS" else "INSUFFICIENT_FUNDS"
            return self._send(200, record)

        if self.path == "/mock/trigger-webhook":
            psp_id, url = body.get("psp_transaction_id"), body.get("url")
            with _lock:
                record = _collects.get(psp_id)
            if record is None or not url:
                return self._send(400, {"error": {"code": "BAD_TRIGGER", "message": "psp_transaction_id and url"}})
            return self._send(200, {"delivered": False, "note": "webhook delivery lands in Step 10B",
                                    "payload": record, "signature": _signed(json.dumps(record).encode())})

        self._send(404, {"error": {"code": "NOT_FOUND", "message": self.path}})


def main(argv: list[str]) -> None:
    global _secret
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--secret", default="s3cret")
    args = parser.parse_args(argv)
    _secret = args.secret
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"LISTENING {server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main(sys.argv[1:])
