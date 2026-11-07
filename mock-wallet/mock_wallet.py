"""A mock wallet provider: the analogue of mock_psp.py for stored-value wallets.

Deterministic, so the adapter's tests never depend on a provider's uptime:

  wallet_token == "tok_blocked"        → WALLET_BLOCKED (KYC limits), 403
  amount > 1_000_000                   → WALLET_LIMIT_EXCEEDED, 400
  amount % 1000 == 100                 → WALLET_INSUFFICIENT_BALANCE, 402
  otherwise                            → SUCCESS

Two entry points, because wallets have two flows: `/wallet/v1/pay` hands the user to the provider's own UI
(answered PENDING with an action URL), and `/wallet/v1/debit` charges a stored token server-to-server
(answered SETTLED). The adapter only implements the second today; see docs/step12.md for why.

Run: python mock_wallet.py [--port 0] [--secret s3cret]
Prints "LISTENING <port>".
"""
import argparse
import hashlib
import hmac
import json
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_PER_TRANSACTION = 1_000_000  # ₹10,000 in paise

_lock = threading.Lock()
_debits: dict[str, dict] = {}
_secret = "s3cret"


def _signed(body: bytes) -> str:
    return hmac.new(_secret.encode(), body, hashlib.sha256).hexdigest()


def _outcome_for(amount: int) -> str:
    if amount % 1000 == 100:
        return "INSUFFICIENT_BALANCE"
    return "SUCCESS"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _send(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, code: str, message: str) -> None:
        self._send(status, {"error": {"code": code, "message": message}})

    def _read(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        if self.path == "/mock/state":
            with _lock:
                return self._send(200, {"debits": list(_debits.values())})
        if self.path.startswith("/wallet/v1/status/"):
            wallet_id = self.path.rsplit("/", 1)[-1]
            with _lock:
                record = _debits.get(wallet_id)
            if record is None:
                return self._error(404, "TRANSACTION_NOT_FOUND", wallet_id)
            return self._send(200, record)
        self._error(404, "NOT_FOUND", self.path)

    def do_POST(self):
        try:
            body = self._read()
        except ValueError:
            return self._error(400, "BAD_JSON", "body is not JSON")

        if self.path == "/wallet/v1/pay":
            amount, merchant_txn = body.get("amount"), str(body.get("merchant_transaction_id") or "")
            if not isinstance(amount, int) or amount <= 0 or not merchant_txn:
                return self._error(400, "BAD_PAY", "amount and merchant_transaction_id are required")
            wallet_id = f"wal_{uuid.uuid4().hex}"
            with _lock:
                _debits[wallet_id] = {"wallet_transaction_id": wallet_id, "merchant_transaction_id": merchant_txn,
                                      "amount": amount, "status": "PENDING", "created_at": time.time()}
            return self._send(200, {
                "wallet_transaction_id": wallet_id, "status": "PENDING",
                # The provider's own UI. The SDK decides whether to deep-link, popup or iframe.
                "action_url": f"https://wallet.example/checkout/{wallet_id}"})

        if self.path == "/wallet/v1/debit":
            token = str(body.get("wallet_token") or "")
            amount = body.get("amount")
            merchant_txn = str(body.get("merchant_transaction_id") or "")
            if not token or not isinstance(amount, int) or amount <= 0 or not merchant_txn:
                return self._error(400, "BAD_DEBIT", "wallet_token, amount and merchant_transaction_id required")
            if token == "tok_blocked":
                return self._error(403, "WALLET_BLOCKED", "wallet is blocked pending KYC")
            if amount > MAX_PER_TRANSACTION:
                return self._error(400, "WALLET_LIMIT_EXCEEDED", "above the wallet's per-transaction limit")
            outcome = _outcome_for(amount)
            if outcome == "INSUFFICIENT_BALANCE":
                return self._error(402, "WALLET_INSUFFICIENT_BALANCE", "wallet balance is too low")
            wallet_id = f"wal_{uuid.uuid4().hex}"
            record = {"wallet_transaction_id": wallet_id, "merchant_transaction_id": merchant_txn,
                      "amount": amount, "status": "SUCCESS", "created_at": time.time()}
            with _lock:
                _debits[wallet_id] = record
            return self._send(200, record)

        if self.path == "/mock/trigger-webhook":
            wallet_id = body.get("wallet_transaction_id")
            with _lock:
                record = _debits.get(wallet_id)
            if record is None:
                return self._error(400, "BAD_TRIGGER", wallet_id)
            delivery = {"event_id": f"wevt_{uuid.uuid4().hex}", "wallet_transaction_id": wallet_id,
                        "status": body.get("status") or record["status"], "reason": None}
            raw = json.dumps(delivery).encode()
            timestamp = str(int(time.time()))
            signature = hmac.new(_secret.encode(), f"{timestamp}.".encode() + raw, hashlib.sha256).hexdigest()
            return self._send(200, {"body": raw.decode(), "headers": {
                "X-Wallet-Timestamp": timestamp, "X-Wallet-Signature": signature}})

        self._error(404, "NOT_FOUND", self.path)


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
