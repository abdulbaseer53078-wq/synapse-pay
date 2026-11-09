"""Step 21: the local transaction engine. When the cloud is unreachable, terminals send the edge the same
TransactionRequest they would send the cloud; the edge enforces the cached rules, signs the payment, queues it in
SQLite and answers PENDING_OFFLINE. The sync worker (Step 24) delivers it later.

shortcut: terminals reach this API over the shop's LAN; run it with TLS and client certificates required
(`__main__`), but the terminal_id in the body is not yet bound to the presenting certificate — bind it when the
edge reads the client certificate (it is checked against the merchant's terminals in the signed rules meanwhile).
"""
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Callable

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from edge_node import crypto, db
from edge_node.config import EdgeConfig
from edge_node.rules import RulesExpired, RulesMissing, RulesTampered, current_rules

ROLLING = timedelta(hours=24)  # the per_day offline limit's window
RAILS = ("CARD", "UPI", "WALLET", "QR")  # what an offline sale can be (the sync item's underlying_rail)
RECEIPT_NOTE = "OFFLINE - AWAITING BANK APPROVAL"


class TransactionRequest(BaseModel):
    """The cloud's TransactionRequest. Fields the sync item doesn't carry (metadata, webhook_url...) are accepted
    and dropped, so the SDK sends one payload whether it is talking to the cloud or to the edge."""
    model_config = ConfigDict(extra="ignore")
    idempotency_key: uuid.UUID
    amount: int = Field(gt=0)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    payment_method: str
    method_details: dict
    terminal_id: str = Field(min_length=1, max_length=64)
    merchant_id: str = Field(min_length=1, max_length=64)


def error(status: int, code: str, message: str, category: str, retryable: bool = False) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error_code": code, "error_message": message,
                                                     "error_category": category, "retryable": retryable})


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")


def create_app(cfg: EdgeConfig, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> FastAPI:
    conn = db.connect(cfg.db_path)
    db.migrate(conn)
    conn.close()
    app = FastAPI(title="SynapsePay Edge Node")

    @app.exception_handler(RequestValidationError)
    async def invalid(_, exc: RequestValidationError):  # field paths only: never echo values (card data)
        fields = "; ".join(".".join(map(str, e["loc"][1:])) for e in exc.errors())
        return error(400, "INVALID_REQUEST", f"invalid fields: {fields}", "VALIDATION_ERROR")

    @app.post("/local/v1/transactions", status_code=201)
    def create(req: TransactionRequest):
        at = now()
        if req.payment_method not in RAILS:
            return error(400, "INVALID_REQUEST", f"payment_method must be one of {', '.join(RAILS)}", "VALIDATION_ERROR")
        request_hash = hashlib.sha256(json.dumps(req.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
        conn = db.connect(cfg.db_path)
        try:
            try:
                rules = current_rules(conn, cfg, at)
            except RulesMissing:
                return error(503, "RULES_MISSING", "this edge has no offline rules yet", "SYSTEM_ERROR")
            except RulesExpired:
                return error(503, "RULES_EXPIRED", "offline rules are older than 72 hours; reconnect to refresh",
                             "SYSTEM_ERROR")
            except RulesTampered:
                return error(503, "RULES_TAMPERED", "offline rules failed verification", "SYSTEM_ERROR")
            if req.merchant_id != cfg.merchant_id or (rules.terminals and req.terminal_id not in rules.terminals):
                return error(403, "TERMINAL_NOT_FOUND", "terminal is not one of this merchant's", "AUTHENTICATION_ERROR")

            conn.execute("BEGIN IMMEDIATE")  # the day's total and the insert must not interleave with another sale
            try:
                existing = conn.execute("SELECT request_hash, offline_reference, created_at FROM offline_queue"
                                        " WHERE idempotency_key = ?", (str(req.idempotency_key),)).fetchone()
                if existing is not None:
                    conn.execute("COMMIT")
                    if existing["request_hash"] != request_hash:
                        return error(409, "IDEMPOTENCY_KEY_CONFLICT",
                                     "idempotency_key was already used with a different request body", "VALIDATION_ERROR")
                    return JSONResponse(status_code=200, content=_response(req, existing["offline_reference"],
                                                                           existing["created_at"]))
                if req.amount > rules.offline_limits.per_transaction:
                    conn.execute("COMMIT")
                    return error(422, "OFFLINE_LIMIT_EXCEEDED",
                                 f"offline payments are limited to {rules.offline_limits.per_transaction}",
                                 "HARD_DECLINE")
                # PR 6 (F-06): a rolling 24 hours, not the calendar day (no fresh allowance at midnight), and
                # anything not yet synced counts whatever its timestamp, so winding the clock on can't free it.
                (exposure,) = conn.execute(
                    "SELECT coalesce(sum(amount), 0) FROM offline_queue WHERE terminal_id = ? AND status != 'FAILED'"
                    " AND (created_at >= ? OR status IN ('PENDING_OFFLINE', 'SYNCING'))",
                    (req.terminal_id, _iso(at - ROLLING))).fetchone()
                if exposure + req.amount > rules.offline_limits.per_day:
                    conn.execute("COMMIT")
                    return error(422, "OFFLINE_LIMIT_EXCEEDED",
                                 "this terminal's offline total for the last 24 hours is reached", "HARD_DECLINE")
                reference, created = str(uuid.uuid4()), _iso(at)
                item = {"offline_reference": reference, "local_timestamp": created,
                        "idempotency_key": str(req.idempotency_key), "amount": req.amount, "currency": req.currency,
                        "payment_method": "OFFLINE", "underlying_rail": req.payment_method,
                        "terminal_id": req.terminal_id, "merchant_id": req.merchant_id,
                        "method_details": req.method_details, "edge_node_id": cfg.edge_node_id}
                head = conn.execute("SELECT last_seq, last_hash FROM chain_head").fetchone()
                item["edge_seq"], item["prev_hash"] = (head[0] + 1, head[1]) if head else (1, "")
                item["signature"] = crypto.sign(cfg.signing_key_pem, item)  # the chain fields are signed too
                conn.execute(
                    "INSERT INTO offline_queue (offline_reference, idempotency_key, request_hash, terminal_id, amount,"
                    " payload_json, created_at, updated_at, edge_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (reference, str(req.idempotency_key), request_hash, req.terminal_id, req.amount,
                     json.dumps(item), created, created, item["edge_seq"]))
                conn.execute("INSERT INTO chain_head (singleton, last_seq, last_hash) VALUES (1, ?, ?)"
                             " ON CONFLICT (singleton) DO UPDATE SET last_seq = excluded.last_seq,"
                             " last_hash = excluded.last_hash", (item["edge_seq"], crypto.chain_hash(item)))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            return _response(req, reference, created)
        finally:
            conn.close()

    @app.get("/local/v1/transactions/{offline_reference}")
    def status(offline_reference: str):
        conn = db.connect(cfg.db_path)
        try:
            row = conn.execute("SELECT offline_reference, status, transaction_id, result_json FROM offline_queue"
                               " WHERE offline_reference = ?", (offline_reference,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return error(404, "NOT_FOUND", "no such offline payment", "VALIDATION_ERROR")
        result = json.loads(row["result_json"]) if row["result_json"] else {}
        return {"offline_reference": row["offline_reference"], "status": row["status"],
                "transaction_id": row["transaction_id"], "error": result.get("error")}

    return app


def _response(req: TransactionRequest, reference: str, created: str) -> dict:
    return {"offline_reference": reference, "idempotency_key": str(req.idempotency_key), "status": "PENDING_OFFLINE",
            "amount": req.amount, "currency": req.currency, "payment_method": req.payment_method,
            "created_at": created, "receipt_note": RECEIPT_NOTE}
