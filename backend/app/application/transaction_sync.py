"""Offline sync (Stage 1, Step 13): a terminal's queued sales become real transactions.

An offline payment is not a new rail — it is a sale the terminal accepted without connectivity and is now
telling us about. So this service does not invent a parallel transaction path: for every item it verifies the
terminal's signature, enforces the advertised offline_limits, and then submits the item to the normal engine
with the **underlying rail** as its payment_method. Idempotency, authorization, audit and webhooks are therefore
the same code the online path uses, and the audit trail names the rail that actually moved the money.

Items are independent: one forged or stale item must not fail the other ninety-nine, so the response is a
per-item result list and the HTTP status stays 200.

An edge node (Step 21) uploads sales it accepted for its merchant's terminals. Then the edge's key signs every item,
its own signed offline limits apply, and each item names the edge and its merchant: an edge can't speak for another
merchant's terminal (the engine also checks the terminal belongs to that merchant).
"""
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from app.application.methods import MethodRegistry
from app.application.offline_sync import OfflineSignatureInvalid, verify_item
from app.application.registration import RegistrationError


class SyncRepository(Protocol):
    def terminal_public_key(self, terminal_id: UUID) -> str | None:
        """The registration certificate's public key: the only thing that can prove who queued the sale."""


class EdgeRepository(Protocol):
    def get(self, edge_node_id: UUID): ...
    def public_key(self, edge_node_id: UUID) -> str | None: ...


class SyncEngine(Protocol):
    def create(self, caller_terminal: UUID, body: dict) -> dict: ...


def _failed(reference: str, reason: str) -> dict:
    return {"offline_reference": reference, "status": "FAILED", "reason": reason}


class OfflineSyncService:
    def __init__(self, methods: MethodRegistry, repository: SyncRepository, engine: SyncEngine,
                 verify: Callable[[str, bytes, bytes], bool], clock=time.time, edges: EdgeRepository | None = None):
        self.methods = methods
        self.edges = edges
        self.repository = repository
        self.engine = engine
        self.verify = verify  # the CA's signature check, reused rather than reinvented
        self.clock = clock

    def limits(self) -> dict:
        offline = self.methods.for_method("OFFLINE").capabilities()
        return offline.offline_limits or {"max_per_txn": 0, "max_age_minutes": 0, "currency": "INR"}

    def sync(self, terminal_id: UUID, items: list[dict]) -> list[dict]:
        public_key = self.repository.terminal_public_key(terminal_id)
        if public_key is None:
            # The gateway authenticated the certificate; a missing key means the row is gone. Refuse the batch.
            raise RegistrationError("terminal has no registration certificate", code="TERMINAL_NOT_FOUND")

        limits = self.limits()
        now = datetime.fromtimestamp(self.clock(), UTC)
        results = []
        for item in items:
            reference = str(item.get("offline_reference") or "")
            results.append(self._one(item, reference, public_key, limits, terminal_id, now))
        return results

    def sync_edge(self, edge_node_id: UUID, items: list[dict]) -> list[dict]:
        node = self.edges.get(edge_node_id) if self.edges else None
        public_key = self.edges.public_key(edge_node_id) if node else None
        if public_key is None:
            raise RegistrationError("edge node is not active or has no certificate", code="EDGE_NODE_NOT_FOUND")
        limits = {"max_per_txn": node.limits.per_transaction, "max_age_minutes": node.limits.max_age_minutes}
        now = datetime.fromtimestamp(self.clock(), UTC)
        results = []
        for item in items:
            reference = str(item.get("offline_reference") or "")
            # Both fields are signed, so a mismatch is a misrouted item, not a forgery: say which.
            if str(item.get("edge_node_id")) != str(edge_node_id) or str(item.get("merchant_id")) != str(node.merchant_id):
                results.append(_failed(reference, "EDGE_MISMATCH"))
                continue
            try:
                terminal_id = UUID(str(item.get("terminal_id")))
            except ValueError:
                results.append(_failed(reference, "TERMINAL_MISMATCH"))
                continue
            results.append(self._one(item, reference, public_key, limits, terminal_id, now))
        return results

    def _one(self, item, reference, public_key, limits, terminal_id, now) -> dict:
        try:
            verify_item(item, public_key, self.verify)
        except OfflineSignatureInvalid:
            return _failed(reference, "SIGNATURE_INVALID")

        if int(item.get("amount") or 0) > int(limits.get("max_per_txn") or 0):
            return _failed(reference, "OFFLINE_LIMIT_EXCEEDED")

        try:
            accepted_at = datetime.fromisoformat(str(item["local_timestamp"]).replace("Z", "+00:00"))
        except (KeyError, ValueError):
            return _failed(reference, "OFFLINE_TIMESTAMP_INVALID")
        if (now - accepted_at).total_seconds() > int(limits.get("max_age_minutes") or 0) * 60:
            return _failed(reference, "OFFLINE_TRANSACTION_EXPIRED")

        body = {
            "idempotency_key": item["idempotency_key"], "amount": item["amount"],
            "currency": item["currency"], "payment_method": item["underlying_rail"],
            "method_details": item["method_details"], "terminal_id": str(terminal_id),
            "merchant_id": item["merchant_id"],
        }
        try:
            response = self.engine.create(terminal_id, body)
        except RegistrationError as exc:
            # A rail-level refusal is this item's outcome, not the batch's.
            return _failed(reference, exc.code)
        return {"offline_reference": reference, "transaction_id": response["transaction_id"],
                "status": response["status"]}
