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
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from app.application.methods import MethodRegistry
from app.application.offline_sync import OfflineSignatureInvalid, verify_item
from app.application.registration import Forbidden, RegistrationError
from app.domain.edge_chain import chain_hash, judge


class SyncRepository(Protocol):
    def terminal_public_key(self, terminal_id: UUID) -> str | None:
        """The registration certificate's public key: the only thing that can prove who queued the sale."""


class EdgeRepository(Protocol):
    def get(self, edge_node_id: UUID): ...
    def public_key(self, edge_node_id: UUID) -> str | None: ...


class EdgeChain(Protocol):
    """The cloud's record of each edge's hash chain (PR 6) and of the offline spend it accepted."""
    def exclusive(self, edge_node_id: UUID): ...
    def flagged(self, edge_node_id: UUID) -> str | None: ...
    def head(self, edge_node_id: UUID, seqs: list[int]) -> tuple[int, dict[int, str]]: ...
    def record(self, edge_node_id: UUID, links: list[tuple[int, str]]) -> None: ...
    def flag(self, edge_node_id: UUID, reason: str) -> None: ...
    def offline_total(self, terminal_id: UUID, since: datetime, until: datetime, excluding_key: str) -> int: ...


class OpsAlerts(Protocol):
    def ops_alert(self, summary: str, severity: str, details: dict) -> None: ...


class SyncEngine(Protocol):
    def create(self, caller_terminal: UUID, body: dict) -> dict: ...


def _failed(reference: str, reason: str) -> dict:
    return {"offline_reference": reference, "status": "FAILED", "reason": reason}


class OfflineSyncService:
    def __init__(self, methods: MethodRegistry, repository: SyncRepository, engine: SyncEngine,
                 verify: Callable[[str, bytes, bytes], bool], clock=time.time, edges: EdgeRepository | None = None,
                 chain: EdgeChain | None = None, alerts: OpsAlerts | None = None):
        self.methods = methods
        self.edges = edges
        self.chain = chain
        self.alerts = alerts
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
        limits = {"max_per_txn": node.limits.per_transaction, "max_age_minutes": node.limits.max_age_minutes,
                  "per_day": node.limits.per_day}
        now = datetime.fromtimestamp(self.clock(), UTC)
        with self.chain.exclusive(edge_node_id):
            reason = self.chain.flagged(edge_node_id)
            if reason:
                raise Forbidden(f"this edge's offline sales are on hold for review: {reason}")
            results: dict[int, dict] = {}
            routed = []  # (position, item, terminal_id): this edge's, signed and well formed
            for position, item in enumerate(items):
                reference = str(item.get("offline_reference") or "")
                # Both fields are signed, so a mismatch is a misrouted item, not a forgery: say which.
                if str(item.get("edge_node_id")) != str(edge_node_id) or str(item.get("merchant_id")) != str(node.merchant_id):
                    results[position] = _failed(reference, "EDGE_MISMATCH")
                    continue
                try:
                    terminal_id = UUID(str(item.get("terminal_id")))
                except ValueError:
                    results[position] = _failed(reference, "TERMINAL_MISMATCH")
                    continue
                try:
                    verify_item(item, public_key, self.verify)
                except OfflineSignatureInvalid:
                    results[position] = _failed(reference, "SIGNATURE_INVALID")
                    continue
                routed.append((position, item, terminal_id))

            broken = self._check_chain(edge_node_id, [item for _, item, _ in routed])
            if broken:
                self.chain.flag(edge_node_id, broken)
                if self.alerts:
                    self.alerts.ops_alert("SECURITY: an edge node's offline queue was tampered with", "critical",
                                          {"edge_node_id": str(edge_node_id), "detail": broken})
                raise Forbidden(f"this edge's offline queue doesn't add up ({broken}); its sales are on hold for review")

            for position, item, terminal_id in routed:
                reference = str(item.get("offline_reference") or "")
                results[position] = self._one(item, reference, public_key, limits, terminal_id, now, verified=True)
        return [results[i] for i in range(len(items))]

    def _check_chain(self, edge_node_id: UUID, items: list[dict]) -> str | None:
        """None, having recorded the new links, if the batch extends this edge's chain; otherwise why it doesn't.

        An edge that has never sent a chained item may still send unchained ones (it predates PR 6); once it has
        chained it can't stop, or deleting a sale would be as easy as sending the rest unchained.
        """
        chained = [i for i in items if "edge_seq" in i]
        seqs = [i["edge_seq"] for i in chained]
        if any(not isinstance(q, int) or isinstance(q, bool) for q in seqs) or \
                any(not isinstance(i.get("prev_hash"), str) for i in chained):
            return "edge_seq must be an integer and prev_hash a string"
        last, seen = self.chain.head(edge_node_id, seqs)
        if len(chained) < len(items):
            return "an unchained item from an edge that chains its queue" if last or chained else None
        links = []
        for item in sorted(chained, key=lambda i: i["edge_seq"]):
            seq, digest = item["edge_seq"], chain_hash(item)
            why = judge(seq, item["prev_hash"], digest, seen, last)
            if why:
                return why
            if seq > last:
                links.append((seq, digest))
                seen[seq], last = digest, seq
        self.chain.record(edge_node_id, links)
        return None

    def _one(self, item, reference, public_key, limits, terminal_id, now, verified=False) -> dict:
        if not verified:
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
        if "per_day" in limits:
            # F-07: the edge enforces this too, but the cloud must not rely on a box in a shop. Rolling 24 hours by
            # the edge's clock, the same window the edge applied.
            spent = self.chain.offline_total(terminal_id, accepted_at - timedelta(hours=24), accepted_at,
                                             str(item["idempotency_key"]))
            if spent + int(item["amount"]) > int(limits["per_day"]):
                return _failed(reference, "OFFLINE_DAILY_LIMIT_EXCEEDED")

        body = {
            "idempotency_key": item["idempotency_key"], "amount": item["amount"],
            "currency": item["currency"], "payment_method": item["underlying_rail"],
            "method_details": item["method_details"], "terminal_id": str(terminal_id),
            "merchant_id": item["merchant_id"],
        }
        if "per_day" in limits:  # an edge's sale: remember when it was made, for the rolling limit above
            body["metadata"] = {"offline_reference": reference, "offline_local_timestamp": accepted_at.isoformat()}
        try:
            response = self.engine.create(terminal_id, body)
        except RegistrationError as exc:
            # A rail-level refusal is this item's outcome, not the batch's.
            return _failed(reference, exc.code)
        return {"offline_reference": reference, "transaction_id": response["transaction_id"],
                "status": response["status"]}
