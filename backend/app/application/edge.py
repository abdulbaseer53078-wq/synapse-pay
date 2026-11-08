"""Edge nodes (Step 20): registering them, and the signed offline rules they fetch.

The rules are what an edge node may do while the cloud is unreachable: how much one offline payment may be, how
much a terminal may take offline in a day, which terminals are the merchant's. They are signed with the cloud's
rules key, and the payload binds the edge_node_id, the merchant_id and an expiry, so a rule set can't be replayed
to another edge, moved to another merchant, or kept past its date. rules_version only moves forward.
"""
import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, Protocol
from uuid import UUID, uuid4

from app.application.offline_sync import canonical_item
from app.application.registration import (CertificateAuthority, CertificateAuthorityUnavailable, Forbidden,
                                          InvalidInput, IssuedCertificate, NotFound)
from app.domain.edge import RULES_TTL, edge_uri


@dataclass(frozen=True)
class OfflineLimits:
    per_transaction: int  # minor units
    per_day: int  # per terminal, per local day
    max_age_minutes: int = 4320

    def check(self) -> None:
        if self.per_transaction <= 0 or self.per_day < self.per_transaction or self.max_age_minutes <= 0:
            raise InvalidInput("offline limits: per_transaction > 0, per_day >= per_transaction, max_age_minutes > 0")


@dataclass(frozen=True)
class EdgeNode:
    edge_node_id: UUID
    merchant_id: UUID
    status: str
    rules_version: int
    limits: OfflineLimits


@dataclass(frozen=True)
class RegisteredEdge:
    edge_node_id: UUID
    certificate_pem: str
    ca_certificate_pem: str
    rules_public_key_pem: str  # the edge pins this to verify every rule set it receives


class EdgeRepository(Protocol):
    def create(self, edge_node_id: UUID, merchant_id: UUID, limits: OfflineLimits, cert: IssuedCertificate,
               actor_id: str) -> None:
        """Raises UnknownReference for an unknown merchant. Audited."""
    def get(self, edge_node_id: UUID) -> EdgeNode | None: ...
    def update_limits(self, edge_node_id: UUID, limits: OfflineLimits, actor_id: str) -> int:
        """Stores new limits and returns the new rules_version (always higher). NotFound if unknown. Audited."""
    def active_terminals(self, merchant_id: UUID) -> list[str]: ...


class RulesSigner(Protocol):
    public_key_pem: str

    def sign(self, message: bytes) -> bytes: ...


class EdgeService:
    def __init__(self, repo: EdgeRepository, ca: CertificateAuthority, signer: RulesSigner | None,
                 routing_rules: dict[str, tuple[str, ...]], now: Callable[[], datetime] | None = None):
        self.repo = repo
        self.ca = ca
        self.signer = signer
        self.routing_rules = routing_rules
        self.now = now or (lambda: datetime.now(UTC))

    def _signer(self) -> RulesSigner:
        if self.signer is None:
            raise CertificateAuthorityUnavailable("edge rules signing key is not configured")
        return self.signer

    def register(self, merchant_id: UUID, csr_pem: str, limits: OfflineLimits, actor_id: str) -> RegisteredEdge:
        limits.check()
        signer = self._signer()
        edge_node_id = uuid4()
        # Certificate first: a row without one would be an edge that can never authenticate.
        cert = self.ca.issue(csr_pem, edge_node_id, uri=edge_uri(edge_node_id))
        self.repo.create(edge_node_id, merchant_id, limits, cert, actor_id)
        return RegisteredEdge(edge_node_id, cert.certificate_pem, self.ca.ca_certificate_pem, signer.public_key_pem)

    def update_limits(self, edge_node_id: UUID, limits: OfflineLimits, actor_id: str) -> int:
        limits.check()
        return self.repo.update_limits(edge_node_id, limits, actor_id)

    def admit(self, edge_node_id: UUID) -> None:
        """Gateway check for an edge node's certificate: only a registered, ACTIVE edge gets through."""
        node = self.repo.get(edge_node_id)
        if node is None or node.status != "ACTIVE":
            raise Forbidden("certificate's edge node is not registered or not active")

    def rules(self, edge_node_id: UUID) -> dict:
        """The signed rule set for the edge that authenticated as `edge_node_id`."""
        signer = self._signer()
        node = self.repo.get(edge_node_id)
        if node is None:
            raise NotFound("edge node not found")
        if node.status != "ACTIVE":
            raise Forbidden(f"edge node is {node.status}")
        issued = self.now()
        payload = {
            "edge_node_id": str(node.edge_node_id),
            "merchant_id": str(node.merchant_id),
            "rules_version": node.rules_version,
            "issued_at": _iso(issued),
            "expires_at": _iso(issued + RULES_TTL),
            "offline_limits": {"per_transaction": node.limits.per_transaction, "per_day": node.limits.per_day,
                               "max_age_minutes": node.limits.max_age_minutes},
            "terminals": sorted(self.repo.active_terminals(node.merchant_id)),
            "routing_rules": {method: list(hosts) for method, hosts in sorted(self.routing_rules.items())},
            # Filled by Step 22 (fraud screening) and Step 23 (token vault index); signed from day one.
            "fraud_thresholds": {"blocklist": [], "blocklist_key": None, "max_txns_per_hour": None,
                                 "high_risk_amount": None},
            "token_index": {"entries": [], "revocations": []},
        }
        signature = signer.sign(canonical_item(payload))
        return {**payload, "signature": base64.b64encode(signature).decode()}


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")
