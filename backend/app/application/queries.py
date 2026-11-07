"""Merchant and admin reads of the registry, plus metadata edits.

Merchants see only their own terminals (others' are 404, as on the lifecycle endpoints). An admin may act on any
terminal; every such access is written to the audit log.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.application.registration import Forbidden, InvalidInput, NotFound
from app.domain.terminal import Actor


@dataclass(frozen=True)
class TerminalView:
    terminal_id: UUID
    merchant_id: UUID
    device_serial: str
    device_model: str
    firmware_version: str | None
    status: str
    health_state: str
    last_heartbeat_at: datetime | None
    certification_profile_id: UUID | None
    registered_at: datetime
    activated_at: datetime | None
    status_changed_at: datetime
    metadata: dict[str, str]


@dataclass(frozen=True)
class CertificateView:
    serial_number: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
    current: bool


@dataclass(frozen=True)
class HeartbeatView:
    sent_at: datetime
    received_at: datetime
    connectivity_type: str
    latency_ms: int
    firmware_version: str
    battery_level: int | None


@dataclass(frozen=True)
class StatusEvent:
    occurred_at: datetime
    action: str
    from_status: str | None
    to_status: str
    actor_type: str
    reason: str | None


class TerminalQueryRepository(Protocol):
    def terminal(self, terminal_id: UUID, merchant_id: UUID | None) -> TerminalView | None:
        """merchant_id None means any merchant (admin)."""
    def list_terminals(self, merchant_id: UUID, status: str | None, health: str | None, after: UUID | None,
                       limit: int) -> list[TerminalView]:
        """Ordered by terminal_id, starting after `after`."""
    def update_metadata(self, terminal_id: UUID, merchant_id: UUID | None, metadata: dict) -> TerminalView | None: ...
    def certificates(self, terminal_id: UUID) -> list[CertificateView]: ...
    def heartbeats(self, terminal_id: UUID, limit: int) -> list[HeartbeatView]: ...
    def status_events(self, terminal_id: UUID) -> list[StatusEvent]: ...
    def audit_access(self, admin_id: str, entity_type: str, entity_id: UUID, action: str) -> None: ...


class TerminalQueryService:
    def __init__(self, repo: TerminalQueryRepository):
        self.repo = repo

    def list_terminals(self, actor: Actor, actor_id: str, merchant_id: UUID | None, status: str | None,
                       health: str | None, cursor: UUID | None, limit: int) -> tuple[list[TerminalView], UUID | None]:
        """A page of terminals and the cursor for the next one (None on the last page)."""
        if actor == Actor.ADMIN:
            if merchant_id is None:
                raise InvalidInput("merchant_id is required when listing as an admin")
            self.repo.audit_access(actor_id, "merchant", merchant_id, "list_terminals")
        elif merchant_id not in (None, UUID(actor_id)):
            raise Forbidden("merchant_id does not match the authenticated merchant")
        rows = self.repo.list_terminals(merchant_id or UUID(actor_id), status, health, cursor, limit + 1)
        return rows[:limit], rows[limit - 1].terminal_id if len(rows) > limit else None

    def get(self, terminal_id: UUID, actor: Actor, actor_id: str) -> TerminalView:
        return self._visible(terminal_id, actor, actor_id, "read")

    def update_metadata(self, terminal_id: UUID, actor: Actor, actor_id: str, metadata: dict) -> TerminalView:
        view = self.repo.update_metadata(terminal_id, self._scope(terminal_id, actor, actor_id, "update_metadata"),
                                         metadata)
        if view is None:
            raise NotFound("terminal not found")
        return view

    def certificates(self, terminal_id: UUID, actor: Actor, actor_id: str) -> list[CertificateView]:
        self._visible(terminal_id, actor, actor_id, "read_certificates")
        return self.repo.certificates(terminal_id)

    def heartbeats(self, terminal_id: UUID, actor: Actor, actor_id: str, limit: int) -> list[HeartbeatView]:
        self._visible(terminal_id, actor, actor_id, "read_heartbeats")
        return self.repo.heartbeats(terminal_id, limit)

    def status_events(self, terminal_id: UUID, actor: Actor, actor_id: str) -> list[StatusEvent]:
        self._visible(terminal_id, actor, actor_id, "read_events")
        return self.repo.status_events(terminal_id)

    def _scope(self, terminal_id: UUID, actor: Actor, actor_id: str, action: str) -> UUID | None:
        """The merchant to filter by: the caller's own, or None for an admin, whose access is audited."""
        if actor == Actor.ADMIN:
            self.repo.audit_access(actor_id, "terminal", terminal_id, action)
            return None
        return UUID(actor_id)

    def _visible(self, terminal_id: UUID, actor: Actor, actor_id: str, action: str) -> TerminalView:
        view = self.repo.terminal(terminal_id, self._scope(terminal_id, actor, actor_id, action))
        if view is None:
            raise NotFound("terminal not found")
        return view
