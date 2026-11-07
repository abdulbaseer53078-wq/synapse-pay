"""Transaction-time authorization: may this terminal run this payment method for this amount, right now?

Called by the routing engine before every transaction. Reads straight from the registry (one indexed row),
so a status, firmware or certification change applies to the very next call.
"""
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from app.application.registration import CertificationRegistry, Forbidden, NotFound
from app.domain.terminal import (CertificationProfile, HealthState, TerminalStatus, authorization_denial,
                                 health_at)


@dataclass(frozen=True)
class AuthorizationContext:
    status: TerminalStatus
    status_changed_at: datetime
    last_heartbeat_at: datetime | None
    device_model: str
    firmware_version: str | None
    profile: CertificationProfile | None


@dataclass(frozen=True)
class Authorization:
    status: TerminalStatus
    status_changed_at: datetime
    health: HealthState
    profile: CertificationProfile | None
    reason: str | None  # None means authorized


class AuthorizationRepository(Protocol):
    def authorization_context(self, terminal_id: UUID) -> AuthorizationContext | None: ...


class AuthorizationService:
    def __init__(self, repo: AuthorizationRepository, certification: CertificationRegistry):
        self.repo = repo
        self.certification = certification

    def authorize(self, terminal_id: UUID, method: str, amount: int) -> Authorization:
        ctx = self.repo.authorization_context(terminal_id)
        if ctx is None:
            raise NotFound("terminal not found")
        now = datetime.now(UTC)
        health = health_at(ctx.last_heartbeat_at, now)
        # Re-checked here too: a firmware version can be de-certified after the terminal installed it.
        firmware_ok = ctx.firmware_version is not None \
            and self.certification.is_certified(ctx.device_model, ctx.firmware_version)
        reason = authorization_denial(ctx.status, health, firmware_ok, ctx.profile, method, amount, now)
        return Authorization(ctx.status, ctx.status_changed_at, health, ctx.profile, reason)

    def admit(self, terminal_id: UUID) -> None:
        """Gateway check for an mTLS request from this terminal: only ACTIVE terminals reach business logic."""
        ctx = self.repo.authorization_context(terminal_id)
        if ctx is None:
            raise Forbidden("certificate's terminal is not registered")
        if ctx.status != TerminalStatus.ACTIVE:
            raise Forbidden(f"terminal is {ctx.status}; only ACTIVE terminals may connect")
