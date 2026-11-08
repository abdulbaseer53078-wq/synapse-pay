import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

HEARTBEAT_WINDOW = timedelta(seconds=60)  # max |server time - sent_at|
HEALTHY_WITHIN = timedelta(seconds=90)
DEGRADED_WITHIN = timedelta(minutes=5)  # beyond this: UNREACHABLE


class TerminalStatus(StrEnum):
    PENDING = "PENDING"
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    DECOMMISSIONED = "DECOMMISSIONED"
    REJECTED = "REJECTED"


class HealthState(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNREACHABLE = "UNREACHABLE"


class Actor(StrEnum):
    TERMINAL = "TERMINAL"
    MERCHANT = "MERCHANT"
    ADMIN = "ADMIN"
    SYSTEM = "SYSTEM"


@dataclass(frozen=True)
class Transition:
    to: TerminalStatus
    sources: frozenset[TerminalStatus]
    actors: frozenset[Actor]
    revokes_certificate: bool


S, A = TerminalStatus, Actor
# Lifecycle changes triggered after activation. Registration (PENDING → PENDING_ACTIVATION → ACTIVE,
# PENDING → REJECTED) is driven by the handshake itself. Revocation is allowed from every state that
# holds a valid certificate, not only ACTIVE.
TRANSITIONS = {
    "suspend": Transition(S.SUSPENDED, frozenset({S.ACTIVE}), frozenset({A.MERCHANT, A.ADMIN}), False),
    "reinstate": Transition(S.ACTIVE, frozenset({S.SUSPENDED}), frozenset({A.ADMIN}), False),
    "revoke": Transition(S.REVOKED, frozenset({S.ACTIVE, S.SUSPENDED, S.PENDING_ACTIVATION}),
                         frozenset({A.MERCHANT, A.ADMIN}), True),
    "decommission": Transition(S.DECOMMISSIONED, frozenset({S.ACTIVE, S.SUSPENDED}), frozenset({A.MERCHANT}), True),
}


@dataclass(frozen=True)
class CertificationProfile:
    profile_id: UUID
    certified_for: frozenset[str]
    expires_at: datetime
    per_transaction_limit: int  # minor units
    per_day_limit: int


def health_at(last_heartbeat_at: datetime | None, now: datetime) -> HealthState:
    """Same thresholds as the refresh-health job, computed live so authorization never trails it."""
    if last_heartbeat_at is None or now - last_heartbeat_at >= DEGRADED_WITHIN:
        return HealthState.UNREACHABLE
    return HealthState.HEALTHY if now - last_heartbeat_at < HEALTHY_WITHIN else HealthState.DEGRADED


def authorization_denial(status: TerminalStatus, health: HealthState, firmware_denial: str | None,
                         profile: CertificationProfile | None, method: str, amount: int, now: datetime) -> str | None:
    """Why a transaction may not run on this terminal, or None if it may. DEGRADED still authorizes."""
    if status != TerminalStatus.ACTIVE:
        return "TERMINAL_NOT_ACTIVE"
    if health == HealthState.UNREACHABLE:
        return "TERMINAL_UNREACHABLE"
    if firmware_denial:  # FIRMWARE_UNCERTIFIED or CERTIFICATION_EXPIRED, from the certification matrix
        return firmware_denial
    if profile is None:
        return "METHOD_NOT_CERTIFIED"
    if profile.expires_at <= now:
        return "CERTIFICATION_EXPIRED"
    if method not in profile.certified_for:
        return "METHOD_NOT_CERTIFIED"
    # shortcut: per-day limit isn't enforced; it needs the transaction engine's daily totals.
    if amount > profile.per_transaction_limit:
        return "LIMIT_EXCEEDED"
    return None


TERMINAL_URI_PREFIX = "urn:synapsepay:terminal:"


def terminal_uri(terminal_id: UUID) -> str:
    """The URI SAN a terminal's certificate carries; the gateway reads the terminal_id from it."""
    return f"{TERMINAL_URI_PREFIX}{terminal_id}"


def device_fingerprint(secure_element_id: str, firmware_version: str, hardware_id: str) -> str:
    """Lowercase hex SHA-256 of the parts joined with '|'. Terminals compute the same value."""
    return hashlib.sha256(f"{secure_element_id}|{firmware_version}|{hardware_id}".encode()).hexdigest()
