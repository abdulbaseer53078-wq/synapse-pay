"""Terminal lifecycle: two-phase registration (merchant creates → terminal submits CSR → terminal proves
key possession), status changes (suspend, reinstate, revoke, decommission), and signed heartbeats."""
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from app.domain.terminal import (HEARTBEAT_WINDOW, TRANSITIONS, Actor, HealthState, TerminalStatus,
                                 device_fingerprint)

UNCERTIFIED_FIRMWARE = "UNCERTIFIED_FIRMWARE"

TOKEN_TTL = timedelta(minutes=15)
CHALLENGE_TTL = timedelta(minutes=15)


# Errors carry the spec's error_code; the API layer maps each kind to an HTTP status.
class RegistrationError(Exception):
    code = "INVALID_REQUEST"

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.code = code or self.code


class InvalidInput(RegistrationError): ...
class UnknownReference(RegistrationError): ...
class NotFound(RegistrationError):
    code = "TERMINAL_NOT_FOUND"
class Conflict(RegistrationError): ...
class Unauthenticated(RegistrationError):
    code = "UNAUTHENTICATED"
class Forbidden(RegistrationError):
    code = "FORBIDDEN"
class CertificateAuthorityUnavailable(RegistrationError):
    code = "INTERNAL_ERROR"


@dataclass(frozen=True)
class TerminalSnapshot:
    merchant_id: UUID
    status: TerminalStatus
    certificate_serial: str | None


@dataclass(frozen=True)
class Heartbeat:
    sent_at: datetime
    connectivity_type: str
    latency_ms: int
    firmware_version: str
    battery_level: int | None


@dataclass(frozen=True)
class HeartbeatContext:
    status: TerminalStatus
    device_model: str
    firmware_version: str | None
    public_key_pem: str | None


@dataclass(frozen=True)
class IssuedCertificate:
    serial_number: str
    certificate_pem: str
    public_key_pem: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class ActivationState:
    status: TerminalStatus
    public_key_pem: str | None
    challenge: bytes | None
    challenge_valid: bool


class TerminalRepository(Protocol):
    def create_terminal(self, merchant_id: UUID, device_serial: str, device_model: str, metadata: dict,
                        token_hash: bytes, token_ttl: timedelta) -> tuple[UUID, datetime]:
        """Raises Conflict for a taken device_serial, UnknownReference for an unknown merchant."""
    def pending_model(self, terminal_id: UUID, token_hash: bytes) -> str | None:
        """The device_model if the token is valid and unused and the terminal is PENDING, else None."""
    def complete_registration(self, terminal_id: UUID, token_hash: bytes, cert: IssuedCertificate,
                              secure_element_id: str, firmware_version: str,
                              challenge: bytes, challenge_ttl: timedelta) -> datetime | None:
        """Atomically consumes the token and stores everything; challenge expiry, or None if the token was taken."""
    def activation_state(self, terminal_id: UUID) -> ActivationState | None: ...
    def activate(self, terminal_id: UUID) -> datetime | None:
        """PENDING_ACTIVATION → ACTIVE; activated_at, or None if the terminal was no longer awaiting activation."""
    def reject(self, terminal_id: UUID, token_hash: bytes, reason: str) -> None:
        """PENDING → REJECTED (by SYSTEM), consuming the token, if the token is still valid."""
    def transition(self, terminal_id: UUID, to: TerminalStatus, check: Callable[[TerminalSnapshot], None],
                   actor: Actor, actor_id: str, action: str, reason: str | None,
                   revoke_certificate: bool) -> datetime:
        """Locks the terminal, calls check (which may raise to abort), then applies the change and audits it,
        all in one transaction. Raises NotFound for an unknown terminal. Returns status_changed_at."""
    def heartbeat_context(self, terminal_id: UUID) -> HeartbeatContext | None: ...
    def record_heartbeat(self, terminal_id: UUID, hb: Heartbeat, update_terminal: bool,
                         suspend_reason: str | None) -> tuple[TerminalStatus, HealthState]:
        """In one transaction: raises Unauthenticated if hb.sent_at isn't later than the previous heartbeat's;
        stores it; if update_terminal, sets last_heartbeat_at, firmware_version and HEALTHY; if suspend_reason,
        ACTIVE → SUSPENDED by SYSTEM, audited. Returns the terminal's resulting status and health."""
    def refresh_health(self) -> int:
        """Recomputes health_state from last_heartbeat_at for every terminal; returns how many changed."""


class CertificationRegistry(Protocol):
    def is_certified(self, device_model: str, firmware_version: str) -> bool: ...


class CertificateAuthority(Protocol):
    ca_certificate_pem: str

    def issue(self, csr_pem: str, terminal_id: UUID, uri: str | None = None) -> IssuedCertificate:
        """Raises InvalidInput for an unparsable CSR, a bad CSR signature or an unsupported key. `uri` is the
        URI SAN (default: the terminal's); edge nodes (Step 20) get theirs, with their id as `terminal_id`."""
    def verify_signature(self, public_key_pem: str, message: bytes, signature: bytes) -> bool: ...
    def revoke(self, serial_number: str) -> None:
        """Idempotent. Raises CertificateAuthorityUnavailable if the revocation was not published."""


@dataclass(frozen=True)
class CreatedTerminal:
    terminal_id: UUID
    registration_token: str
    registration_token_expires_at: datetime


@dataclass(frozen=True)
class RegisteredTerminal:
    certificate: IssuedCertificate
    ca_certificate_pem: str
    activation_challenge: bytes
    challenge_expires_at: datetime


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


class RegistrationService:
    def __init__(self, repo: TerminalRepository, ca: CertificateAuthority, approved_models: dict[str, re.Pattern],
                 certification: CertificationRegistry):
        self.repo = repo
        self.ca = ca
        self.approved_models = approved_models  # device_model → pattern its hardware_id must match
        self.certification = certification

    def create_terminal(self, merchant_id: UUID, device_serial: str, device_model: str, metadata: dict) -> CreatedTerminal:
        if device_model not in self.approved_models:
            raise UnknownReference(f"device_model '{device_model}' is not an approved model")
        token = secrets.token_urlsafe(32)
        terminal_id, expires_at = self.repo.create_terminal(
            merchant_id, device_serial, device_model, metadata, _hash(token), TOKEN_TTL)
        return CreatedTerminal(terminal_id, token, expires_at)

    def register(self, terminal_id: UUID, registration_token: str, csr_pem: str, secure_element_id: str,
                 firmware_version: str, hardware_id: str, fingerprint: str) -> RegisteredTerminal:
        token_hash = _hash(registration_token)
        model = self.repo.pending_model(terminal_id, token_hash)
        if model is None:
            raise Unauthenticated("registration_token is invalid, expired or already used")

        expected = device_fingerprint(secure_element_id, firmware_version, hardware_id)
        pattern = self.approved_models.get(model)
        if not hmac.compare_digest(expected, fingerprint) or pattern is None or not pattern.fullmatch(hardware_id):
            # A wrong device is a security signal, unlike a malformed CSR: reject the terminal for good.
            self.repo.reject(terminal_id, token_hash, "device_fingerprint does not match the registered model")
            raise Forbidden("device_fingerprint does not match the registered device model")

        cert = self.ca.issue(csr_pem, terminal_id)
        challenge = secrets.token_bytes(32)
        challenge_expires_at = self.repo.complete_registration(
            terminal_id, token_hash, cert, secure_element_id, firmware_version, challenge, CHALLENGE_TTL)
        if challenge_expires_at is None:  # a concurrent request consumed the token first
            raise Unauthenticated("registration_token is invalid, expired or already used")
        return RegisteredTerminal(cert, self.ca.ca_certificate_pem, challenge, challenge_expires_at)

    def activate(self, terminal_id: UUID, signed_challenge: bytes) -> datetime:
        state = self.repo.activation_state(terminal_id)
        if state is None:
            raise NotFound("terminal not found")
        if state.status != TerminalStatus.PENDING_ACTIVATION:
            raise Conflict(f"terminal is {state.status}, not awaiting activation")
        if not state.challenge_valid:
            raise Unauthenticated("activation challenge has expired")
        if not self.ca.verify_signature(state.public_key_pem, state.challenge, signed_challenge):
            raise Unauthenticated("signed_challenge does not verify against the terminal's certificate")
        activated_at = self.repo.activate(terminal_id)
        if activated_at is None:
            raise Conflict("terminal is no longer awaiting activation")
        return activated_at

    def change_status(self, terminal_id: UUID, action: str, actor: Actor, actor_id: str,
                      reason: str | None) -> tuple[TerminalStatus, datetime]:
        """actor_id is the merchant_id for a MERCHANT actor; merchants may only act on their own terminals."""
        t = TRANSITIONS[action]
        if actor not in t.actors:
            raise Forbidden(f"{actor} may not {action} a terminal")

        def check(current: TerminalSnapshot) -> None:
            if actor == Actor.MERCHANT and str(current.merchant_id) != actor_id:
                raise NotFound("terminal not found")  # don't reveal other merchants' terminals
            if current.status not in t.sources:
                raise Conflict(f"cannot {action} a {current.status} terminal")
            # Revoke at the CA first, inside the DB transaction: if it fails, the status change rolls back.
            if t.revokes_certificate and current.certificate_serial:
                self.ca.revoke(current.certificate_serial)

        changed_at = self.repo.transition(terminal_id, t.to, check, actor, actor_id, action, reason,
                                          t.revokes_certificate)
        return t.to, changed_at

    def ingest_heartbeat(self, terminal_id: UUID, signed_body: bytes, signature: bytes,
                         hb: Heartbeat) -> tuple[TerminalStatus, HealthState]:
        """signed_body is the raw request body the terminal signed; hb is its parsed content."""
        if abs(datetime.now(UTC) - hb.sent_at) > HEARTBEAT_WINDOW:
            raise Unauthenticated("sent_at is outside the 60-second window of server time")
        ctx = self.repo.heartbeat_context(terminal_id)
        # Unknown terminals get the same answer as bad signatures, so the endpoint doesn't reveal which exist.
        if ctx is None or ctx.public_key_pem is None \
                or not self.ca.verify_signature(ctx.public_key_pem, signed_body, signature):
            raise Unauthenticated("heartbeat signature does not verify against the terminal's certificate")
        if ctx.status not in (TerminalStatus.ACTIVE, TerminalStatus.SUSPENDED, TerminalStatus.REVOKED):
            raise Conflict(f"a {ctx.status} terminal cannot send heartbeats")

        live = ctx.status != TerminalStatus.REVOKED  # a revoked terminal's heartbeat is logged, nothing more
        uncertified = (live and hb.firmware_version != ctx.firmware_version
                       and not self.certification.is_certified(ctx.device_model, hb.firmware_version))
        return self.repo.record_heartbeat(terminal_id, hb, update_terminal=live,
                                          suspend_reason=UNCERTIFIED_FIRMWARE if uncertified else None)
