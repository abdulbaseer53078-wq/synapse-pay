import base64
import binascii
from datetime import datetime
from typing import Generic, Literal, TypeVar
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from app.api.auth import merchant_with_scope, registry_caller, with_scope
from app.application.authorization import AuthorizationService
from app.application.queries import (CertificateView, HeartbeatView, StatusEvent, TerminalQueryService,
                                     TerminalView)
from app.application.registration import (Forbidden, Heartbeat, InvalidInput, RegistrationService,
                                          Unauthenticated)
from app.domain.terminal import TRANSITIONS, Actor, HealthState, TerminalStatus

router = APIRouter(prefix="/api/v1/terminals", tags=["terminals"])

# '|' separates the fingerprint parts, so it can't appear inside one.
_PART = Field(min_length=1, max_length=128, pattern=r"^[^|]+$")


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateTerminalBody(_Body):
    merchant_id: UUID
    device_serial: str = Field(min_length=1, max_length=64)
    device_model: str = Field(min_length=1, max_length=64)
    metadata: dict[str, str] = {}


class CreateTerminalResponse(BaseModel):
    terminal_id: UUID
    status: str
    registration_token: str
    registration_token_expires_at: datetime


class RegisterBody(_Body):
    registration_token: str = Field(min_length=1, max_length=128)
    csr_pem: str = Field(min_length=1, max_length=8192)
    secure_element_id: str = _PART
    firmware_version: str = _PART
    hardware_id: str = _PART
    device_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class RegisterResponse(BaseModel):
    terminal_id: UUID
    status: str
    certificate_pem: str
    certificate_serial: str
    certificate_expires_at: datetime
    ca_certificate_pem: str
    activation_challenge: str  # base64; sign the decoded bytes with SHA-256
    activation_challenge_expires_at: datetime


class ActivateBody(_Body):
    signed_challenge: str = Field(min_length=1, max_length=1024)  # base64


class ActivateResponse(BaseModel):
    terminal_id: UUID
    status: str
    activated_at: datetime


def _service(request: Request) -> RegistrationService:
    return request.app.state.registration


def _authorization_service(request: Request) -> AuthorizationService:
    return request.app.state.authorization


def _queries(request: Request) -> TerminalQueryService:
    return request.app.state.queries


@router.post("", status_code=201, response_model=CreateTerminalResponse)
def create_terminal(body: CreateTerminalBody, service: RegistrationService = Depends(_service),
                    caller: UUID = Depends(merchant_with_scope("registry:write"))):
    if body.merchant_id != caller:
        raise Forbidden("merchant_id does not match the authenticated merchant")
    created = service.create_terminal(body.merchant_id, body.device_serial, body.device_model, body.metadata)
    return CreateTerminalResponse(terminal_id=created.terminal_id, status="PENDING",
                                  registration_token=created.registration_token,
                                  registration_token_expires_at=created.registration_token_expires_at)


# No OAuth on the terminal endpoints: the registration token, then the key signature, are the credentials.
@router.post("/{terminal_id}/register", response_model=RegisterResponse)
def register(terminal_id: UUID, body: RegisterBody, service: RegistrationService = Depends(_service)):
    r = service.register(terminal_id, body.registration_token, body.csr_pem, body.secure_element_id,
                         body.firmware_version, body.hardware_id, body.device_fingerprint)
    return RegisterResponse(
        terminal_id=terminal_id, status="PENDING_ACTIVATION",
        certificate_pem=r.certificate.certificate_pem, certificate_serial=r.certificate.serial_number,
        certificate_expires_at=r.certificate.expires_at, ca_certificate_pem=r.ca_certificate_pem,
        activation_challenge=base64.b64encode(r.activation_challenge).decode(),
        activation_challenge_expires_at=r.challenge_expires_at)


@router.post("/{terminal_id}/activate", response_model=ActivateResponse)
def activate(terminal_id: UUID, body: ActivateBody, service: RegistrationService = Depends(_service)):
    try:
        signature = base64.b64decode(body.signed_challenge, validate=True)
    except binascii.Error:
        raise InvalidInput("signed_challenge is not valid base64")
    activated_at = service.activate(terminal_id, signature)
    return ActivateResponse(terminal_id=terminal_id, status="ACTIVE", activated_at=activated_at)


class StatusChangeBody(_Body):
    reason: str | None = Field(None, max_length=256)


class StatusChangeResponse(BaseModel):
    terminal_id: UUID
    status: str
    status_changed_at: datetime


def _status_change_route(action: str):
    def handler(terminal_id: UUID, body: StatusChangeBody | None = None,
                service: RegistrationService = Depends(_service),
                caller: tuple[Actor, str] = Depends(registry_caller("registry:write"))) -> StatusChangeResponse:
        status, changed_at = service.change_status(terminal_id, action, *caller, body.reason if body else None)
        return StatusChangeResponse(terminal_id=terminal_id, status=status, status_changed_at=changed_at)
    return handler


for _action in TRANSITIONS:
    router.add_api_route(f"/{{terminal_id}}/{_action}", _status_change_route(_action), methods=["POST"],
                         response_model=StatusChangeResponse, name=f"{_action}_terminal")


class HeartbeatBody(_Body):
    sent_at: AwareDatetime
    connectivity_type: Literal["ETHERNET", "CELLULAR", "MESH"]
    latency_ms: int = Field(ge=0)
    firmware_version: str = Field(min_length=1, max_length=64)
    battery_level: int | None = Field(None, ge=0, le=100)


class HeartbeatResponse(BaseModel):
    terminal_id: UUID
    status: str
    health_state: str


class Certification(BaseModel):
    profile_id: UUID
    certified_for: list[str]
    expires_at: datetime


class Limits(BaseModel):
    per_transaction: int
    per_day: int


class AuthorizationResponse(BaseModel):
    terminal_id: UUID
    authorized: bool
    status: str
    reason: str | None
    # Set only when authorized:
    health_state: str | None = None
    certification: Certification | None = None
    limits: Limits | None = None
    # Set only when not authorized:
    status_changed_at: datetime | None = None


# The routing engine's service token; unscoped to a merchant, so merchant tokens never carry it.
@router.get("/{terminal_id}/authorization", response_model=AuthorizationResponse,
            response_model_exclude_unset=True, dependencies=[Depends(with_scope("registry:authorize"))])
def authorization(terminal_id: UUID, payment_method: Literal["CARD", "UPI", "WALLET", "QR", "OFFLINE"],
                  amount: int = Query(gt=0), service: AuthorizationService = Depends(_authorization_service)):
    a = service.authorize(terminal_id, payment_method, amount)
    if a.reason:
        return AuthorizationResponse(terminal_id=terminal_id, authorized=False, reason=a.reason, status=a.status,
                                     status_changed_at=a.status_changed_at)
    p = a.profile
    return AuthorizationResponse(
        terminal_id=terminal_id, authorized=True, status=a.status, health_state=a.health, reason=None,
        certification=Certification(profile_id=p.profile_id, certified_for=sorted(p.certified_for),
                                    expires_at=p.expires_at),
        limits=Limits(per_transaction=p.per_transaction_limit, per_day=p.per_day_limit))


@router.post("/{terminal_id}/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(terminal_id: UUID, request: Request, x_signature: str | None = Header(None),
                    service: RegistrationService = Depends(_service)):
    # The signature covers the exact bytes sent, so read the raw body rather than a re-serialised model.
    raw = await request.body()
    if not x_signature:
        raise Unauthenticated("missing X-Signature header")
    try:
        signature = base64.b64decode(x_signature, validate=True)
    except binascii.Error:
        raise Unauthenticated("X-Signature is not valid base64")
    try:
        body = HeartbeatBody.model_validate_json(raw)
    except ValidationError as exc:
        raise InvalidInput("; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()))
    status, health = await run_in_threadpool(
        service.ingest_heartbeat, terminal_id, raw, signature, Heartbeat(**body.model_dump()))
    return HeartbeatResponse(terminal_id=terminal_id, status=status, health_state=health)


# Query and management API. Reads take registry:read or registry:write; admins (registry:admin) may act on any
# merchant's terminals, and each such access is audited.
T = TypeVar("T")
_reader = registry_caller("registry:read", "registry:write")


class ListOf(BaseModel, Generic[T]):
    data: list[T]


class TerminalPage(ListOf[TerminalView]):
    next_cursor: UUID | None  # pass as ?cursor= for the next page; null on the last page


@router.get("", response_model=TerminalPage)
def list_terminals(merchant_id: UUID | None = Query(None, description="Required for admins; merchants get their own"),
                   status: TerminalStatus | None = None, health_state: HealthState | None = None,
                   cursor: UUID | None = None, limit: int = Query(50, ge=1, le=100),
                   service: TerminalQueryService = Depends(_queries),
                   caller: tuple[Actor, str] = Depends(_reader)):
    data, next_cursor = service.list_terminals(*caller, merchant_id, status, health_state, cursor, limit)
    return TerminalPage(data=data, next_cursor=next_cursor)


@router.get("/{terminal_id}", response_model=TerminalView)
def get_terminal(terminal_id: UUID, service: TerminalQueryService = Depends(_queries),
                 caller: tuple[Actor, str] = Depends(_reader)):
    return service.get(terminal_id, *caller)


class UpdateTerminalBody(_Body):
    # Only metadata: device_model selects the hardware pattern and certified firmware, so it isn't editable.
    metadata: dict[str, str]


@router.patch("/{terminal_id}", response_model=TerminalView)
def update_terminal(terminal_id: UUID, body: UpdateTerminalBody, service: TerminalQueryService = Depends(_queries),
                    caller: tuple[Actor, str] = Depends(registry_caller("registry:write"))):
    return service.update_metadata(terminal_id, *caller, body.metadata)


@router.get("/{terminal_id}/certificates", response_model=ListOf[CertificateView])
def list_certificates(terminal_id: UUID, service: TerminalQueryService = Depends(_queries),
                      caller: tuple[Actor, str] = Depends(_reader)):
    return ListOf[CertificateView](data=service.certificates(terminal_id, *caller))


@router.get("/{terminal_id}/heartbeats", response_model=ListOf[HeartbeatView])
def list_heartbeats(terminal_id: UUID, limit: int = Query(100, ge=1, le=1000),
                    service: TerminalQueryService = Depends(_queries),
                    caller: tuple[Actor, str] = Depends(_reader)):
    return ListOf[HeartbeatView](data=service.heartbeats(terminal_id, *caller, limit))


@router.get("/{terminal_id}/events", response_model=ListOf[StatusEvent])
def list_events(terminal_id: UUID, service: TerminalQueryService = Depends(_queries),
                caller: tuple[Actor, str] = Depends(_reader)):
    return ListOf[StatusEvent](data=service.status_events(terminal_id, *caller))
