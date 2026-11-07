"""Read-only audit API (Step 7.6).

    GET /api/v1/audit/events?correlation_id=<uuid>

That is the support call: one payment, the whole timeline, oldest first. Filters and a keyset cursor exist for
the bulk case (reconciliation, dispute export). Nothing here writes: the log is append-only by construction.
"""
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app.api.auth import with_any_scope
from app.application.audit import AuditQueryService

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

EventType = Literal[
    "TRANSACTION_INITIATED", "TRANSACTION_SUBMITTED", "TRANSACTION_PENDING", "TRANSACTION_AUTHORIZED",
    "TRANSACTION_CAPTURED", "TRANSACTION_SETTLED", "TRANSACTION_FAILED", "TRANSACTION_VOIDED",
    "TRANSACTION_REFUNDED", "TERMINAL_CREATED", "TERMINAL_REGISTERED", "TERMINAL_ACTIVATED",
    "TERMINAL_REJECTED", "TERMINAL_SUSPENDED", "TERMINAL_REINSTATED", "TERMINAL_REVOKED",
    "TERMINAL_DECOMMISSIONED", "TERMINAL_FIRMWARE_CHANGED", "TERMINAL_HEALTH_CHANGED", "ADMIN_ACCESS",
]


class AuditEventView(BaseModel):
    sequence: int
    event_id: UUID
    timestamp: datetime
    event_type: str
    actor: str
    entity_id: str
    correlation_id: str
    payload: dict
    prev_hash: str
    hash: str


class AuditPage(BaseModel):
    data: list[AuditEventView]
    next_cursor: int | None  # pass as ?cursor= for the next page; null on the last page


def _service(request: Request) -> AuditQueryService:
    return request.app.state.audit


# audit:read is the support/ops scope. A registry admin already sees the registry's own trail, so it is accepted
# too rather than requiring a second token for the same read.
_reader = with_any_scope("audit:read", "registry:admin")


@router.get("/events", response_model=AuditPage)
def list_events(correlation_id: str | None = Query(None, max_length=64),
                entity_id: str | None = Query(None, max_length=64),
                event_type: EventType | None = None,
                start: datetime | None = Query(None, alias="from"),
                end: datetime | None = Query(None, alias="to"),
                cursor: int | None = Query(None, ge=0),
                limit: int = Query(100, ge=1, le=200),
                service: AuditQueryService = Depends(_service),
                _: dict = Depends(_reader)):
    data, next_cursor = service.search(correlation_id=correlation_id, entity_id=entity_id, event_type=event_type,
                                       start=start, end=end, after_sequence=cursor, limit=limit)
    return AuditPage(data=data, next_cursor=next_cursor)


@router.get("/chain")
def chain_head(service: AuditQueryService = Depends(_service), _: dict = Depends(_reader)):
    """The current chain position. Ops use it to confirm ingestion kept up."""
    return service.head()
