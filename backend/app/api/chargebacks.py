"""Chargebacks (PR 8, spec 1.15.0): the acquirer's signed notices, and the merchant's view and defence.

Notices are signed by the acquirer (X-Timestamp, X-Signature over "<timestamp>.<raw body>", the same scheme as the
PSP webhooks) and answered 200 once trusted, even for a duplicate or an unknown payment: a 4xx would make the acquirer
retry for days over something retrying can't fix.
"""
import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.api.auth import merchant_from_api_key
from app.application.chargebacks import ChargebackService
from app.application.methods import WebhookRejected
from app.application.registration import NotFound
from app.infrastructure.postgres_chargebacks import view

router = APIRouter(tags=["chargebacks"])


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OpenedNotice(_Body):
    event_id: str = Field(min_length=1, max_length=128)
    acquirer_id: str = Field(min_length=1, max_length=64)
    case_id: str = Field(min_length=1, max_length=64)
    network_reference: str = Field(min_length=1, max_length=64, description="The payment's RRN")
    amount: int = Field(gt=0)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    reason_code: str = Field(min_length=1, max_length=10)
    evidence_deadline: datetime


class ResolutionNotice(_Body):
    event_id: str = Field(min_length=1, max_length=128)
    acquirer_id: str = Field(min_length=1, max_length=64)
    case_id: str = Field(min_length=1, max_length=64)
    outcome: Literal["WON", "LOST"]


class Evidence(_Body):
    """Structured text only; documents are a follow-up (they need storage and retention rules)."""
    explanation: str = Field(min_length=1, max_length=2000)
    receipt_number: str | None = Field(default=None, max_length=64)
    tracking_number: str | None = Field(default=None, max_length=64)
    carrier: str | None = Field(default=None, max_length=64)
    delivery_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    customer_communication: str | None = Field(default=None, max_length=2000)


def _service(request: Request) -> ChargebackService:
    return request.app.state.chargebacks


async def _notice(request: Request, model, apply) -> JSONResponse:
    raw = await request.body()  # the signature covers exactly these bytes
    service = _service(request)
    try:
        service.verify(raw, {k.lower(): v for k, v in request.headers.items()})
        notice = model.model_validate(json.loads(raw or b"{}"))
    except WebhookRejected as rejected:
        return JSONResponse(status_code=rejected.status,
                            content={"error_code": rejected.code, "error_message": rejected.message})
    except (ValueError, ValidationError):  # field paths only: never echo the values
        return JSONResponse(status_code=400, content={"error_code": "INVALID_PAYLOAD",
                                                      "error_message": "not a valid chargeback notice"})
    try:
        chargeback = await run_in_threadpool(apply, service, notice)
    except NotFound as missing:
        return JSONResponse(status_code=200, content={"received": True, "applied": False, "reason": missing.message})
    return JSONResponse(status_code=200, content={"received": True, "chargeback_id": f"cb_{chargeback.chargeback_id.hex}",
                                                  "status": chargeback.status})


@router.post("/api/v1/webhooks/chargebacks")
async def chargeback_opened(request: Request) -> JSONResponse:
    return await _notice(request, OpenedNotice, lambda service, n: service.opened(
        n.event_id, n.acquirer_id, n.case_id, n.network_reference, n.amount, n.currency, n.reason_code,
        n.evidence_deadline)[0])


@router.post("/api/v1/webhooks/chargebacks/resolution")
async def chargeback_resolved(request: Request) -> JSONResponse:
    return await _notice(request, ResolutionNotice, lambda service, n: service.resolved(
        n.event_id, n.acquirer_id, n.case_id, n.outcome))


def _chargeback_id(value: str) -> UUID:
    if not value.startswith("cb_") or len(value) != 35:
        raise NotFound("chargeback not found", code="CHARGEBACK_NOT_FOUND")
    try:
        return UUID(hex=value[3:])
    except ValueError:
        raise NotFound("chargeback not found", code="CHARGEBACK_NOT_FOUND") from None


@router.get("/api/v1/chargebacks/{chargeback_id}")
def get_chargeback(chargeback_id: str, merchant: UUID = Depends(merchant_from_api_key),
                   service: ChargebackService = Depends(_service)) -> dict:
    found = service.store.get(merchant, _chargeback_id(chargeback_id))
    if found is None:
        raise NotFound("chargeback not found", code="CHARGEBACK_NOT_FOUND")
    return view(found)


@router.post("/api/v1/chargebacks/{chargeback_id}/evidence")
def submit_evidence(chargeback_id: str, body: Evidence, merchant: UUID = Depends(merchant_from_api_key),
                    service: ChargebackService = Depends(_service)) -> dict:
    # shortcut: stored and shown to operators; submitting it to the acquirer is a per-acquirer adapter still to build.
    return view(service.store.submit_evidence(merchant, _chargeback_id(chargeback_id),
                                              body.model_dump(exclude_none=True)))
