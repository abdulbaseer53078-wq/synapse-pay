"""Refund, capture and void (PR 4, spec 1.13.0): the merchant's server acts on its own payments with its secret key.

A refund needs an Idempotency-Key header: the same key returns the same refund, whatever state it reached, so a
double-clicked "Refund" button refunds once. Capture and void are idempotent by state: doing either twice is a no-op.
"""
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import merchant_from_api_key
from app.application.refunds import RefundService
from app.application.registration import InvalidInput, NotFound
from app.application.transactions import parse_public_id, public_id

router = APIRouter(tags=["refunds"])


class RefundBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: int = Field(ge=1, le=9_999_999_999_99, description="Minor units; at most what is left of the payment")
    reason: str | None = Field(default=None, max_length=255)


def _service(request: Request) -> RefundService:
    return request.app.state.refunds


def _transaction(transaction_id: str) -> UUID:
    parsed = parse_public_id(transaction_id, "txn_")
    if parsed is None:  # the same answer as an unknown id: the shape of an id says nothing
        raise NotFound("transaction not found", code="TRANSACTION_NOT_FOUND")
    return parsed


def _view(refund) -> dict:
    body = {"refund_id": f"rfnd_{refund.refund_id.hex}", "transaction_id": public_id(refund.transaction_id),
            "amount": refund.amount, "status": refund.status,
            "created_at": refund.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": refund.updated_at.isoformat().replace("+00:00", "Z")}
    for key in ("reason", "network_reference", "error"):
        if getattr(refund, key):
            body[key] = getattr(refund, key)
    return body


@router.post("/api/v1/transactions/{transaction_id}/refund")
def refund(transaction_id: str, body: RefundBody, idempotency_key: str | None = Header(default=None),
           merchant: UUID = Depends(merchant_from_api_key), service: RefundService = Depends(_service)) -> JSONResponse:
    try:
        key = UUID(idempotency_key or "")
    except ValueError:
        raise InvalidInput("an Idempotency-Key header (a UUID) is required for refunds") from None
    made, created = service.refund(merchant, _transaction(transaction_id), body.amount, body.reason, key)
    return JSONResponse(status_code=201 if created else 200, content=_view(made))


@router.post("/api/v1/transactions/{transaction_id}/capture")
def capture(transaction_id: str, merchant: UUID = Depends(merchant_from_api_key),
            service: RefundService = Depends(_service)) -> dict:
    return service.capture(merchant, _transaction(transaction_id))


@router.post("/api/v1/transactions/{transaction_id}/void")
def void(transaction_id: str, merchant: UUID = Depends(merchant_from_api_key),
         service: RefundService = Depends(_service)) -> dict:
    return service.void(merchant, _transaction(transaction_id))
