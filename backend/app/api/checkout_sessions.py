"""Hosted checkout sessions for browser-based e-commerce (1.19.0)."""
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.api_keys import verify_api_key
from app.application.registration import NotFound

router = APIRouter(tags=["checkout"])


class CreateSessionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: int = Field(ge=100)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    description: str | None = Field(default=None, max_length=255)
    success_url: str = Field(max_length=2048)
    cancel_url: str = Field(max_length=2048)
    metadata: dict[str, str] = Field(default_factory=dict)


@router.post("/api/v1/checkout/sessions", status_code=201)
def create_session(body: CreateSessionBody, request: Request,
                   merchant: UUID = Depends(verify_api_key)) -> dict:
    return request.app.state.checkout_sessions.create(
        merchant, body.amount, body.currency, body.description,
        body.success_url, body.cancel_url, body.metadata)


@router.get("/api/v1/checkout/sessions/{session_id}")
def get_session(session_id: str, request: Request, merchant: UUID = Depends(verify_api_key)) -> dict:
    result = request.app.state.checkout_sessions.get(session_id, merchant)
    if result is None:
        raise NotFound("checkout session not found", code="CHECKOUT_SESSION_NOT_FOUND")
    return result
