"""Hosted checkout sessions for browser-based e-commerce (1.19.0)."""
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.api_keys import verify_api_key
from app.api.errors import error_response
from app.application.payment_intents import online_acquirer_ids
from app.application.registration import InvalidInput, NotFound
from app.application.transactions import BadCardData, CardRequest, CardServiceUnavailable

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


class PayBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Brief asked for card_number/expiry_month/expiry_year/cvv — refused: raw card data can never reach the
    # backend (PCI DSS; HttpCardProcessor only accepts encrypted_card_data). The SDK encrypts before sending.
    encrypted_card_data: str
    card_expiry: str = Field(pattern=r"^\d{4}-\d{2}$")  # YYYY-MM, matches CardRequest.card_expiry


@router.post("/api/v1/checkout/sessions/{session_id}/pay", response_model=None)
def pay_session(session_id: str, body: PayBody, request: Request) -> dict | JSONResponse:
    sessions = request.app.state.checkout_sessions
    session = sessions.get_for_pay(session_id)
    if session is None:
        raise NotFound("checkout session not found", code="CHECKOUT_SESSION_NOT_FOUND")
    if session["status"] not in ("OPEN",):
        raise InvalidInput(f"checkout session is {session['status']}", code="CHECKOUT_SESSION_NOT_PAYABLE")

    if not sessions.begin_pay(session_id):
        # Either expired or already PROCESSING (double-click)
        raise InvalidInput("checkout session is not payable", code="CHECKOUT_SESSION_NOT_PAYABLE")

    tid, mid = online_acquirer_ids(session["merchant_id"])
    card_req = CardRequest(
        transaction_id=uuid4(),
        kind="PURCHASE",
        amount=session["amount"],
        currency=session["currency"],
        acquirer_terminal_id=tid,
        acquirer_merchant_id=mid,
        encrypted_card_data=body.encrypted_card_data,
        card_expiry=body.card_expiry,
    )
    try:
        result = request.app.state.cards.process(card_req)
    except (BadCardData, CardServiceUnavailable):
        sessions.reopen(session_id)
        raise

    if result.status == "APPROVED":
        sessions.complete(session_id)
        return {"status": "APPROVED", "success_url": session["success_url"]}

    sessions.reopen(session_id)
    msg = (result.error or {}).get("error_message", "card declined")
    return error_response(402, "CARD_DECLINED", "VALIDATION_ERROR", msg)
