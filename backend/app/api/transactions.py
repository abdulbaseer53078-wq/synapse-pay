"""POST /api/v1/transactions (spec: createTransaction)."""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.application.registration import InvalidInput
from app.application.transactions import TransactionService

router = APIRouter(prefix="/api/v1/transactions", tags=["transactions"])

_SECRET = Field(min_length=1, max_length=4096)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CardDetails(_Body):
    encrypted_card_data: str = _SECRET
    card_expiry: str = Field(pattern=r"^(0[1-9]|1[0-2])/[0-9]{2}$")
    cardholder_name: str | None = Field(default=None, max_length=128)
    card_network: Literal["VISA", "MASTERCARD", "RUPAY", "AMEX"]
    pin_block: str | None = Field(default=None, min_length=1, max_length=512)


class TransactionBody(_Body):
    idempotency_key: UUID
    amount: int = Field(ge=1, le=9_999_999_999_99)  # DE 4 holds 12 digits
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    payment_method: Literal["CARD", "UPI", "WALLET", "QR", "OFFLINE"]
    # Only CARD is processed in this release; other methods' details are checked when they're supported.
    method_details: dict
    terminal_id: str = Field(min_length=1, max_length=64)
    merchant_id: str = Field(min_length=1, max_length=64)
    customer_ref: str | None = Field(default=None, max_length=128)
    capture_mode: Literal["AUTO", "MANUAL"] = "AUTO"
    description: str | None = Field(default=None, max_length=512)
    metadata: dict[str, str] | None = None
    webhook_url: str | None = Field(default=None, pattern=r"^https://", max_length=2048)
    payment_intent_id: str | None = Field(default=None, pattern=r"^pi_[0-9a-f]{32}$")  # since 1.3.0


@router.post("", status_code=201)
def create_transaction(body: TransactionBody, request: Request,
                       x_terminal_id: str | None = Header(default=None)) -> JSONResponse:
    service: TransactionService = request.app.state.transactions
    data = body.model_dump(mode="json", exclude_unset=True)
    if body.payment_method == "CARD":
        # Validated here so errors name fields; never echoed back (encrypted_card_data, PII).
        try:
            details = CardDetails.model_validate(body.method_details)
        except ValidationError as e:
            # Field paths and reasons only, as for every other validation error.
            raise InvalidInput("; ".join(f"method_details.{'.'.join(map(str, err['loc']))}: {err['msg']}"
                                         for err in e.errors()))
        data["method_details"] = details.model_dump(exclude_none=True)
    data.setdefault("capture_mode", "AUTO")
    caller = None
    if x_terminal_id is not None:
        try:
            caller = UUID(x_terminal_id)
        except ValueError:
            caller = None
    return JSONResponse(status_code=201, content=service.create(caller, data))
