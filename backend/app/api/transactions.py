"""POST /api/v1/transactions (spec: createTransaction).

Method-agnostic since Step 8: the body carries `method_details` as an object, and the registered adapter
validates it. This module knows the envelope, not the rail.
"""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.application.registration import InvalidInput, Unauthenticated
from app.application.transaction_sync import OfflineSyncService
from app.application.transactions import TransactionService

router = APIRouter(prefix="/api/v1/transactions", tags=["transactions"])

# A terminal offline for hours can generate hundreds of sales; 100 keeps one request short enough that its
# response arrives before the link drops again, and a retry is cheap.
MAX_SYNC_ITEMS = 100


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TransactionBody(_Body):
    idempotency_key: UUID
    amount: int = Field(ge=1, le=9_999_999_999_99)  # DE 4 holds 12 digits
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    payment_method: Literal["CARD", "UPI", "WALLET", "QR", "OFFLINE"]
    # Shape chosen by payment_method; the adapter for that method validates it (Step 8).
    method_details: dict
    terminal_id: str = Field(min_length=1, max_length=64)
    merchant_id: str = Field(min_length=1, max_length=64)
    customer_ref: str | None = Field(default=None, max_length=128)
    capture_mode: Literal["AUTO", "MANUAL"] = "AUTO"
    description: str | None = Field(default=None, max_length=512)
    metadata: dict[str, str] | None = None
    webhook_url: str | None = Field(default=None, pattern=r"^https://", max_length=2048)
    payment_intent_id: str | None = Field(default=None, pattern=r"^pi_[0-9a-f]{32}$")  # since 1.3.0


@router.post("/sync", status_code=200)
def sync_offline(body: dict, request: Request,
                 x_terminal_id: str | None = Header(default=None)) -> JSONResponse:
    """Batch upload of sales a terminal accepted while offline (spec: syncOfflineTransactions).

    The terminal's certificate is the authentication (the gateway verified it); each item's own signature is
    what proves the amount was not edited in the local queue. Nothing here is trusted before that check.
    """
    caller = None
    if x_terminal_id is not None:
        try:
            caller = UUID(x_terminal_id)
        except ValueError:
            caller = None
    if caller is None:
        raise Unauthenticated("offline sync requires a terminal's client certificate (mTLS)")

    items = body.get("transactions")
    if not isinstance(items, list) or not items:
        raise InvalidInput("transactions must be a non-empty array")
    if len(items) > MAX_SYNC_ITEMS:
        raise InvalidInput(f"a batch may hold at most {MAX_SYNC_ITEMS} transactions; send more, smaller batches")

    service: OfflineSyncService = request.app.state.offline_sync
    return JSONResponse(status_code=200, content={"results": service.sync(caller, items)})


@router.post("", status_code=201)
def create_transaction(body: TransactionBody, request: Request,
                       x_terminal_id: str | None = Header(default=None)) -> JSONResponse:
    service: TransactionService = request.app.state.transactions
    data = body.model_dump(mode="json", exclude_unset=True)
    data.setdefault("capture_mode", "AUTO")
    caller = None
    if x_terminal_id is not None:
        try:
            caller = UUID(x_terminal_id)
        except ValueError:
            caller = None
    return JSONResponse(status_code=201, content=service.create(caller, data))
