"""Saved cards (Step 29, spec 1.12.0): a merchant server saves a card the customer entered (encrypted to the
checkout key, so it arrives here unreadable) and pays with the token later. Secret API key only."""
import re
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import merchant_from_api_key
from app.application.card_tokens import CardTokenService
from app.application.registration import NotFound

router = APIRouter(tags=["card tokens"])
_TOKEN = re.compile(r"^tok_[0-9a-f]{32}$")


class SaveCardBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    encrypted_card_data: str = Field(min_length=1, max_length=4096)
    card_expiry: str = Field(pattern=r"^(0[1-9]|1[0-2])/[0-9]{2}$")
    card_network: Literal["VISA", "MASTERCARD", "RUPAY", "AMEX"]
    customer_ref: str | None = Field(default=None, max_length=128)


def _service(request: Request) -> CardTokenService:
    return request.app.state.card_tokens


@router.post("/api/v1/card-tokens", status_code=201)
def save_card(body: SaveCardBody, merchant: UUID = Depends(merchant_from_api_key),
              service: CardTokenService = Depends(_service)) -> dict:
    # Idempotent by nature: the same card saved again by this merchant returns the same token.
    return service.save(merchant, body.encrypted_card_data, body.card_expiry, body.card_network, body.customer_ref)


@router.delete("/api/v1/card-tokens/{token}", status_code=204)
def delete_card(token: str, merchant: UUID = Depends(merchant_from_api_key),
                service: CardTokenService = Depends(_service)) -> Response:
    if not _TOKEN.match(token):
        raise NotFound("card token not found", code="CARD_TOKEN_NOT_FOUND")  # the same answer as an unknown one
    service.delete(merchant, token)
    return Response(status_code=204)
