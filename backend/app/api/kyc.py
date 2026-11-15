"""Merchant KYC submission and status check."""
import re
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.api.auth import merchant_from_api_key
from app.application.registration import InvalidInput

router = APIRouter(tags=["kyc"])

_PAN_RE = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
# GST format: 2-digit state code + PAN + 1 entity code + Z + 1 check digit
_GST_RE = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")


class KycBody(BaseModel):
    pan_number: str = Field(min_length=10, max_length=10)
    gst_number: str = Field(min_length=15, max_length=15)


@router.post("/api/v1/kyc/submit", status_code=202)
def submit_kyc(body: KycBody, request: Request,
               merchant: UUID = Depends(merchant_from_api_key)) -> dict:
    if not _PAN_RE.match(body.pan_number):
        raise InvalidInput("invalid PAN format (expected AAAAA0000A)", code="INVALID_PAN")
    if not _GST_RE.match(body.gst_number):
        raise InvalidInput("invalid GST format", code="INVALID_GST")
    request.app.state.kyc.submit(merchant, body.pan_number, body.gst_number)
    return {"status": "PENDING", "message": "KYC submitted; under review"}


@router.get("/api/v1/kyc/status")
def get_kyc_status(request: Request,
                   merchant: UUID = Depends(merchant_from_api_key)) -> dict:
    status = request.app.state.kyc.status_for(merchant)
    return {"status": status or "NOT_SUBMITTED"}
