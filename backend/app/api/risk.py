"""Risk hold visibility: open holds with their reason and required documentation."""
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from app.api.api_keys import verify_api_key

router = APIRouter(tags=["risk"])


@router.get("/api/v1/risk-status")
def risk_status(request: Request, merchant: UUID = Depends(verify_api_key)) -> dict:
    return {"holds": request.app.state.risk.holds_for_merchant(merchant)}
