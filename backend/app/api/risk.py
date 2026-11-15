"""Risk hold visibility: open holds with their reason and required documentation."""
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.api_keys import verify_api_key
from app.application.registration import NotFound

router = APIRouter(tags=["risk"])


@router.get("/api/v1/risk-status")
def risk_status(
    request: Request,
    status: str = Query(default="open", pattern="^(open|all)$"),
    merchant: UUID = Depends(verify_api_key),
) -> dict:
    return {"holds": request.app.state.risk.holds_for_merchant(merchant, status_filter=status)}


@router.get("/api/v1/risk-status/{hold_id}")
def get_risk_hold(hold_id: str, request: Request, merchant: UUID = Depends(verify_api_key)) -> dict:
    result = request.app.state.risk.hold_for_merchant(UUID(hold_id), merchant)
    if result is None:
        raise NotFound("risk hold not found", code="RISK_HOLD_NOT_FOUND")
    return result
