"""Transparent fee breakdowns: each settlement's Gross, MDR, GST, and Net."""
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.api_keys import verify_api_key

router = APIRouter(tags=["settlements"])


@router.get("/api/v1/settlements")
def list_settlements(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    merchant: UUID = Depends(verify_api_key),
) -> dict:
    return {"settlements": request.app.state.settlements.list_for_merchant(merchant, limit)}
