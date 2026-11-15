"""Transparent fee breakdowns: each settlement's Gross, MDR, GST, and Net."""
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.api_keys import verify_api_key

router = APIRouter(tags=["settlements"])


@router.get("/api/v1/settlements")
def list_settlements(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    after: str | None = Query(default=None),
    merchant: UUID = Depends(verify_api_key),
) -> dict:
    return request.app.state.settlements.list_for_merchant(merchant, limit=limit, after=after)
