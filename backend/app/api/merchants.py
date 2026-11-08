"""GET /api/v1/merchants/me/recovery-stats (spec: getRecoveryStats): what failover saved this merchant."""
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from app.api.auth import merchant_from_api_key

router = APIRouter(prefix="/api/v1/merchants/me", tags=["merchants"])


@router.get("/recovery-stats")
def recovery_stats(request: Request, days: int = Query(default=30, ge=1, le=90),
                   merchant: UUID = Depends(merchant_from_api_key)) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return request.app.state.recovery.for_merchant(merchant, since)
