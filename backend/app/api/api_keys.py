"""Developer API key management.

verify_api_key: live-mode-only dependency for endpoints that only make sense in production.
The router below lets any key (test or live) manage the merchant's key set.
"""
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.auth import merchant_from_api_key
from app.application.registration import Unauthenticated

_bearer = HTTPBearer(auto_error=False)
router = APIRouter(tags=["api-keys"])


def verify_api_key(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> UUID:
    """Dependency: merchant_id for a valid sk_live_... key. Refuses test-mode keys."""
    if creds is None or not creds.credentials.startswith("sk_live_"):
        raise Unauthenticated("a live API key (Authorization: Bearer sk_live_...) is required")
    merchant = request.app.state.api_keys.merchant_for(creds.credentials)
    if merchant is None:
        raise Unauthenticated("invalid or revoked API key")
    return merchant


@router.get("/api/v1/api-keys")
def list_api_keys(request: Request, merchant: UUID = Depends(merchant_from_api_key)) -> dict:
    return {"items": request.app.state.api_keys.list_for_merchant(merchant)}


@router.post("/api/v1/api-keys", status_code=201)
def create_api_key(request: Request, merchant: UUID = Depends(merchant_from_api_key)) -> dict:
    key, key_id = request.app.state.api_keys.create(merchant, mode="live")
    return {
        "key_id": str(key_id),
        "prefix": key[:12],
        "secret_key": key,
        "created_at": datetime.now(UTC).isoformat(),
    }


@router.delete("/api/v1/api-keys/{key_id}", status_code=204)
def revoke_api_key(key_id: str, request: Request, merchant: UUID = Depends(merchant_from_api_key)):
    # Idempotent: 204 whether the key was active or already revoked.
    request.app.state.api_keys.revoke(UUID(key_id), merchant)
