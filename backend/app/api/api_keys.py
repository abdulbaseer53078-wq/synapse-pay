"""Developer API key dependency — live mode only.

merchant_from_api_key in auth.py accepts any sk_... key (test or live).
This dependency is for endpoints that only make sense in production: it refuses sk_test_ keys.
"""
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.application.registration import Unauthenticated

_bearer = HTTPBearer(auto_error=False)


def verify_api_key(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> UUID:
    """Dependency: merchant_id for a valid sk_live_... key. Refuses test-mode keys."""
    if creds is None or not creds.credentials.startswith("sk_live_"):
        raise Unauthenticated("a live API key (Authorization: Bearer sk_live_...) is required")
    merchant = request.app.state.api_keys.merchant_for(creds.credentials)
    if merchant is None:
        raise Unauthenticated("invalid or revoked API key")
    return merchant
