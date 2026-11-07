from uuid import UUID

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.application.registration import Forbidden, Unauthenticated
from app.domain.terminal import Actor

_bearer = HTTPBearer(auto_error=False)


def _claims(request: Request, creds: HTTPAuthorizationCredentials | None) -> dict:
    if creds is None:
        raise Unauthenticated("missing bearer token")
    try:
        # shortcut: one static public key; switch to the auth server's JWKS once it exists.
        return jwt.decode(creds.credentials, request.app.state.jwt_public_key,
                          algorithms=["ES256", "RS256"], options={"require": ["exp", "sub"]})
    except jwt.InvalidTokenError:
        raise Unauthenticated("invalid or expired access token")


def with_scope(scope: str):
    """Dependency: the claims of a valid OAuth access token that carries `scope`."""

    def dependency(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict:
        claims = _claims(request, creds)
        if scope not in claims.get("scope", "").split():
            raise Forbidden(f"access token lacks the {scope} scope")
        return claims

    return dependency


def merchant_with_scope(scope: str):
    """Dependency: the merchant_id (token `sub`) of a valid OAuth access token that carries `scope`."""

    def dependency(claims: dict = Depends(with_scope(scope))) -> UUID:
        try:
            return UUID(claims["sub"])
        except ValueError:
            raise Unauthenticated("invalid or expired access token")

    return dependency


def registry_caller(*merchant_scopes: str):
    """Dependency: (ADMIN, sub) for a registry:admin token, else (MERCHANT, merchant_id) for a token carrying
    any of merchant_scopes."""

    def dependency(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> tuple[Actor, str]:
        claims = _claims(request, creds)
        scopes = claims.get("scope", "").split()
        if "registry:admin" in scopes:
            return Actor.ADMIN, claims["sub"]
        if any(s in scopes for s in merchant_scopes):
            try:
                return Actor.MERCHANT, str(UUID(claims["sub"]))
            except ValueError:
                raise Unauthenticated("invalid or expired access token")
        raise Forbidden(f"access token lacks the {' or '.join(merchant_scopes)} or registry:admin scope")

    return dependency


def merchant_from_api_key(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> UUID:
    """Dependency: the merchant whose secret API key (Authorization: Bearer sk_...) made the request."""
    if creds is None or not creds.credentials.startswith("sk_"):
        raise Unauthenticated("a secret API key (Authorization: Bearer sk_...) is required")
    merchant = request.app.state.api_keys.merchant_for(creds.credentials)
    if merchant is None:
        raise Unauthenticated("invalid or revoked API key")
    return merchant
