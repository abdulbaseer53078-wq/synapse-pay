"""Envoy ext_authz target. Envoy has already verified the client certificate (chain + CRL) and forwards
its URI SAN in X-Forwarded-Client-Cert, which it sanitises so a client can't supply its own.

Not routed by Envoy and must not be exposed publicly: anyone who can reach it could forge the header.
"""
import re
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from app.application.authorization import AuthorizationService
from app.application.registration import Forbidden
from app.domain.terminal import TERMINAL_URI_PREFIX

router = APIRouter(prefix="/internal/gateway", include_in_schema=False)

_SAN = re.compile(r"URI=" + re.escape(TERMINAL_URI_PREFIX) + r"([0-9a-fA-F-]{36})(?:[;,]|$)")
_PATH_TERMINAL = re.compile(r"^/?api/v1/terminals/([^/?]+)")


def _service(request: Request) -> AuthorizationService:
    return request.app.state.authorization


@router.api_route("/authz/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def authz(path: str, request: Request, service: AuthorizationService = Depends(_service)) -> Response:
    match = _SAN.search(request.headers.get("x-forwarded-client-cert", ""))
    if match is None:
        raise Forbidden("client certificate carries no terminal identity")
    terminal_id = UUID(match.group(1))
    in_path = _PATH_TERMINAL.match(path)
    if in_path and in_path.group(1).lower() != str(terminal_id):
        raise Forbidden("client certificate belongs to a different terminal")
    service.admit(terminal_id)
    # Envoy forwards this to the backend, so business logic gets the authenticated terminal.
    return Response(status_code=200, headers={"x-terminal-id": str(terminal_id)})
