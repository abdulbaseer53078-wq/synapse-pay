"""Envoy ext_authz target. Envoy has already verified the client certificate (chain + CRL) and forwards
its URI SAN in X-Forwarded-Client-Cert, which it sanitises so a client can't supply its own.

Not routed by Envoy and must not be exposed publicly: anyone who can reach it could forge the header.
"""
import re
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from app.application.authorization import AuthorizationService
from app.application.registration import Forbidden
from app.domain.edge import EDGE_URI_PREFIX
from app.domain.terminal import TERMINAL_URI_PREFIX

router = APIRouter(prefix="/internal/gateway", include_in_schema=False)

_SAN = re.compile(r"URI=" + re.escape(TERMINAL_URI_PREFIX) + r"([0-9a-fA-F-]{36})(?:[;,]|$)")
_PATH_TERMINAL = re.compile(r"^/?api/v1/terminals/([^/?]+)")
_EDGE_SAN = re.compile(r"URI=" + re.escape(EDGE_URI_PREFIX) + r"([0-9a-fA-F-]{36})(?:[;,]|$)")
# All an edge node's certificate may reach (Step 20), and of those, what is the edge's alone. Offline sync is
# shared: terminals upload their own queue there, edge nodes upload theirs (Step 21).
EDGE_ONLY_PATHS = ("internal/v1/edge/",)
EDGE_PATHS = EDGE_ONLY_PATHS + ("api/v1/transactions/sync",)
# Both identity headers are always set, the one that doesn't apply to a value that is never an id: ext_authz only
# overwrites headers its answer carries, so this is what stops a client sending its own.
_NOBODY = "-"


def _service(request: Request) -> AuthorizationService:
    return request.app.state.authorization


@router.api_route("/authz/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def authz(path: str, request: Request, service: AuthorizationService = Depends(_service)) -> Response:
    client_cert = request.headers.get("x-forwarded-client-cert", "")
    edge = _EDGE_SAN.search(client_cert)
    if edge is not None:
        if not path.lstrip("/").startswith(EDGE_PATHS):
            raise Forbidden("an edge node's certificate may only reach the edge API")
        edge_node_id = UUID(edge.group(1))
        request.app.state.edge.admit(edge_node_id)
        return Response(status_code=200, headers={"x-edge-node-id": str(edge_node_id), "x-terminal-id": _NOBODY})
    match = _SAN.search(client_cert)
    if match is None:
        raise Forbidden("client certificate carries no terminal identity")
    if path.lstrip("/").startswith(EDGE_ONLY_PATHS):
        raise Forbidden("the edge API is for edge nodes")
    terminal_id = UUID(match.group(1))
    in_path = _PATH_TERMINAL.match(path)
    if in_path and in_path.group(1).lower() != str(terminal_id):
        raise Forbidden("client certificate belongs to a different terminal")
    service.admit(terminal_id)
    # Envoy forwards this to the backend, so business logic gets the authenticated terminal.
    return Response(status_code=200, headers={"x-terminal-id": str(terminal_id), "x-edge-node-id": _NOBODY})
