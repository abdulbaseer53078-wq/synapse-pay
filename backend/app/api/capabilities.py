"""GET /api/v1/capabilities/{payment_method} (spec: getCapabilities).

Static per method, served straight from the adapter that implements it, so the answer can never drift from
what the rail actually does. The SDK fetches each descriptor once at startup and caches it, then refuses
impossible actions itself — a partial refund button that never appears beats a request that fails.

An unknown method is a 400 here, not the 422 the transaction endpoint returns: the path parameter is an enum
in the contract (`TransactionRequest.payment_method`), so a value outside it is a malformed request.
"""
from fastapi import APIRouter, Depends, Request

from app.api.auth import with_scope_or_terminal
from app.application.methods import MethodNotSupported, MethodRegistry
from app.application.registration import InvalidInput

router = APIRouter(prefix="/api/v1/capabilities", tags=["capabilities"])

_reader = with_scope_or_terminal("transactions:read")


@router.get("/{payment_method}")
def get_capabilities(payment_method: str, request: Request, _: dict | None = Depends(_reader)) -> dict:
    registry: MethodRegistry = request.app.state.methods
    try:
        adapter = registry.for_method(payment_method)
    except MethodNotSupported as exc:
        raise InvalidInput(str(exc.message)) from exc
    return adapter.capabilities().to_dict()
