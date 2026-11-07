"""Inbound provider callbacks (Stages 1, Steps 10B and 12b).

Two routes, one handler: the security checks and the deduplication are identical for every provider, and the
adapter is the only thing that differs. The body is never parsed by FastAPI — `request.body()` is read raw,
because a signature over a parse-and-reserialise round trip will not match the sender's.

No auth dependency on either route: the HMAC signature *is* the authentication, and they bypass the mTLS
gateway's terminal check because a payment network is not a terminal (see gateway/envoy.yaml).
"""
from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from app.application.methods import WebhookRejected
from app.application.upi_webhooks import WebhookHandler

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


async def _dispatch(request: Request, handler: WebhookHandler) -> JSONResponse:
    raw = await request.body()  # raw bytes: the signature covers exactly these
    try:
        outcome = await run_in_threadpool(handler.handle, raw, dict(request.headers))
    except WebhookRejected as rejected:
        return JSONResponse(status_code=rejected.status,
                            content={"error_code": rejected.code, "error_message": rejected.message})
    # 200 for anything trusted, including a duplicate and an unknown payment: a 4xx would make the provider
    # retry for hours over something retrying cannot fix.
    return JSONResponse(status_code=200, content={
        "received": True, "duplicate": outcome.duplicate, "applied": outcome.applied,
        "status": outcome.status, "reason": outcome.reason})


@router.post("/upi")
async def upi_webhook(request: Request) -> JSONResponse:
    return await _dispatch(request, request.app.state.upi_webhooks)


@router.post("/wallet")
async def wallet_webhook(request: Request) -> JSONResponse:
    return await _dispatch(request, request.app.state.wallet_webhooks)
