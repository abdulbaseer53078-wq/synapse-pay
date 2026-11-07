"""POST /api/v1/webhooks/upi — the public callback the PSP (or NPCI) posts to (Stage 1, Step 10B).

Deliberately has no auth dependency: the HMAC signature *is* the authentication, and a bearer token here would
be a second shared secret to leak. It must also bypass the mTLS gateway's terminal check — a PSP is not a
terminal — which is why gateway/envoy.yaml disables ext_authz for this path.

The body is never parsed by FastAPI: `request.body()` is read raw, because a signature over a
parse-and-reserialise round trip will not match the provider's.
"""
from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from app.application.methods import WebhookRejected
from app.application.upi_webhooks import UpiWebhookHandler

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


@router.post("/upi")
async def upi_webhook(request: Request) -> JSONResponse:
    handler: UpiWebhookHandler = request.app.state.upi_webhooks
    raw = await request.body()  # raw bytes: the signature covers exactly these
    try:
        outcome = await run_in_threadpool(handler.handle, raw, dict(request.headers))
    except WebhookRejected as rejected:
        return JSONResponse(status_code=rejected.status,
                            content={"error_code": rejected.code, "error_message": rejected.message})
    # 200 for anything trusted, including a duplicate and an unknown payment: a 4xx would make the PSP retry
    # for hours over something retrying cannot fix.
    return JSONResponse(status_code=200, content={
        "received": True, "duplicate": outcome.duplicate, "applied": outcome.applied,
        "status": outcome.status, "reason": outcome.reason})
