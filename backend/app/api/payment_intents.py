"""Payment intents, the card frame, the sandbox issuer page, and terminal checkout (Step 6)."""
import time
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import merchant_from_api_key
from app.application.payment_intents import PaymentIntentService
from app.application.registration import Forbidden, InvalidInput, Unauthenticated

router = APIRouter(tags=["payment intents"])
CHECKOUT_DIR = Path(__file__).parents[1] / "checkout"
# The web SDK's <script> build (npm run build in sdks/web). shortcut: served by the API; a CDN in production.
WEB_SDK = Path(__file__).parents[3] / "sdks" / "web" / "dist" / "synapsepay.js"


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateIntentBody(_Body):
    idempotency_key: UUID
    amount: int = Field(ge=100, le=9_999_999_999_99)  # at least ₹1.00; DE 4 holds 12 digits
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    capture_mode: Literal["AUTO", "MANUAL"] = "AUTO"
    description: str | None = Field(default=None, max_length=512)
    metadata: dict[str, str] | None = None
    webhook_url: str | None = Field(default=None, pattern=r"^https?://", max_length=2048)
    terminal_id: UUID | None = None


class ConfirmCard(_Body):
    encrypted_card_data: str = Field(min_length=1, max_length=4096)
    encrypted_cvv: str | None = Field(default=None, min_length=1, max_length=4096)
    card_expiry: str = Field(pattern=r"^(0[1-9]|1[0-2])/[0-9]{2}$")
    card_network: Literal["VISA", "MASTERCARD", "RUPAY", "AMEX"]
    cardholder_name: str | None = Field(default=None, max_length=128)


class ConfirmBody(_Body):
    client_secret: str = Field(min_length=1, max_length=128)
    payment_method: Literal["CARD"] = "CARD"
    card: ConfirmCard


class OtpBody(_Body):
    client_secret: str = Field(min_length=1, max_length=128)
    otp: str = Field(min_length=1, max_length=12)


def _service(request: Request) -> PaymentIntentService:
    return request.app.state.intents


# Merchant server: secret API key


@router.post("/api/v1/payment_intents")
def create_intent(body: CreateIntentBody, request: Request, merchant: UUID = Depends(merchant_from_api_key),
                  service: PaymentIntentService = Depends(_service)) -> JSONResponse:
    data = body.model_dump(mode="json", exclude_unset=True)
    url = data.get("webhook_url")
    if url and not url.startswith("https://") and not request.app.state.allow_insecure_webhooks:
        raise InvalidInput("webhook_url must be https")
    intent, created = service.create(merchant, data)
    return JSONResponse(status_code=201 if created else 200, content=intent)


@router.post("/api/v1/payment_intents/{intent_id}/cancel")
def cancel_intent(intent_id: str, merchant: UUID = Depends(merchant_from_api_key),
                  service: PaymentIntentService = Depends(_service)) -> dict:
    return service.cancel(merchant, intent_id)


@router.get("/api/v1/payment_intents/{intent_id}")
def retrieve_intent(intent_id: str, request: Request, client_secret: str | None = Query(default=None),
                    service: PaymentIntentService = Depends(_service)) -> dict:
    """With the secret key: the full intent. With ?client_secret: what the customer's page may see."""
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer sk_"):
        merchant = request.app.state.api_keys.merchant_for(authorization.split(" ", 1)[1])
        if merchant is None:
            raise Unauthenticated("invalid or revoked API key")
        return service.retrieve(merchant, intent_id)
    return service.retrieve_for_client(intent_id, client_secret)


# Customer's browser or app: client_secret


@router.post("/api/v1/payment_intents/{intent_id}/confirm")
def confirm_intent(intent_id: str, body: ConfirmBody, service: PaymentIntentService = Depends(_service)) -> dict:
    card = body.card.model_dump(exclude_none=True)
    card.pop("cardholder_name", None)  # PII the flow doesn't need: never stored
    return service.confirm(intent_id, body.client_secret, card)


@router.get("/api/v1/checkout/key")
def checkout_key(service: PaymentIntentService = Depends(_service)) -> JSONResponse:
    """The HSM's public checkout key (JWK). Card frames and mobile SDKs encrypt card data to it."""
    return JSONResponse(service.checkout_key(), headers={"cache-control": "public, max-age=300"})


@router.get("/checkout/card-frame")
def card_frame() -> FileResponse:
    # The only page that ever holds a typed card number. Served from Synapse's origin so the merchant's page
    # (another origin) can't read it.
    return FileResponse(CHECKOUT_DIR / "card-frame.html", headers={
        "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';"
                                   " frame-ancestors *",
        "cache-control": "no-store"})


@router.get("/checkout/{name}")
def checkout_asset(name: Literal["card-frame.js", "card-frame.css", "acs.js"]) -> FileResponse:
    media = "text/css" if name.endswith(".css") else "text/javascript"
    return FileResponse(CHECKOUT_DIR / name, media_type=media)


@router.get("/js/synapsepay.js")
def web_sdk() -> FileResponse:
    if not WEB_SDK.exists():
        from app.application.registration import NotFound
        raise NotFound("web SDK not built: run npm run build in sdks/web", "INVALID_REQUEST")
    return FileResponse(WEB_SDK, media_type="text/javascript", headers={"cache-control": "public, max-age=300"})


# Sandbox issuer (ACS) challenge page. shortcut: stands in for the issuer's 3-D Secure page.


@router.get("/sandbox/acs/{intent_id}", response_class=HTMLResponse)
def sandbox_acs(intent_id: str, client_secret: str = Query(min_length=1),
                service: PaymentIntentService = Depends(_service)) -> HTMLResponse:
    intent = service.retrieve_for_client(intent_id, client_secret)
    rupees = f"{intent['amount'] / 100:,.2f}"
    last4 = intent.get("card", {}).get("last4", "????")
    html = (CHECKOUT_DIR / "acs.html").read_text().replace("{{AMOUNT}}", rupees).replace("{{LAST4}}", last4)
    return HTMLResponse(html, headers={
        "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';"
                                   " frame-ancestors *", "cache-control": "no-store"})


@router.post("/sandbox/acs/{intent_id}")
def sandbox_acs_submit(intent_id: str, body: OtpBody, service: PaymentIntentService = Depends(_service)) -> dict:
    return service.complete_challenge(intent_id, body.client_secret, body.otp)


# Terminal checkout: an mTLS terminal asks for the next payment it should take (long poll)

MAX_WAIT = 10.0  # under Envoy's default 15 s route timeout


@router.get("/api/v1/terminals/{terminal_id}/checkout")
def terminal_checkout(terminal_id: UUID, request: Request, wait: float = Query(default=0, ge=0, le=MAX_WAIT),
                      service: PaymentIntentService = Depends(_service)) -> Response:
    caller = request.headers.get("x-terminal-id")
    if caller is None:
        raise Unauthenticated("terminal checkout requires the terminal's client certificate (mTLS)")
    if caller != str(terminal_id):
        raise Forbidden("client certificate belongs to a different terminal")
    deadline = time.monotonic() + wait
    while True:
        job = service.next_for_terminal(terminal_id)
        if job is not None:
            return JSONResponse(job)
        if time.monotonic() >= deadline:
            return Response(status_code=204)
        time.sleep(0.25)
