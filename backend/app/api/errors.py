"""Renders every error in the spec's Error shape: error_code, error_message, error_category, retryable."""
from fastapi import FastAPI, Request
import psycopg
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.application import observability
from app.domain.ledger import LedgerImbalance

from app.application.registration import (CertificateAuthorityUnavailable, Conflict, Forbidden, InvalidInput,
                                          NotFound, RegistrationError, Unauthenticated, UnknownReference)
from app.application.methods import (AdapterUnavailable, CapabilityNotSupported, InvalidMethodDetails,
                                     MethodNotSupported)
from app.application.payment_intents import IntentConflict, IntentNotConfirmable
from app.application.transactions import (BadCardData, CardServiceUnavailable, IdempotencyConflict, IntentNotPayable,
                                          MerchantMismatch, StillProcessing)

_HTTP = {
    InvalidInput: (400, "VALIDATION_ERROR"),
    Unauthenticated: (401, "AUTHENTICATION_ERROR"),
    Forbidden: (403, "AUTHENTICATION_ERROR"),
    NotFound: (404, "VALIDATION_ERROR"),
    Conflict: (409, "VALIDATION_ERROR"),
    UnknownReference: (422, "VALIDATION_ERROR"),
    CertificateAuthorityUnavailable: (503, "SYSTEM_ERROR"),
    IdempotencyConflict: (409, "VALIDATION_ERROR"),
    StillProcessing: (409, "SYSTEM_ERROR"),  # retryable: same request, still running
    CardServiceUnavailable: (503, "SYSTEM_ERROR"),
    BadCardData: (400, "VALIDATION_ERROR"),
    MethodNotSupported: (422, "VALIDATION_ERROR"),
    InvalidMethodDetails: (400, "VALIDATION_ERROR"),
    AdapterUnavailable: (503, "SYSTEM_ERROR"),
    CapabilityNotSupported: (422, "VALIDATION_ERROR"),
    MerchantMismatch: (422, "VALIDATION_ERROR"),
    IntentNotPayable: (409, "VALIDATION_ERROR"),
    IntentConflict: (409, "VALIDATION_ERROR"),
    IntentNotConfirmable: (409, "VALIDATION_ERROR"),
}


def error_response(status: int, code: str, category: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "error_code": code, "error_message": message, "error_category": category,
        "retryable": category == "SYSTEM_ERROR"})


def install(app: FastAPI) -> None:
    @app.exception_handler(LedgerImbalance)
    @app.exception_handler(psycopg.errors.RaiseException)
    async def ledger_integrity(request: Request, exc: Exception) -> JSONResponse:
        # Raised by the ledger's own checks or its database triggers (migration 016): the whole request rolled back,
        # so no money moved, but it should never happen. Counted, paged, and refused without detail.
        text = str(exc)
        reason = ("imbalance" if isinstance(exc, LedgerImbalance) or "IMBALANCE" in text.upper()
                  else "append_only" if "append-only" in text else "other")
        observability.LEDGER_INTEGRITY_REFUSED.labels(reason).inc()
        alerts = getattr(request.app.state, "ops_alerts", None)
        if alerts:
            alerts.ops_alert("CRITICAL: a ledger write was refused for breaking an invariant", "critical",
                             {"reason": reason, "path": request.url.path})
        return error_response(500, "INTERNAL_ERROR", "SYSTEM_ERROR", "the request was refused and rolled back")

    @app.exception_handler(RegistrationError)
    async def registration_error(_: Request, exc: RegistrationError) -> JSONResponse:
        status, category = _HTTP[type(exc)]
        return error_response(status, exc.code, category, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Field paths and reasons only: never echo input values, which can include tokens.
        message = "; ".join(f"{'.'.join(map(str, e['loc'][1:]))}: {e['msg']}" for e in exc.errors())
        return error_response(400, "INVALID_REQUEST", "VALIDATION_ERROR", message)
