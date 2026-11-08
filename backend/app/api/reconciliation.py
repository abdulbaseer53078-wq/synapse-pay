"""Reconciliation reports for the operations team (PR 7, spec 1.14.0). Read-only: runs are made by the nightly job
(`python -m app.reconcile`), never by a request."""
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse

from app.api.auth import with_scope
from app.application.reconciliation import ReconciliationService
from app.application.registration import NotFound

router = APIRouter(tags=["reconciliation"])
_admin = with_scope("registry:admin")


def _service(request: Request) -> ReconciliationService:
    return request.app.state.reconciliation


@router.get("/api/v1/reconciliation/runs")
def runs(limit: int = Query(default=50, ge=1, le=200), service: ReconciliationService = Depends(_service),
         _: dict = Depends(_admin)) -> dict:
    return {"runs": service.store.runs(limit)}


@router.get("/api/v1/reconciliation/runs/{run_id}")
def run(run_id: UUID, service: ReconciliationService = Depends(_service), _: dict = Depends(_admin)) -> dict:
    found = service.store.run(run_id)
    if found is None:
        raise NotFound("reconciliation run not found", code="RECONCILIATION_RUN_NOT_FOUND")
    return found


@router.get("/api/v1/reconciliation/runs/{run_id}/report.csv", response_class=PlainTextResponse)
def report(run_id: UUID, service: ReconciliationService = Depends(_service), _: dict = Depends(_admin)) -> str:
    try:
        return service.report_csv(run_id)
    except KeyError:
        raise NotFound("reconciliation run not found", code="RECONCILIATION_RUN_NOT_FOUND") from None
