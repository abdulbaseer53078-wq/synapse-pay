"""Certification test harness runs (Step 27). CI or a test lab records a run with `certification:run`; recording
one approves nothing. A registry:admin can then record the scheme's certification, but only for a firmware whose
latest run passed that scheme."""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import with_scope
from app.api.certifications import Scheme
from app.application.certification import CertificationAdmin

router = APIRouter(tags=["certification registry"])


class ReportCase(BaseModel):
    model_config = ConfigDict(extra="allow")  # expected, got and evidence are kept as the harness wrote them
    id: str = Field(min_length=1, max_length=64)
    scheme: Scheme
    passed: bool


class Report(BaseModel):
    model_config = ConfigDict(extra="allow")
    cases: list[ReportCase] = Field(max_length=500)


class RecordRunBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_model: str = Field(min_length=1, max_length=64)
    firmware_version: str = Field(min_length=1, max_length=32)
    driver: str = Field(min_length=1, max_length=64)
    report: Report


@router.post("/api/v1/certification-runs", status_code=201)
def record_run(body: RecordRunBody, request: Request, claims: dict = Depends(with_scope("certification:run"))) -> dict:
    service: CertificationAdmin = request.app.state.certifications
    run = service.record_run(body.device_model, body.firmware_version, body.driver, body.report.model_dump(),
                             claims["sub"])
    return {"run_id": str(run.run_id), "device_model": run.device_model, "firmware_version": run.firmware_version,
            "driver": run.driver, "passed": run.passed, "schemes": sorted(run.schemes),
            "recorded_at": run.recorded_at.isoformat()}
