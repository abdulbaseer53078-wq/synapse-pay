"""The certification registry's admin API (Step 26): platform admins (registry:admin) record what each scheme
certified. Every change is audited and reaches every API process's in-memory matrix before the next payment."""
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.api.auth import with_scope
from app.application.certification import CertificationAdmin
from app.domain.certification import Certification

router = APIRouter(tags=["certification registry"])
_admin = with_scope("registry:admin")

Scheme = Literal["VISA", "MASTERCARD", "RUPAY", "AMEX", "NPCI_UPI"]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateCertificationBody(_Body):
    device_model: str = Field(min_length=1, max_length=64)
    firmware_version: str = Field(min_length=1, max_length=32, description="Exact version: no wildcards or ranges")
    scheme: Scheme
    acquirer_id: str = Field(min_length=1, max_length=64)
    certificate_number: str = Field(min_length=1, max_length=128)
    valid_from: datetime | None = None
    valid_until: datetime

    @model_validator(mode="after")
    def _dates(self):
        for value in (self.valid_from, self.valid_until):
            if value is not None and value.tzinfo is None:
                raise ValueError("timestamps need a time zone")
        if self.valid_until <= (self.valid_from or datetime.now(UTC)):
            raise ValueError("valid_until must be after valid_from (or now)")
        return self


class UpdateCertificationBody(_Body):
    status: Literal["ACTIVE", "SUSPENDED"] | None = None
    valid_until: datetime | None = None


class MinimumFirmwareBody(_Body):
    minimum_secure_firmware: str = Field(min_length=1, max_length=32)


def _service(request: Request) -> CertificationAdmin:
    return request.app.state.certifications


def _view(c: Certification) -> dict:
    return {"certification_id": str(c.certification_id), "device_model": c.device_model,
            "firmware_version": c.firmware_version, "scheme": c.scheme, "acquirer_id": c.acquirer_id,
            "certificate_number": c.certificate_number, "status": c.status,
            "valid_from": c.valid_from.isoformat(), "valid_until": c.valid_until.isoformat()}


@router.post("/api/v1/certifications", status_code=201)
def create_certification(body: CreateCertificationBody, service: CertificationAdmin = Depends(_service),
                         claims: dict = Depends(_admin)) -> dict:
    cert = Certification(uuid4(), body.device_model, body.firmware_version, body.scheme, body.acquirer_id,
                         body.certificate_number, "ACTIVE", body.valid_from or datetime.now(UTC), body.valid_until)
    return _view(service.create(cert, claims["sub"]))


@router.patch("/api/v1/certifications/{certification_id}")
def update_certification(certification_id: UUID, body: UpdateCertificationBody,
                         service: CertificationAdmin = Depends(_service), claims: dict = Depends(_admin)) -> dict:
    return _view(service.update(certification_id, body.status, body.valid_until, claims["sub"]))


# shortcut: unpaginated; the matrix is a few hundred rows per model. Add keyset pagination if it grows.
@router.get("/api/v1/certifications")
def list_certifications(device_model: str | None = Query(default=None, max_length=64),
                        firmware_version: str | None = Query(default=None, max_length=32),
                        service: CertificationAdmin = Depends(_service), _: dict = Depends(_admin)) -> dict:
    return {"certifications": [_view(c) for c in service.list(device_model, firmware_version)]}


@router.put("/api/v1/device-models/{device_model}/minimum-firmware")
def set_minimum_firmware(device_model: str, body: MinimumFirmwareBody, service: CertificationAdmin = Depends(_service),
                         claims: dict = Depends(_admin)) -> dict:
    service.set_minimum(device_model, body.minimum_secure_firmware, claims["sub"])
    return {"device_model": device_model, "minimum_secure_firmware": body.minimum_secure_firmware}
