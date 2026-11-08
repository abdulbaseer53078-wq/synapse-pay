"""Edge nodes (Step 20). Registering one and changing its offline limits are platform-admin actions; fetching
rules is the edge itself, authenticated by its certificate at the gateway (which sets x-edge-node-id)."""
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import with_scope
from app.application.edge import EdgeService, OfflineLimits
from app.application.registration import Unauthenticated

router = APIRouter(tags=["edge"])


class OfflineLimitsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    per_transaction: int = Field(gt=0, description="Largest single offline payment, minor units")
    per_day: int = Field(gt=0, description="Most one terminal may take offline per day, minor units")
    max_age_minutes: int = Field(4320, gt=0, description="Oldest offline payment the cloud accepts at sync")

    def limits(self) -> OfflineLimits:
        return OfflineLimits(self.per_transaction, self.per_day, self.max_age_minutes)


class RegisterEdgeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    merchant_id: UUID
    csr_pem: str = Field(min_length=1, max_length=8192)
    offline_limits: OfflineLimitsBody


def _service(request: Request) -> EdgeService:
    return request.app.state.edge


@router.post("/api/v1/edge-nodes", status_code=201)
def register_edge(body: RegisterEdgeBody, service: EdgeService = Depends(_service),
                  claims: dict = Depends(with_scope("registry:admin"))) -> dict:
    edge = service.register(body.merchant_id, body.csr_pem, body.offline_limits.limits(), claims["sub"])
    return {"edge_node_id": str(edge.edge_node_id), "certificate_pem": edge.certificate_pem,
            "ca_certificate_pem": edge.ca_certificate_pem, "rules_public_key_pem": edge.rules_public_key_pem}


@router.put("/api/v1/edge-nodes/{edge_node_id}/offline-limits")
def update_edge_limits(edge_node_id: UUID, body: OfflineLimitsBody, service: EdgeService = Depends(_service),
                       claims: dict = Depends(with_scope("registry:admin"))) -> dict:
    version = service.update_limits(edge_node_id, body.limits(), claims["sub"])
    return {"edge_node_id": str(edge_node_id), "rules_version": version}


@router.get("/internal/v1/edge/rules", include_in_schema=False)
def edge_rules(x_edge_node_id: str | None = Header(default=None), service: EdgeService = Depends(_service)) -> dict:
    # Set by the gateway from the edge's certificate; trusting it is safe only behind the gateway, which strips
    # any client-supplied one (the same assumption x-terminal-id relies on).
    try:
        edge_node_id = UUID(x_edge_node_id or "")
    except ValueError:
        raise Unauthenticated("an edge node certificate is required")
    return service.rules(edge_node_id)
