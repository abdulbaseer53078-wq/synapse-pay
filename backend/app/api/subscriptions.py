"""Merchant subscriptions (SaaS plans). Upgrading is a platform-admin action (registry:admin) until a billing
provider takes payment for plans: a merchant-callable upgrade would hand out PRO for free."""
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from app.api.auth import with_scope
from app.application.subscriptions import Subscription, SubscriptionService

router = APIRouter(prefix="/api/v1/subscriptions", tags=["subscriptions"])
_admin = with_scope("registry:admin")


class UpgradeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    merchant_id: UUID


def _service(request: Request) -> SubscriptionService:
    return request.app.state.subscriptions


def _view(s: Subscription) -> dict:
    return {"merchant_id": str(s.merchant_id), "tier": s.tier, "status": s.status,
            "current_period_end": s.current_period_end.isoformat() if s.current_period_end else None,
            "renewal_count": s.renewal_count}


@router.post("/upgrade")
def upgrade(body: UpgradeBody, claims: dict = Depends(_admin),
            service: SubscriptionService = Depends(_service)) -> dict:
    """Moves the merchant to an active PRO period. Safe to retry: an active PRO merchant is returned unchanged."""
    return _view(service.upgrade_to_pro(body.merchant_id, actor_id=claims["sub"]))


@router.post("/renew")
def renew(body: UpgradeBody, claims: dict = Depends(with_scope("billing:webhook")),
          service: SubscriptionService = Depends(_service)) -> dict:
    """Extends an active paid period by 30 days. Safe to retry: see SubscriptionService.renew_subscription."""
    return _view(service.renew_subscription(body.merchant_id, actor_id=claims["sub"]))
