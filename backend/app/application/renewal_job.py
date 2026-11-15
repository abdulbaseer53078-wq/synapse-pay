"""Background sweep: renew active PRO/ENTERPRISE subscriptions before their period expires.

shortcut: not scheduled anywhere, because renewing takes no payment yet; when a BillingProvider exists, charge
first, renew on success, and add the sweep to app/jobs.py.
"""
import logging
from datetime import UTC, datetime, timedelta

from app.application.subscriptions import Subscription, SubscriptionRepository, SubscriptionService

RENEWAL_ACTOR = "system:renewal_job"
RENEWAL_WINDOW = timedelta(hours=24)  # renew subscriptions expiring within this window

logger = logging.getLogger(__name__)


def sweep_renewals(
    repo: SubscriptionRepository,
    service: SubscriptionService,
    *,
    now: datetime | None = None,
    window: timedelta = RENEWAL_WINDOW,
    actor_id: str = RENEWAL_ACTOR,
) -> list[Subscription]:
    """Renews every ACTIVE paid subscription expiring within `window` by one period and returns the renewed ones.
    A renewal that fails is logged and skipped, so one bad row doesn't stop the sweep."""
    now = now or datetime.now(UTC)
    renewed: list[Subscription] = []
    for sub in repo.list_active_expiring(now, within=window):
        try:
            result = service.renew_subscription(sub.merchant_id, actor_id)
        except Exception:
            logger.exception("renewal_sweep: failed to renew merchant=%s", sub.merchant_id)
            continue
        if result.renewal_count > sub.renewal_count:  # not a no-op
            renewed.append(result)
    return renewed
