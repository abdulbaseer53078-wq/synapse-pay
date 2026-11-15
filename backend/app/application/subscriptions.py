"""SaaS subscriptions: which plan a merchant is on, and what it entitles them to.

A merchant with no subscription row is on FREE. Offline payments through an edge node need a paid plan (PRO or
ENTERPRISE) that is ACTIVE and whose period hasn't ended; PAST_DUE and CANCELED don't count.

Upgrades are a platform-admin action for now: nothing takes payment for a plan yet.
shortcut: no billing provider; when one exists, put it behind a BillingProvider interface and let its webhook call
`upgrade_to_pro` instead of an admin.
"""
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from app.application.registration import Conflict

PAID_TIERS = frozenset({"PRO", "ENTERPRISE"})
PERIOD = timedelta(days=30)


@dataclass(frozen=True)
class Subscription:
    merchant_id: UUID
    tier: str  # FREE | PRO | ENTERPRISE
    status: str  # ACTIVE | PAST_DUE | CANCELED
    current_period_end: datetime | None  # None: the implicit FREE plan of a merchant with no row
    renewal_count: int = 0  # how many times the paid period was renewed

    def entitles_offline(self, now: datetime) -> bool:
        return (self.tier in PAID_TIERS and self.status == "ACTIVE"
                and self.current_period_end is not None and self.current_period_end > now)


class SubscriptionRepository(Protocol):
    def get(self, merchant_id: UUID) -> Subscription | None: ...

    def save(self, subscription: Subscription, previous: Subscription, actor_id: str) -> None:
        """Upserts the row and audits the change in one transaction. Raises UnknownReference for an unknown
        merchant."""

    def list_active_expiring(self, now: datetime, within: timedelta) -> list[Subscription]:
        """ACTIVE paid subscriptions whose period ends at or before now + within."""


class SubscriptionService:
    def __init__(self, repo: SubscriptionRepository, now: Callable[[], datetime] | None = None):
        self.repo = repo
        self.now = now or (lambda: datetime.now(UTC))

    def current(self, merchant_id: UUID) -> Subscription:
        return self.repo.get(merchant_id) or Subscription(merchant_id, "FREE", "ACTIVE", None)

    def has_paid_plan(self, merchant_id: UUID) -> bool:
        return self.current(merchant_id).entitles_offline(self.now())

    def upgrade_to_pro(self, merchant_id: UUID, actor_id: str) -> Subscription:
        """Idempotent by state: a merchant already on an active PRO period is returned unchanged, so a retried call
        neither extends the period nor writes a second audit row."""
        now = self.now()
        current = self.current(merchant_id)
        if current.tier == "PRO" and current.entitles_offline(now):
            return current
        if current.tier == "ENTERPRISE" and current.status == "ACTIVE":
            raise Conflict("merchant is on ENTERPRISE; moving to PRO would be a downgrade", code="SUBSCRIPTION_CONFLICT")
        upgraded = Subscription(merchant_id, "PRO", "ACTIVE", now + PERIOD)
        self.repo.save(upgraded, current, actor_id)
        return upgraded

    def renew_subscription(self, merchant_id: UUID, actor_id: str) -> Subscription:
        """Extends an ACTIVE paid period by one PERIOD, keeping the tier. Idempotent by state: a merchant with more
        than one period still ahead is returned unchanged, so a duplicate webhook can't extend twice. FREE, PAST_DUE
        and CANCELED merchants are returned unchanged too, so a batch needs no filtering first.
        shortcut: takes no payment; when a BillingProvider exists, charge first and call this only on success."""
        now = self.now()
        current = self.current(merchant_id)
        end = current.current_period_end
        if current.tier not in PAID_TIERS or current.status != "ACTIVE" or end is None or end > now + PERIOD:
            return current
        # From the period's end, so a late webhook causes no drift; from now if it already lapsed, so the merchant
        # isn't billed for days it had no plan.
        renewed = replace(current, current_period_end=max(end, now) + PERIOD, renewal_count=current.renewal_count + 1)
        self.repo.save(renewed, current, actor_id)
        return renewed
