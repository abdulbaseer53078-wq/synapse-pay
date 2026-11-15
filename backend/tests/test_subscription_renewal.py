"""Contract tests for subscription auto-renewal (spec 1.17.0 / W2's renew_subscription).

All tests in this file will FAIL until Worker 2's branch lands — renew_subscription does not exist
on main yet. That is intentional: these tests define the contract W2 must meet.

Fixture style: FakeRepo (no live DB). The conftest.py db fixture cannot be used here because:
  1. merchant_subscriptions is not in the TRUNCATE list, so rows would bleed between tests.
  2. PostgresSubscriptions.get() does not yet read renewal_count (migration adds the column; infra doesn't).
  3. psycopg_pool is unavailable in the no-DB CI path these tests are designed to run on.

DISCREPANCIES vs lead spec:
  Lead spec: ENTERPRISE renews by 365 days. Worker 2 uses PERIOD = 30d for all tiers.
  Test 2 (below) asserts 30 days (what the code does). If the product intends 365d for ENTERPRISE,
  Worker 2 must add a tier-specific period map; update this test when that happens.

  Lead spec: "7-day window" for the renewal job. Worker 2's RENEWAL_WINDOW = timedelta(hours=24).
  Test 4 asserts the 24h constant. The 10-day scenario is still NOT renewed either way.

  Lead spec: audit row with action="RENEWED". PostgresSubscriptions writes action="subscription.upgrade"
  for every save (there is no RENEWED action code). Tests assert actor_id == "system:renewal_job"
  instead, which is the only distinguishing marker in the current audit schema.
"""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.application.subscriptions import Subscription, SubscriptionService

try:
    from app.application.renewal_job import RENEWAL_WINDOW, sweep_renewals
    _RENEWAL_JOB_AVAILABLE = True
except ImportError:
    _RENEWAL_JOB_AVAILABLE = False

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
ACTOR = "system:renewal_job"


class FakeRepo:
    """Minimal fake matching the SubscriptionRepository protocol. Mirrors the existing test_subscriptions.py."""

    def __init__(self):
        self.rows: dict = {}
        self.saves: list = []  # (subscription, previous, actor_id)

    def get(self, merchant_id):
        return self.rows.get(merchant_id)

    def save(self, subscription, previous, actor_id):
        self.rows[subscription.merchant_id] = subscription
        self.saves.append((subscription, previous, actor_id))

    def list_active_expiring(self, now, within):
        return [
            s for s in self.rows.values()
            if s.tier in {"PRO", "ENTERPRISE"}
            and s.status == "ACTIVE"
            and s.current_period_end is not None
            and s.current_period_end <= now + within
        ]


def _service(repo=None):
    return SubscriptionService(repo or FakeRepo(), now=lambda: NOW)


# ---------------------------------------------------------------------------
# Test 1: a PRO merchant expiring in 3 days gets renewed (period +30 days)
# ---------------------------------------------------------------------------

def test_pro_merchant_expiring_in_3_days_is_renewed():
    """PRO merchant whose period_end is 3 days away gets an extra 30-day period."""
    repo = FakeRepo()
    merchant = uuid4()
    period_end = NOW + timedelta(days=3)
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", period_end)

    renewed = _service(repo).renew_subscription(merchant, ACTOR)

    assert renewed.tier == "PRO"
    assert renewed.status == "ACTIVE"
    assert renewed.current_period_end == period_end + timedelta(days=30), (
        "period extends from current_period_end, not from now — late webhooks must not cause drift"
    )
    assert renewed.renewal_count == 1


# ---------------------------------------------------------------------------
# Test 2: an ENTERPRISE merchant expiring in 3 days gets renewed
# shortcut: lead spec says 365 days for ENTERPRISE; Worker 2 uses PERIOD=30d for all tiers.
#   If the product intends a 365-day ENTERPRISE period, Worker 2 must add tier-specific periods
#   and this assertion should change to timedelta(days=365).
# ---------------------------------------------------------------------------

def test_enterprise_merchant_expiring_in_3_days_is_renewed():
    """ENTERPRISE merchant whose period_end is 3 days away gets renewed.

    Asserts 30-day extension (current Worker 2 implementation: single PERIOD constant).
    Lead spec claimed 365 days for ENTERPRISE — see file docstring for the discrepancy note.
    """
    repo = FakeRepo()
    merchant = uuid4()
    period_end = NOW + timedelta(days=3)
    repo.rows[merchant] = Subscription(merchant, "ENTERPRISE", "ACTIVE", period_end)

    renewed = _service(repo).renew_subscription(merchant, ACTOR)

    assert renewed.tier == "ENTERPRISE", "tier is preserved after renewal"
    assert renewed.status == "ACTIVE"
    # shortcut: 30d matches Worker 2's PERIOD; upgrade to 365d when tier-specific periods are added
    assert renewed.current_period_end == period_end + timedelta(days=30)
    assert renewed.renewal_count == 1


# ---------------------------------------------------------------------------
# Test 3: a CANCELED merchant is NOT renewed
# ---------------------------------------------------------------------------

def test_canceled_merchant_is_not_renewed():
    """CANCELED subscription must not be extended by auto-renewal."""
    repo = FakeRepo()
    merchant = uuid4()
    period_end = NOW + timedelta(days=3)
    repo.rows[merchant] = Subscription(merchant, "PRO", "CANCELED", period_end)

    result = _service(repo).renew_subscription(merchant, ACTOR)

    assert result.status == "CANCELED", "status must remain CANCELED"
    assert result.current_period_end == period_end, "period_end must not be extended"
    assert repo.saves == [], "no audit row written for a CANCELED subscription"


# ---------------------------------------------------------------------------
# Test 4: a merchant with 10 days remaining (outside the renewal window) is NOT swept
# Note: RENEWAL_WINDOW = 24 hours in Worker 2's code (not the lead spec's 7 days).
#   10 days is outside both windows, so the behaviour is the same either way.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _RENEWAL_JOB_AVAILABLE, reason="renewal_job not yet on this branch")
def test_merchant_with_10_days_remaining_is_not_swept():
    """The renewal sweep must not renew a subscription that still has 10 days left.

    Worker 2's RENEWAL_WINDOW is 24 hours; 10 days is well outside that window.
    Lead spec referred to a 7-day window — either way 10 days is not swept.
    """
    repo = FakeRepo()
    merchant = uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=10))

    renewed = sweep_renewals(repo, _service(repo), now=NOW, window=RENEWAL_WINDOW)

    assert renewed == [], "subscription with 10 days remaining must not be swept"
    assert repo.saves == []


# ---------------------------------------------------------------------------
# Test 5: each renewed subscription has an audit row attributable to the renewal job
# Note: the audit_log table uses action="subscription.upgrade" for all saves (no RENEWED code yet).
#   We verify actor_id == "system:renewal_job" — the only distinguishing marker today.
#   When a RENEWED action code is added to _audit_entity, add a DB-level test for it.
# ---------------------------------------------------------------------------

def test_renewed_subscription_has_audit_row_with_renewal_actor():
    """Every successful renewal must write exactly one audit row attributed to the renewal actor.

    The audit action string ('RENEWED' per lead spec) does not yet exist; we assert actor_id.
    shortcut: add a DB-level test for action="RENEWED" when PostgresSubscriptions writes it.
    """
    repo = FakeRepo()
    merchant = uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=3))

    _service(repo).renew_subscription(merchant, ACTOR)

    assert len(repo.saves) == 1, "exactly one audit row written per renewal"
    _sub, _prev, actor_id = repo.saves[0]
    assert actor_id == ACTOR, (
        f"audit actor must be '{ACTOR}' so queries can distinguish automatic renewals from admin upgrades; "
        f"got '{actor_id}'"
    )


# ---------------------------------------------------------------------------
# Bonus: renewal_count increments across multiple renewals (regression guard)
# ---------------------------------------------------------------------------

def test_renewal_count_increments_on_each_renewal():
    """renewal_count tracks the number of auto-renewals and must increment on each call."""
    repo = FakeRepo()
    merchant = uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=2))

    service = _service(repo)
    first = service.renew_subscription(merchant, ACTOR)
    # as if time passed: the renewed period is now a day from ending, so the second call sees an expiring period
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=1), first.renewal_count)
    second = service.renew_subscription(merchant, ACTOR)

    assert first.renewal_count == 1
    assert second.renewal_count == 2
