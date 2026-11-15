"""SaaS subscriptions: the upgrade endpoint, the plan rules, the offline gate on edge rules, and auto-renewal.
No database: the repository is faked here; the Postgres repository is covered through the edge fixtures in
test_edge_rules.py."""
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import errors as errors_module
from app.api import subscriptions as subscriptions_api
from app.application.edge import EdgeNode, EdgeService, OfflineLimits
from app.application.registration import Conflict, UnknownReference
from app.application.subscriptions import Subscription, SubscriptionService

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


class FakeRepo:
    def __init__(self, known=None):
        self.rows: dict = {}
        self.saves: list = []
        self.known = known  # merchant ids that exist; None: all

    def get(self, merchant_id):
        return self.rows.get(merchant_id)

    def save(self, subscription, previous, actor_id):
        if self.known is not None and subscription.merchant_id not in self.known:
            raise UnknownReference("merchant not found", code="MERCHANT_NOT_FOUND")
        self.rows[subscription.merchant_id] = subscription
        self.saves.append((subscription, previous, actor_id))

    def list_active_expiring(self, now, within):
        return [s for s in self.rows.values()
                if s.tier in {"PRO", "ENTERPRISE"} and s.status == "ACTIVE"
                and s.current_period_end is not None and s.current_period_end <= now + within]


def _service(repo=None):
    return SubscriptionService(repo or FakeRepo(), now=lambda: NOW)


# --- plan rules ------------------------------------------------------------------------------------------------

def test_a_merchant_without_a_subscription_is_free_and_not_entitled():
    service, merchant = _service(), uuid4()
    assert service.current(merchant).tier == "FREE"
    assert service.has_paid_plan(merchant) is False


@pytest.mark.parametrize("tier,status,ends_in,entitled", [
    ("PRO", "ACTIVE", timedelta(days=1), True),
    ("ENTERPRISE", "ACTIVE", timedelta(days=1), True),
    ("PRO", "PAST_DUE", timedelta(days=1), False),
    ("PRO", "CANCELED", timedelta(days=1), False),
    ("PRO", "ACTIVE", -timedelta(seconds=1), False),  # the period ended: not paid for any more
    ("FREE", "ACTIVE", timedelta(days=1), False),
])
def test_only_an_active_paid_period_entitles_offline(tier, status, ends_in, entitled):
    repo, merchant = FakeRepo(), uuid4()
    repo.rows[merchant] = Subscription(merchant, tier, status, NOW + ends_in)
    assert _service(repo).has_paid_plan(merchant) is entitled


def test_upgrade_starts_a_30_day_pro_period_and_is_audited_once_when_retried():
    repo, merchant = FakeRepo(), uuid4()
    service = _service(repo)

    first = service.upgrade_to_pro(merchant, actor_id="admin-1")
    again = service.upgrade_to_pro(merchant, actor_id="admin-1")

    assert (first.tier, first.status, first.current_period_end) == ("PRO", "ACTIVE", NOW + timedelta(days=30))
    assert again == first, "a retry neither extends the period"
    assert len(repo.saves) == 1, "nor writes a second change"
    assert repo.saves[0][1].tier == "FREE" and repo.saves[0][2] == "admin-1"


def test_a_lapsed_pro_merchant_can_be_upgraded_again():
    repo, merchant = FakeRepo(), uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "PAST_DUE", NOW - timedelta(days=3))
    assert _service(repo).upgrade_to_pro(merchant, "admin-1").status == "ACTIVE"


def test_upgrading_an_enterprise_merchant_to_pro_is_refused():
    repo, merchant = FakeRepo(), uuid4()
    repo.rows[merchant] = Subscription(merchant, "ENTERPRISE", "ACTIVE", NOW + timedelta(days=200))
    with pytest.raises(Conflict):
        _service(repo).upgrade_to_pro(merchant, "admin-1")
    assert repo.saves == []


# --- the endpoint ----------------------------------------------------------------------------------------------

@pytest.fixture
def api():
    key = ec.generate_private_key(ec.SECP256R1())
    app = FastAPI()
    app.state.jwt_public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    repo = FakeRepo()
    app.state.subscriptions = _service(repo)
    errors_module.install(app)
    app.include_router(subscriptions_api.router)
    return TestClient(app), key, repo


def _token(key, scope="registry:admin"):
    return {"Authorization": "Bearer " + jwt.encode(
        {"sub": "admin-ops-1", "scope": scope, "exp": int(time.time()) + 300}, key, "ES256")}


def test_an_admin_upgrades_a_merchant_to_pro(api):
    client, key, repo = api
    merchant = uuid4()
    r = client.post("/api/v1/subscriptions/upgrade", headers=_token(key), json={"merchant_id": str(merchant)})
    assert r.status_code == 200, r.text
    assert r.json() == {"merchant_id": str(merchant), "tier": "PRO", "status": "ACTIVE",
                        "current_period_end": (NOW + timedelta(days=30)).isoformat(), "renewal_count": 0}
    assert repo.saves[0][2] == "admin-ops-1", "the token subject is the audited actor"


@pytest.mark.parametrize("headers_for,status", [
    (lambda key: {}, 401),                                      # no token
    (lambda key: _token(key, scope="transactions:write"), 403),  # a merchant's token can't grant itself PRO
])
def test_only_platform_admins_can_upgrade(api, headers_for, status):
    client, key, repo = api
    r = client.post("/api/v1/subscriptions/upgrade", headers=headers_for(key), json={"merchant_id": str(uuid4())})
    assert r.status_code == status and repo.saves == []


def test_upgrade_errors_use_the_spec_error_shape(api):
    client, key, repo = api
    enterprise, unknown = uuid4(), uuid4()
    repo.rows[enterprise] = Subscription(enterprise, "ENTERPRISE", "ACTIVE", NOW + timedelta(days=200))
    repo.known = {enterprise}

    downgrade = client.post("/api/v1/subscriptions/upgrade", headers=_token(key), json={"merchant_id": str(enterprise)})
    missing = client.post("/api/v1/subscriptions/upgrade", headers=_token(key), json={"merchant_id": str(unknown)})
    extra = client.post("/api/v1/subscriptions/upgrade", headers=_token(key),
                        json={"merchant_id": str(unknown), "tier": "ENTERPRISE"})

    assert (downgrade.status_code, downgrade.json()["error_code"]) == (409, "SUBSCRIPTION_CONFLICT")
    assert (missing.status_code, missing.json()["error_code"]) == (422, "MERCHANT_NOT_FOUND")
    assert extra.status_code == 400, "the tier can't be chosen by the caller"


# --- the offline gate on edge rules ----------------------------------------------------------------------------

class FakeEdges:
    def __init__(self, node):
        self.node = node

    def get(self, edge_node_id):
        return self.node if edge_node_id == self.node.edge_node_id else None

    def active_terminals(self, merchant_id):
        return []


class FakeSigner:
    def sign(self, message):
        return b"sig"


def _rules(entitled):
    merchant = uuid4()
    node = EdgeNode(uuid4(), merchant, "ACTIVE", 3, OfflineLimits(200_000, 1_000_000, 4320))
    service = EdgeService(FakeEdges(node), ca=None, signer=FakeSigner(), routing_rules={}, now=lambda: NOW,
                          offline_entitled=lambda m: entitled and m == merchant)
    return service.rules(node.edge_node_id)


def test_a_paid_merchants_edge_gets_its_offline_limits():
    body = _rules(entitled=True)
    assert body["offline_limits"] == {"per_transaction": 200_000, "per_day": 1_000_000, "max_age_minutes": 4320}
    assert "subscription_required" not in body


def test_a_free_merchants_edge_gets_signed_rules_that_allow_no_offline_sale():
    # Not a 403: the edge syncs only after a successful rules fetch, so sales it already took must still go through.
    body = _rules(entitled=False)
    assert body["offline_limits"]["per_transaction"] == 0 and body["offline_limits"]["per_day"] == 0
    assert body["subscription_required"] == "SUBSCRIPTION_REQUIRED"
    assert body["signature"], "still a valid signed rule set, so the edge installs it and keeps syncing"

# --- auto-renewal (1.17.0) ---------------------------------------------------------------------------------

def test_renewal_extends_active_period_from_period_end_not_from_now():
    # Period must grow from current_period_end so late webhooks don't cause drift.
    repo, merchant = FakeRepo(), uuid4()
    end = NOW + timedelta(days=5)  # still active but nearly expired
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", end, 0)
    renewed = _service(repo).renew_subscription(merchant, "system:renewal_job")
    assert renewed.current_period_end == end + timedelta(days=30)
    assert renewed.renewal_count == 1


def test_renewal_increments_renewal_count_and_audits_with_system_actor():
    repo, merchant = FakeRepo(), uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=5), 2)
    _service(repo).renew_subscription(merchant, "system:renewal_job")
    sub, _prev, actor = repo.saves[0]
    assert sub.renewal_count == 3
    assert actor == "system:renewal_job", "audit queries can filter automatic vs admin renewals by actor"


def test_renewal_is_idempotent_when_more_than_one_period_remains():
    # A second renewal webhook must not double-extend the period.
    repo, merchant = FakeRepo(), uuid4()
    far_future = NOW + timedelta(days=35)  # more than one PERIOD from now
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", far_future, 1)
    result = _service(repo).renew_subscription(merchant, "system:renewal_job")
    assert result.current_period_end == far_future, "period unchanged"
    assert repo.saves == [], "no audit row written for a no-op renewal"


def test_renewal_of_enterprise_plan_preserves_tier():
    repo, merchant = FakeRepo(), uuid4()
    end = NOW + timedelta(days=3)
    repo.rows[merchant] = Subscription(merchant, "ENTERPRISE", "ACTIVE", end, 0)
    renewed = _service(repo).renew_subscription(merchant, "system:renewal_job")
    assert renewed.tier == "ENTERPRISE"
    assert renewed.current_period_end == end + timedelta(days=30)


@pytest.mark.parametrize("tier,status", [
    ("FREE", "ACTIVE"),
    ("PRO", "PAST_DUE"),
    ("PRO", "CANCELED"),
])
def test_renewal_of_ineligible_merchant_is_a_no_op(tier, status):
    # Ineligible merchants are returned unchanged, not errored: the renewal job can safely call
    # renew_subscription on a batch without filtering first.
    repo, merchant = FakeRepo(), uuid4()
    repo.rows[merchant] = Subscription(merchant, tier, status, NOW + timedelta(days=5), 0)
    result = _service(repo).renew_subscription(merchant, "system:renewal_job")
    assert result.tier == tier and result.status == status
    assert repo.saves == []


def test_renewal_of_a_free_merchant_with_no_row_is_a_no_op():
    service, merchant = _service(), uuid4()
    result = service.renew_subscription(merchant, "system:renewal_job")
    assert result.tier == "FREE"


def test_list_active_expiring_returns_only_subscriptions_due_within_window():
    repo = FakeRepo()
    due_soon, m1 = uuid4(), uuid4()
    not_due, m2 = uuid4(), uuid4()
    past_due, m3 = uuid4(), uuid4()
    repo.rows[m1] = Subscription(m1, "PRO", "ACTIVE", NOW + timedelta(days=2), 0)
    repo.rows[m2] = Subscription(m2, "PRO", "ACTIVE", NOW + timedelta(days=10), 0)
    repo.rows[m3] = Subscription(m3, "PRO", "PAST_DUE", NOW + timedelta(days=2), 0)
    expiring = repo.list_active_expiring(NOW, timedelta(days=5))
    assert len(expiring) == 1 and expiring[0].merchant_id == m1


# --- renewal endpoint (1.17.0) ---------------------------------------------------------------------------------
# These tests require Worker 2 to add POST /api/v1/subscriptions/renew to the router. They will FAIL until then.

@pytest.fixture
def renewal_api():
    key = ec.generate_private_key(ec.SECP256R1())
    app = FastAPI()
    app.state.jwt_public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    repo = FakeRepo()
    app.state.subscriptions = _service(repo)
    errors_module.install(app)
    app.include_router(subscriptions_api.router)
    return TestClient(app), key, repo


def _billing_token(key):
    return {"Authorization": "Bearer " + jwt.encode(
        {"sub": "billing-service", "scope": "billing:webhook", "exp": int(time.time()) + 300}, key, "ES256")}


def test_billing_webhook_renews_an_active_pro_merchant(renewal_api):
    client, key, repo = renewal_api
    merchant = uuid4()
    end = NOW + timedelta(days=5)
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", end, 0)
    r = client.post("/api/v1/subscriptions/renew", headers=_billing_token(key),
                    json={"merchant_id": str(merchant)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tier"] == "PRO" and body["status"] == "ACTIVE"
    assert body["renewal_count"] == 1
    assert repo.saves[0][2] == "billing-service", "JWT subject is the audited actor"


def test_billing_webhook_is_idempotent_for_already_current_period(renewal_api):
    client, key, repo = renewal_api
    merchant = uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=35), 1)
    r = client.post("/api/v1/subscriptions/renew", headers=_billing_token(key),
                    json={"merchant_id": str(merchant)})
    assert r.status_code == 200
    assert r.json()["renewal_count"] == 1, "no additional renewal written"
    assert repo.saves == []


def test_billing_webhook_requires_billing_webhook_scope(renewal_api):
    client, key, repo = renewal_api
    merchant = uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=5), 0)
    admin_headers = _token(key, scope="registry:admin")
    r = client.post("/api/v1/subscriptions/renew", headers=admin_headers,
                    json={"merchant_id": str(merchant)})
    assert r.status_code == 403 and repo.saves == []


def test_billing_webhook_returns_200_unchanged_for_free_merchant(renewal_api):
    client, key, repo = renewal_api
    merchant = uuid4()
    r = client.post("/api/v1/subscriptions/renew", headers=_billing_token(key),
                    json={"merchant_id": str(merchant)})
    assert r.status_code == 200
    assert r.json()["tier"] == "FREE" and r.json()["renewal_count"] == 0


def test_billing_webhook_response_includes_renewal_count(renewal_api):
    # Ensures the view/serialization layer exposes renewal_count (spec 1.17.0 makes it required).
    client, key, repo = renewal_api
    merchant = uuid4()
    repo.rows[merchant] = Subscription(merchant, "PRO", "ACTIVE", NOW + timedelta(days=5), 7)
    r = client.post("/api/v1/subscriptions/renew", headers=_billing_token(key),
                    json={"merchant_id": str(merchant)})
    assert r.status_code == 200
    assert "renewal_count" in r.json()

# --- renewal sweep job (1.17.0) -------------------------------------------------------------------------

from app.application.renewal_job import RENEWAL_WINDOW, sweep_renewals


def test_sweep_renews_subscriptions_expiring_within_window():
    repo = FakeRepo()
    m1, m2 = uuid4(), uuid4()
    repo.rows[m1] = Subscription(m1, "PRO", "ACTIVE", NOW + timedelta(hours=12), 0)  # due soon
    repo.rows[m2] = Subscription(m2, "PRO", "ACTIVE", NOW + timedelta(days=20), 0)   # not due
    service = _service(repo)
    renewed = sweep_renewals(repo, service, now=NOW, window=RENEWAL_WINDOW)
    assert len(renewed) == 1 and renewed[0].merchant_id == m1
    assert repo.rows[m1].renewal_count == 1
    assert repo.rows[m2].renewal_count == 0, "subscription not due was left alone"


def test_sweep_skips_and_logs_on_per_merchant_error(caplog):
    import logging
    repo = FakeRepo()
    m1 = uuid4()
    # Force save() to blow up for this merchant by marking it unknown
    repo.rows[m1] = Subscription(m1, "PRO", "ACTIVE", NOW + timedelta(hours=1), 0)
    repo.known = set()  # any save raises UnknownReference
    service = _service(repo)
    with caplog.at_level(logging.ERROR, logger="app.application.renewal_job"):
        renewed = sweep_renewals(repo, service, now=NOW)
    assert renewed == [], "failed renewal is not returned"
    assert any("failed to renew" in r.message for r in caplog.records)


def test_sweep_returns_empty_when_nothing_is_due():
    repo = FakeRepo()
    m = uuid4()
    repo.rows[m] = Subscription(m, "PRO", "ACTIVE", NOW + timedelta(days=25), 0)
    assert sweep_renewals(repo, _service(repo), now=NOW) == []
    assert repo.saves == []
