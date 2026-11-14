"""SaaS subscriptions: the upgrade endpoint, the plan rules, and the offline gate on edge rules. No database: the
repository is faked here; the Postgres repository is covered through the edge fixtures in test_edge_rules.py."""
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
                        "current_period_end": (NOW + timedelta(days=30)).isoformat()}
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
