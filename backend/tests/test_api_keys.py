"""API key CRUD: create, list (prefix only), and revoke. No database — FakeApiKeys stands in."""
import hashlib
import secrets
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import api_keys as api_keys_api
from app.api import errors as errors_module
from app.api.auth import merchant_from_api_key


MERCHANT = uuid4()


class FakeKyc:
    """Stub: always returns APPROVED for the test merchant."""
    def status_for(self, merchant_id: UUID) -> str:
        return "APPROVED"


class FakeApiKeys:
    """In-memory stand-in; same interface as PostgresApiKeys."""

    def __init__(self):
        self._rows: dict[UUID, dict] = {}  # key_id -> row
        self._by_hash: dict[bytes, UUID] = {}

    def create(self, merchant_id: UUID, mode: str = "test") -> tuple[str, UUID]:
        key = f"sk_{mode}_{secrets.token_urlsafe(32)}"
        key_id = uuid4()
        now = datetime.now(UTC)
        self._rows[key_id] = {"key_id": key_id, "merchant_id": merchant_id, "prefix": key[:12],
                               "created_at": now, "revoked_at": None}
        self._by_hash[hashlib.sha256(key.encode()).digest()] = key_id
        return key, key_id

    def merchant_for(self, key: str) -> UUID | None:
        h = hashlib.sha256(key.encode()).digest()
        key_id = self._by_hash.get(h)
        if key_id is None:
            return None
        row = self._rows[key_id]
        return row["merchant_id"] if row["revoked_at"] is None else None

    def list_for_merchant(self, merchant_id: UUID) -> list[dict]:
        return [
            {"key_id": str(r["key_id"]), "prefix": r["prefix"],
             "created_at": r["created_at"].isoformat(),
             "revoked_at": r["revoked_at"].isoformat() if r["revoked_at"] else None}
            for r in sorted(self._rows.values(), key=lambda x: x["created_at"], reverse=True)
            if r["merchant_id"] == merchant_id
        ]

    def revoke(self, key_id: UUID, merchant_id: UUID) -> bool:
        row = self._rows.get(key_id)
        if row is None or row["merchant_id"] != merchant_id or row["revoked_at"] is not None:
            return False
        row["revoked_at"] = datetime.now(UTC)
        return True


@pytest.fixture
def app_and_key():
    fake = FakeApiKeys()
    # pre-create the key the test will use to authenticate
    seed_key, _ = fake.create(MERCHANT, mode="test")

    app = FastAPI()
    errors_module.install(app)
    app.include_router(api_keys_api.router)
    app.state.api_keys = fake
    app.state.kyc = FakeKyc()

    # override merchant_from_api_key to authenticate the seed key as MERCHANT
    app.dependency_overrides[merchant_from_api_key] = lambda: MERCHANT

    with TestClient(app) as client:
        yield client, fake, seed_key


def test_create_returns_plaintext_key_once(app_and_key):
    client, _, _ = app_and_key
    r = client.post("/api/v1/api-keys")
    assert r.status_code == 201
    body = r.json()
    assert body["secret_key"].startswith("sk_live_")
    assert body["prefix"] == body["secret_key"][:12]
    assert "key_id" in body


def test_list_shows_prefix_not_secret(app_and_key):
    client, fake, _ = app_and_key
    # create a key so there is something to list
    client.post("/api/v1/api-keys")
    r = client.get("/api/v1/api-keys")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    for item in items:
        assert "secret_key" not in item
        assert item["prefix"].startswith("sk_")
        assert len(item["prefix"]) == 12


def test_revoke_makes_key_inactive(app_and_key):
    client, fake, _ = app_and_key
    # create then revoke
    created = client.post("/api/v1/api-keys").json()
    key_id = created["key_id"]
    r = client.delete(f"/api/v1/api-keys/{key_id}")
    assert r.status_code == 204
    # key no longer authenticates
    assert fake.merchant_for(created["secret_key"]) is None


def test_revoke_is_idempotent(app_and_key):
    client, _, _ = app_and_key
    created = client.post("/api/v1/api-keys").json()
    key_id = created["key_id"]
    client.delete(f"/api/v1/api-keys/{key_id}")
    # second revoke also returns 204
    assert client.delete(f"/api/v1/api-keys/{key_id}").status_code == 204


def test_revoked_key_appears_in_list_with_revoked_at(app_and_key):
    client, _, _ = app_and_key
    created = client.post("/api/v1/api-keys").json()
    client.delete(f"/api/v1/api-keys/{created['key_id']}")
    items = client.get("/api/v1/api-keys").json()["items"]
    revoked = next(i for i in items if i["key_id"] == created["key_id"])
    assert revoked["revoked_at"] is not None
