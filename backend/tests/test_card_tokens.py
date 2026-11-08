"""Step 29, API side: merchants save a card and pay with its token; the backend only ever relays the request to
card-service's vault and never holds the number. The vault itself is tested in card-service/tests/vault.rs."""
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.application.transactions import CardResult
from app.infrastructure.methods.card import CardDetails
from app.main import create_app
from card_sim import encrypted_card

TOKEN = "tok_" + "ab" * 16


class VaultCards:
    """card-service with a vault: saves cards per merchant and answers payments made with a token."""

    def __init__(self):
        self.saved: dict[tuple[str, str], str] = {}
        self.received = []

    def tokenize(self, merchant_id, encrypted_card_data, card_expiry, card_network, customer_ref):
        self.saved[(str(merchant_id), TOKEN)] = card_expiry
        return {"token": TOKEN, "token_type": "PAN", "card_bin": "411111", "card_last4": "1111",
                "card_network": card_network, "card_expiry": card_expiry, "customer_ref": customer_ref,
                "revoked": False}

    def revoke_token(self, merchant_id, token):
        return self.saved.pop((str(merchant_id), token), None) is not None

    def process(self, request):
        self.received.append(request)
        return CardResult(status="CAPTURED", method_reference="ref", auth_code="A1", error=None,
                          reversal="NOT_NEEDED", card_bin="411111", card_last4="1111", host_used=None)


@pytest.fixture
def cards():
    return VaultCards()


@pytest.fixture
def shop(settings, db, cards):
    with TestClient(create_app(settings, cards=cards)) as client:
        merchant = uuid4()
        db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant,))
        key = client.app.state.api_keys.create(merchant)
        yield client, merchant, {"Authorization": f"Bearer {key}"}


def test_card_details_take_exactly_one_card():
    CardDetails(card_token=TOKEN, card_network="VISA")
    CardDetails(encrypted_card_data="sp1.a.b", card_expiry="08/28", card_network="VISA")
    for bad in ({"card_network": "VISA"},
                {"card_token": TOKEN, "encrypted_card_data": "sp1.a.b", "card_expiry": "08/28", "card_network": "VISA"},
                {"encrypted_card_data": "sp1.a.b", "card_network": "VISA"},
                {"card_token": "tok_short", "card_network": "VISA"}):
        with pytest.raises(ValueError):
            CardDetails(**bad)


def test_save_and_delete_a_card(shop, cards):
    client, merchant, auth = shop
    body = {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA",
            "customer_ref": "cust_42"}
    r = client.post("/api/v1/card-tokens", headers=auth, json=body)
    assert r.status_code == 201, r.text
    assert r.json() == {"token": TOKEN, "token_type": "PAN", "card_bin": "411111", "card_last4": "1111",
                        "card_network": "VISA", "card_expiry": "08/28", "customer_ref": "cust_42"}
    assert client.post("/api/v1/card-tokens", json=body).status_code == 401, "secret key only"

    assert client.delete(f"/api/v1/card-tokens/{TOKEN}", headers=auth).status_code == 204
    gone = client.delete(f"/api/v1/card-tokens/{TOKEN}", headers=auth)
    assert gone.status_code == 404 and gone.json()["error_code"] == "CARD_TOKEN_NOT_FOUND"
    assert client.delete("/api/v1/card-tokens/not-a-token", headers=auth).status_code == 404


def test_the_card_adapter_sends_the_token_and_the_merchant_to_card_service(cards):
    from app.application.methods import MethodRequest
    from app.infrastructure.methods.card import CardMethodAdapter

    merchant = uuid4()
    request = MethodRequest(transaction_id=uuid4(), amount=50_000, currency="INR", capture_mode="AUTO",
                            merchant_id=merchant, terminal_id=uuid4(),
                            details={"card_token": TOKEN, "card_network": "VISA"}, customer_ref=None, metadata={})
    result = CardMethodAdapter(cards).initiate(request)
    assert result.status == "CAPTURED"
    [sent] = cards.received
    assert (sent.card_token, sent.merchant_id, sent.encrypted_card_data, sent.card_expiry) == (TOKEN, str(merchant),
                                                                                            "", "")
    assert UUID(sent.merchant_id) == merchant


def test_the_card_service_client_sends_card_token_and_merchant_id():
    import httpx

    from app.application.transactions import CardRequest
    from app.infrastructure.card_service_client import HttpCardProcessor

    seen = {}

    def card_service(request):
        import json
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"status": "CAPTURED", "reversal": "NOT_NEEDED",
                                         "card_bin": "411111", "card_last4": "1111"})

    processor = HttpCardProcessor("http://card-service")
    processor.client = httpx.Client(base_url="http://card-service", transport=httpx.MockTransport(card_service))
    processor.process(CardRequest(transaction_id=uuid4(), kind="PURCHASE", amount=100, currency="INR",
                                  acquirer_terminal_id="T1", acquirer_merchant_id="M1", card_token=TOKEN,
                                  merchant_id="m_1"))
    assert (seen["card_token"], seen["merchant_id"], seen["encrypted_card_data"]) == (TOKEN, "m_1", "")
