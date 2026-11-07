"""HTTP client for the card service (card-service/, Rust), which holds the HSM and the acquirer connection.

The request carries encrypted card data only; the answer carries the outcome and a masked card.
"""
import httpx

from uuid import UUID

from app.application.payment_intents import Authentication
from app.application.transactions import (BadCardData, CardOutcomeUnknown, CardRequest, CardResult,
                                          CardServiceUnavailable)

# The card service gives the host 1.5 s, then up to 3 reversal attempts of 2 s each. Past this, the
# outcome is unknown.
DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=1.0)


class HttpCardProcessor:
    def __init__(self, base_url: str, timeout: httpx.Timeout = DEFAULT_TIMEOUT):
        self.client = httpx.Client(base_url=base_url, timeout=timeout)

    def process(self, request: CardRequest) -> CardResult:
        body = {
            "transaction_id": str(request.transaction_id), "kind": request.kind, "amount": request.amount,
            "currency": request.currency, "acquirer_terminal_id": request.acquirer_terminal_id,
            "acquirer_merchant_id": request.acquirer_merchant_id,
            "encrypted_card_data": request.encrypted_card_data, "card_expiry": request.card_expiry,
            "pin_block": request.pin_block, "host_hint": list(request.host_hint),
        }
        try:
            response = self.client.post("/card/transactions", json=body)
        except httpx.ConnectError as e:
            raise CardServiceUnavailable("the card service is unavailable; nothing was charged") from e
        except httpx.TimeoutException as e:
            raise CardOutcomeUnknown() from e
        except httpx.TransportError as e:
            raise CardOutcomeUnknown() from e
        if response.status_code in (400, 422):
            raise BadCardData(response.json().get("message", "the card data couldn't be used"))
        if response.status_code != 200:
            # The service answered but failed: whether the host was reached is unknown.
            raise CardOutcomeUnknown()
        data = response.json()
        return CardResult(status=data["status"], method_reference=data.get("method_reference"),
                          auth_code=data.get("auth_code"), error=data.get("error"), reversal=data["reversal"],
                          card_bin=data["card_bin"], card_last4=data["card_last4"],
                          host_used=data.get("host_used"))

    def _post(self, path: str, body: dict) -> dict:
        try:
            response = self.client.post(path, json=body)
        except httpx.ConnectError as e:
            raise CardServiceUnavailable("the card service is unavailable") from e
        except httpx.TransportError as e:
            raise CardServiceUnavailable("the card service didn't answer") from e
        if response.status_code in (400, 422):
            raise BadCardData(response.json().get("message", "the card data couldn't be used"))
        if response.status_code != 200:
            raise CardServiceUnavailable(f"card service answered HTTP {response.status_code}")
        return response.json()

    def authenticate(self, transaction_id: UUID, encrypted_card_data: str, encrypted_cvv: str | None, amount: int,
                     currency: str) -> Authentication:
        """3-D Secure. Never charges anything, so every failure here is safe to retry."""
        data = self._post("/card/authenticate", {"transaction_id": str(transaction_id), "amount": amount,
                                                 "currency": currency, "encrypted_card_data": encrypted_card_data,
                                                 "encrypted_cvv": encrypted_cvv})
        return Authentication(data["three_ds"], data["card_bin"], data["card_last4"])

    def checkout_key(self) -> dict:
        try:
            response = self.client.get("/card/checkout-key")
        except httpx.TransportError as e:
            raise CardServiceUnavailable("the card service is unavailable") from e
        if response.status_code != 200:
            raise CardServiceUnavailable("the card service has no checkout key")
        return response.json()

    def close(self) -> None:
        self.client.close()
