"""HTTP client for the card service (card-service/, Rust), which holds the HSM and the acquirer connection.

The request carries encrypted card data only; the answer carries the outcome and a masked card.
"""
import httpx

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
            "pin_block": request.pin_block,
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
                          card_bin=data["card_bin"], card_last4=data["card_last4"])

    def close(self) -> None:
        self.client.close()
