"""HTTP client for a UPI PSP. `mock-psp/mock_psp.py` speaks the same shapes locally.

Two failure kinds, and the distinction is the whole point:

* `PspUnavailable` — we could not ask (transport, timeout, 5xx). Nothing is known, so the transaction must not
  be marked failed; it is retryable and the outcome may still arrive by webhook.
* `PspDeclined` — the PSP answered and refused (4xx). That is an outcome with a code and a category, so it
  becomes a FAILED transaction, not an exception the engine has to interpret.
"""
import httpx

DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=1.0)


class PspUnavailable(Exception):
    def __init__(self, message: str = "the UPI PSP is unavailable; nothing was sent"):
        super().__init__(message)
        self.message = message


class PspDeclined(Exception):
    """A refusal from the PSP: a business outcome, carrying the spec's error_category."""

    def __init__(self, code: str, message: str, category: str = "HARD_DECLINE", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = category
        self.retryable = retryable


class HttpUpiPsp:
    def __init__(self, base_url: str, timeout: httpx.Timeout = DEFAULT_TIMEOUT):
        self.client = httpx.Client(base_url=base_url, timeout=timeout)

    def close(self) -> None:
        self.client.close()

    def validate_vpa(self, vpa: str) -> dict:
        """{vpa, name, status}. Declines (404) when no account is registered to the VPA."""
        return self._call("POST", "/psp/v1/validate-vpa", {"vpa": vpa})

    def collect(self, merchant_transaction_id: str, amount: int, currency: str, vpa: str,
                flow_type: str = "COLLECT") -> dict:
        return self._call("POST", "/psp/v1/collect", {
            "merchant_transaction_id": merchant_transaction_id, "amount": amount, "currency": currency,
            "vpa": vpa, "flow_type": flow_type})

    def status(self, psp_transaction_id: str) -> dict:
        return self._call("GET", f"/psp/v1/status/{psp_transaction_id}")

    def refund(self, psp_transaction_id: str, amount: int) -> dict:
        return self._call("POST", "/psp/v1/refund",
                          {"psp_transaction_id": psp_transaction_id, "amount": amount})

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            response = self.client.request(method, path, json=body)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise PspUnavailable(f"the UPI PSP did not answer ({type(exc).__name__}); nothing was sent") from exc
        if response.status_code >= 500:
            raise PspUnavailable(f"the UPI PSP answered {response.status_code}; nothing was confirmed")
        if response.status_code >= 400:
            raise self._declined(response)
        try:
            return response.json()
        except ValueError as exc:
            raise PspUnavailable("the UPI PSP answered something that is not JSON") from exc

    @staticmethod
    def _declined(response: httpx.Response) -> PspDeclined:
        try:
            error = response.json().get("error") or {}
        except ValueError:
            error = {}
        code = error.get("code") or f"UPI_HTTP_{response.status_code}"
        message = error.get("message") or f"the UPI PSP rejected the request ({response.status_code})"
        if response.status_code == 429:
            # Rate limited: the same request may well work later.
            return PspDeclined(code, message, "SOFT_DECLINE", retryable=True)
        return PspDeclined(code, message, "HARD_DECLINE", retryable=False)
