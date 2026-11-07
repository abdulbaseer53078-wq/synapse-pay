# Step 8 — the payment method adapter interface

The transaction engine used to know it was processing cards. Now it knows one thing: the request names a
method, an adapter is registered for that name, and every adapter answers the same six calls. Adding UPI is a
new file and one line in the composition root — `TransactionService` is not touched, and there is no `if
method == ...` anywhere in the engine.

## The contract

`backend/app/application/methods.py`. A `Protocol`, so adapters are structurally typed and tests can pass
plain objects:

```python
class PaymentMethodAdapter(Protocol):
    method: str                                            # "CARD"

    def validate(self, details: dict) -> dict: ...         # normalise method_details, or raise
    def initiate(self, request: MethodRequest) -> MethodResult: ...
    def capture(self, transaction_id: UUID, amount: int) -> MethodResult: ...
    def refund(self, transaction_id: UUID, amount: int) -> MethodResult: ...
    def status(self, transaction_id: UUID) -> MethodResult: ...
    def handle_webhook(self, payload: dict) -> MethodResult: ...
```

`handle_webhook` is in the contract from day one even though CARD has nothing to do with it: UPI and wallets
answer the API before the network settles, so a method whose adapter cannot receive a callback is incomplete.
CARD raises `UnsupportedOperation` for it rather than pretending.

### The shared error vocabulary

An adapter never raises HTTP-shaped errors. It raises four things the engine understands:

| Adapter raises | Engine does | Client sees |
| :--- | :--- | :--- |
| `AdapterUnavailable` | transaction FAILED, key freed, not stored | 503 `SYSTEM_ERROR`, retryable |
| `InvalidMethodDetails` | transaction FAILED, not stored | 400 `VALIDATION_ERROR`, names the field |
| `OutcomeUnknown` | transaction PENDING, **stored** | 201, PENDING — reconciliation settles it |
| `MethodNotSupported` (registry) | nothing happens at all | 422 `INVALID_REQUEST` |

`OutcomeUnknown` is deliberately not a `RegistrationError`: it is not a failure, and it must never be rendered
as one.

### MethodResult

`status`, `method_reference`, `auth_code`, `error`, `reversal`, `bin`, `last4`. The network's vocabulary —
ISO 8583 response codes, a PSP's JSON — is translated into this by the adapter, so the engine only ever deals
in transaction statuses.

## The card adapter

`backend/app/infrastructure/methods/card.py`. It is a translation layer, not new behaviour: everything in it
was already inside `TransactionService.create` before this step. It owns `CardDetails` (validation, with
`extra="forbid"`), the acquirer's terminal/merchant ids (DE 41/42), and the translation of the card service's
exceptions into the shared four.

Moving `CardDetails` out of `api/transactions.py` is what removed the last `if body["payment_method"] == "CARD"`
from the HTTP layer: the endpoint now passes `method_details` through and the adapter decides what a valid one
looks like.

## Adding a method

```python
class UpiMethodAdapter:
    method = "UPI"

    def validate(self, details: dict) -> dict: ...      # needs a VPA
    def initiate(self, request: MethodRequest) -> MethodResult: ...
    # capture/refund/status/handle_webhook as the rail allows
```

Then, in `main.py`:

```python
methods = MethodRegistry([CardMethodAdapter(cards), UpiMethodAdapter(psp_client)])
```

Nothing else. `test_a_new_method_needs_no_engine_change` in `tests/test_methods.py` is that promise as an
executable assertion: it registers a made-up method and drives a payment through the real engine.

## What is and isn't built

| Contract call | CARD |
| :--- | :--- |
| `validate` | ✅ |
| `initiate` | ✅ (ISO 8583 via the card service) |
| `capture`, `refund`, `status` | ❌ `UnsupportedOperation` — these have no API yet |
| `handle_webhook` | ❌ card authorization is synchronous |

The interface is complete; the card rail is not. That is the honest state: defining six calls and
implementing two is better than defining two and discovering the other four in Step 10.

## Tests

```bash
cd backend && pytest tests/test_methods.py
```

20 cases, no database: registry lookup and duplicate detection, unknown method rejected before anything is
claimed, a second method working through the unchanged engine, the three failure translations, validation
before the idempotency claim, field-path messages that never echo card data, and every unbuilt call raising
`UnsupportedOperation`.

`tests/test_transactions.py` still covers the card path end to end (it needs Postgres).

## Follow-ups

- **Payment intents** (`/v1/payment_intents/{id}/confirm`) still call the card processor directly through
  `CheckoutCardProcessor`. They are a card-only checkout flow today; they should move onto the card adapter
  when a second rail can complete a checkout.
- **API-level shape**: `method_details` is still typed as a free object in the OpenAPI envelope, with the
  per-method `if/then` branches describing it. The adapter validates the same rules at runtime; keeping both
  is deliberate (clients get the contract, the server gets the enforcement).
- Capture, refund and status exist in the interface because the transaction states do. They need API endpoints
  and network support before the card adapter can implement them.
