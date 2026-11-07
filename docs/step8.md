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

## Base adapter (Task 8.3)

`backend/app/infrastructure/methods/base.py`. A rail implements **one** method:

```python
class UpiMethodAdapter(BaseMethodAdapter):
    method = "UPI"
    CAPABILITIES = UPI_CAPABILITIES
    DETAILS = UpiDetails                      # pydantic shape of method_details
    ERROR_MAP = {                             # the PSP's vocabulary → ours
        PspTimeout: lambda exc: AdapterUnavailable("the PSP did not answer; nothing was charged"),
        PspRejected: lambda exc: InvalidMethodDetails(exc.message),
    }

    def send(self, request: MethodRequest) -> MethodResult: ...   # the only code a rail must write
```

The base supplies `capabilities()`, `validate()` from `DETAILS`, the `initiate()` template, and defaults for
every call the rail has not built. The template does three things worth naming:

1. **Translation.** Anything unmapped from `send()` becomes `AdapterUnavailable` — retryable, "nothing was
   charged" — instead of escaping as a 500. An adapter bug should not look like a client error.
2. **Pass-through.** Errors already in the adapter vocabulary are not re-wrapped. This had to be an explicit
   list, not `RegistrationError`: the card service's own exceptions *are* `RegistrationError` subclasses, so
   catching the base class let them through untranslated. Caught by `test_card_failures_are_translated…`.
3. **Type safety.** `send()` returning anything but a `MethodResult` raises `TypeError` immediately — a bug,
   not a payment outcome.

### Two things the base class deliberately does not do

**Idempotency.** The engine claims the key in one transaction *before* the adapter is reached, and replays the
stored response on a repeat. An adapter doing it too would either double-charge or need database access an
adapter must not have. `test_idempotency_is_enforced_by_the_engine_not_the_adapter` drives two identical
requests through the real engine and asserts the adapter was called once.

**Audit.** `audit_log` is written by the repository inside the transaction that changes the state — that is
what makes the outbox ordering correct. An adapter runs outside that transaction, so an audit row written from
there could commit while the transaction rolled back, recording a payment that never happened. Adapters
describe what they did (`MethodResult` carries the network reference, BIN and last four); the engine persists it.

## Adding a method

```python
class FakeMethodAdapter(BaseMethodAdapter):
    method = "FAKE"
    CAPABILITIES = FAKE_CAPABILITIES

    def send(self, request): return MethodResult(status="AUTHORIZED")
```

Then, in `main.py`:

```python
methods = MethodRegistry([CardMethodAdapter(cards), FakeMethodAdapter()])
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

## Capabilities (Task 8.2)

Every adapter exposes `capabilities()`; the registry serves it at the endpoint the spec has always described
but the backend never implemented:

```
GET /api/v1/capabilities/{payment_method}     scope transactions:read, or a terminal over mTLS
```

The values are the frozen `CapabilityDescriptor` (spec 1.3.0), and `CardMethodAdapter` returns exactly the
`CardCapabilities` example the contract is tested against — chargebacks yes, partial refunds yes, recurring
yes, offline yes, settlement T+1, dispute window 120 days, twelve transitions. `test_card_capabilities_match_
the_spec_example` pins the whole thing, and the payload was validated against the OpenAPI schema directly.

### Refusing work before the adapter is called

```python
registry.require("UPI", "partial_refund")   # CapabilityNotSupported — the adapter is never asked
```

`MethodRegistry.require(method, capability)` is the guard the engine uses before any capability-dependent
action. `test_partial_refund_on_a_rail_without_it_never_reaches_the_adapter` asserts exactly that: the error
is raised from the descriptor and the adapter records zero calls. The refund endpoints (not built yet) are
expected to start with this line, which is why the guard lives on the registry rather than inside an adapter.

### A note on the brief's sample JSON

The task's sample said `method` and included `is_synchronous`. The frozen contract says `payment_method` and
has no `is_synchronous`; asynchronous rails are already described by `transitions` (`PENDING → SETTLED`) and
`settlement_timeline`, which is what the SDK and dispute tooling branch on. Renaming would be a breaking
change to a frozen contract, and adding a redundant boolean would be a spec release for no new information.
If a first-class sync/async flag is wanted anyway, it is an additive, non-breaking change — worth doing as its
own version bump rather than smuggling it into this step.

## Tests

```bash
cd backend && pytest tests/test_methods.py tests/test_capabilities.py
```

20 cases in `test_methods.py`, no database: registry lookup and duplicate detection, unknown method rejected
before anything is claimed, a second method working through the unchanged engine, the three failure
translations, validation before the idempotency claim, field-path messages that never echo card data, and every
unbuilt call raising `UnsupportedOperation` — plus the base adapter's translation, pass-through, type check,
model validation and the idempotency property.

13 more in `test_capabilities.py`: the descriptor against the frozen example, `supports()` name handling, the
capability guard refusing partial refunds and chargebacks without calling the adapter, and the endpoint's auth
matrix (token, wrong scope, missing credential, terminal over mTLS, unknown method as 400).

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
