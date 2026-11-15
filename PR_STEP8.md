**Stacked on #6** (`feat/step5-transaction-path`). **Base this PR on `feat/step5-transaction-path`, not `main`** — Step 6 is not on `main` yet.

> Merge order note: #7 and this PR are siblings off the same commit and touch three files in common (`README.md`, `backend/app/api/auth.py`, `backend/app/main.py`). Whichever merges second takes three small conflicts — a README row, one function inserted in `auth.py`, and the router/import block in `main.py`. Nothing semantic.

Full write-up: [`docs/step8.md`](docs/step8.md).

### What this gives you

The transaction engine stopped knowing what a card is. It asks a registry for an adapter by `payment_method`, hands it a validated `MethodRequest`, and maps the returned `MethodResult` onto a transaction state. Adding UPI is a new file plus one line in `main.py` — no branch in the engine, no `if method == ...` anywhere.

**The contract** (`app/application/methods.py`) — six calls as specified, as a `Protocol` rather than an ABC, plus the shared error vocabulary:

| Adapter raises | Engine does | Client sees |
| :--- | :--- | :--- |
| `AdapterUnavailable` | FAILED, key freed, not stored | 503 `SYSTEM_ERROR`, retryable |
| `InvalidMethodDetails` | FAILED, not stored | 400 `VALIDATION_ERROR`, names the field |
| `OutcomeUnknown` | PENDING, **stored** | 201 PENDING |
| `MethodNotSupported` / `CapabilityNotSupported` | nothing happens at all | 422 `INVALID_REQUEST` |

`OutcomeUnknown` is deliberately not a `RegistrationError`: it is not a failure and must never render as one.

**Capabilities** — every adapter answers `capabilities()`, served at `GET /api/v1/capabilities/{payment_method}`, a path the spec has described since 1.0.0 that the backend had never implemented. `CardMethodAdapter` returns the contract's own `CardCapabilities` example. `MethodRegistry.require(method, capability)` is the guard the engine uses before capability-dependent work: a partial refund on a rail without partial refunds is refused from the descriptor, and the adapter is never called.

**`BaseMethodAdapter`** — a rail implements `send()` and declares `CAPABILITIES`, `DETAILS`, `ERROR_MAP`. The base supplies the capabilities call, model-based validation, the `initiate()` template, translation into the shared taxonomy, and defaults for the calls a rail has not built. `CardMethodAdapter` lost its five overrides and kept only the ISO 8583 code.

### Design decisions

**Idempotency and audit stay in the engine — deliberately.** The engine claims the idempotency key in one transaction *before* an adapter is reached, and `audit_log` is written by the repository inside the state-change transaction. An adapter doing either would double-charge on retry, or record a payment that rolled back. `test_idempotency_is_enforced_by_the_engine_not_the_adapter` drives two identical requests through the real engine and asserts the adapter was called once.

**ISO 8583 is not wrapped into the Python adapter.** `card-service/` (Rust) builds the 0100 and sends it; the adapter calls it over HTTP. That is Step 5A's PCI-scope decision — pulling the host connector into the API process would put clear card data where the architecture keeps it out. The engine still cannot tell the difference, which is the point.

**Pass-through is an explicit list, not `RegistrationError`.** The card service's own exceptions *are* `RegistrationError` subclasses, so catching the base class silently broke translation (a dead card service became a generic error instead of the 503 "nothing was charged"). Two tests caught it; the fix is the four shared errors only.

**`is_synchronous` is not added.** The brief asks for it; the frozen `CapabilityDescriptor` has no such field, and describes timing through `transitions` and `settlement_timeline`. Adding it is a small additive spec change that deserves its own version bump rather than an unversioned field.

**`handle_webhook` raises rather than silently ignoring.** An endpoint that accepts a callback has to authenticate it first, and a v1 card rail has no callback contract to authenticate against. It becomes a real handler with a signature check when settlement advice is integrated.

### Tests

- `backend/tests/test_methods.py` — 28 cases, no database: registry lookup and duplicate detection, unknown method rejected before anything is claimed, a second method working through the unchanged engine, the three failure translations, validation before the idempotency claim, field-path messages that never echo card data, every unbuilt call raising `UnsupportedOperation`, the base adapter's translation/pass-through/type check, and three regression pins.
- `backend/tests/test_capabilities.py` — 13 cases: the CARD descriptor against the frozen example, `supports()` name handling, the capability guard refusing partial refunds and chargebacks without calling the adapter, and the endpoint's auth matrix (token, wrong scope, missing credential, terminal over mTLS, unknown method as 400).
- The served CARD descriptor was validated against the OpenAPI schema directly.
- `spec/check_spec.py`: 20 examples, all rules pass. **No spec change** — the endpoint already existed in the contract.

### Not in this PR

- CARD implements `validate` and `initiate` only; `capture`/`refund`/`status`/`handle_webhook` raise `UnsupportedOperation`. The refund endpoints that call `require()` do not exist yet.
- Payment intents (`/v1/payment_intents/{id}/confirm`) still call the card processor directly through `CheckoutCardProcessor`. They are a card-only checkout flow; they move onto the adapter when a second rail can complete a checkout.
- `is_synchronous`, pending its own spec version.

### Reviewing it

1. `backend/app/application/methods.py` — contract, result types, registry, the guard.
2. `backend/app/infrastructure/methods/base.py` — the template and the two documented exclusions.
3. `backend/app/infrastructure/methods/card.py` — what is left of the card rail.
4. `backend/app/application/transactions.py` — the engine's new shape (`for_method` → `validate` → `initiate`).
5. `backend/app/api/capabilities.py` — the endpoint and its 400-vs-422 choice.

15 files across four commits, +1,346/−69 — 8.1 `5f142e0`, 8.2 `68a9f1d`, 8.3 `68b522b`, 8.6 `20302de`.
