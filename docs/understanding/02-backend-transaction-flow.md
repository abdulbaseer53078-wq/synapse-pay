# 02 — Backend transaction flow (`POST /api/v1/transactions`)

Scope: the Python backend (`backend/app/`) and the SQL migration it writes to (`db/migrations/`). The Rust
services (card-service, host-connector) were **not** read. Where a value comes from them, this doc says so and stops.
Spec references point to [01-api-contract.md](01-api-contract.md).

Every reference is `file:line`, relative to the repo root.

---

## 1. Route and wiring

| What | Ref |
| :--- | :--- |
| Router prefix `/api/v1/transactions` | `backend/app/api/transactions.py:18` |
| Handler `create_transaction`, declared `status_code=201` | `backend/app/api/transactions.py:77-80` |
| Router mounted on the app | `backend/app/main.py:240` |
| `TransactionService` built and put on `app.state.transactions` | `backend/app/main.py:202` |
| Error handlers installed | `backend/app/main.py:238` → `backend/app/api/errors.py:47` |

## 2. Execution path, step by step

### 2.1 Authentication (before the handler)

The handler has no auth dependency. The terminal's identity arrives as the `x-terminal-id` header (`backend/app/api/transactions.py:79`), set by the gateway's `ext_authz` callback after it reads the terminal ID from the mTLS client certificate's URI SAN (`backend/app/api/gateway.py:34-55`). The callback always sets both identity headers, so a client can't inject its own (`backend/app/api/gateway.py:25-27`).

The handler parses the header as a UUID, and a bad value becomes `None` (`backend/app/api/transactions.py:87-92`). `None` is rejected as 401 (`backend/app/application/transactions.py:191-193`).

- **OAuth client credentials (merchant backends): NOT IMPLEMENTED IN BACKEND for this route.** The spec allows OAuth or mTLS here, but the code marks it `shortcut: merchant backends (OAuth) arrive with the Merchant SDK` and accepts mTLS only (`backend/app/application/transactions.py:192-193`).
- The trust in `x-terminal-id` assumes Envoy strips any client-supplied value. The Envoy config wasn't read (it isn't Python).

### 2.2 Request validation (two layers)

**Layer 1: Pydantic envelope** (`TransactionBody`, `backend/app/api/transactions.py:29-43`), validated by FastAPI before the handler runs:

| Field | Rule | Ref |
| :--- | :--- | :--- |
| *(whole body)* | `extra="forbid"`: unknown fields are rejected | `backend/app/api/transactions.py:25-26` |
| `idempotency_key` | `UUID` | `:30` |
| `amount` | `int`, `ge=1`, `le=999_999_999_999` (ISO 8583 DE 4 holds 12 digits) | `:31` |
| `currency` | `^[A-Z]{3}$` | `:32` |
| `payment_method` | `Literal["CARD","UPI","WALLET","QR","OFFLINE"]` | `:33` |
| `method_details` | bare `dict`; its shape is checked in layer 2 | `:34-35` |
| `terminal_id`, `merchant_id` | `str`, 1–64 chars | `:36-37` |
| `webhook_url` | `^https://`, ≤ 2048 | `:42` |
| `payment_intent_id` | `^pi_[0-9a-f]{32}$` | `:43` |

A failure becomes **400** `INVALID_REQUEST` / `VALIDATION_ERROR`. The message lists field paths only, never the values (`backend/app/api/errors.py:68-72`).

**Layer 2: business checks in `TransactionService.create`**, in this order:

| # | Check | Failure → HTTP | Ref |
| :--- | :--- | :--- | :--- |
| 1 | caller present (mTLS) | 401 `Unauthenticated` | `backend/app/application/transactions.py:191-193`, `backend/app/api/errors.py:20` |
| 2 | `body.terminal_id` == certificate's terminal | 403 `Forbidden` | `backend/app/application/transactions.py:194-195`, `backend/app/api/errors.py:21` |
| 3 | terminal exists → its merchant | 404 `NotFound` | `backend/app/application/transactions.py:196-198`, `backend/app/api/errors.py:22` |
| 4 | `body.merchant_id` == terminal's merchant | 422 `MERCHANT_NOT_FOUND` | `backend/app/application/transactions.py:199-200`, `:50-51`, `backend/app/api/errors.py:34` |
| 5 | adapter registered for `payment_method` | 422 `MethodNotSupported` | `backend/app/application/transactions.py:202`, `backend/app/api/errors.py:30` |
| 6 | `method_details` validated by that adapter's Pydantic model | 400 `InvalidMethodDetails` | `backend/app/application/transactions.py:203`, `backend/app/infrastructure/methods/base.py:59-63`, `backend/app/api/errors.py:31` |
| 7 | `payment_intent_id` parses as `pi_` + 32 hex | 409 `IntentNotPayable` | `backend/app/application/transactions.py:205-208`, `backend/app/api/errors.py:35` |

All of these run **before** the idempotency key is claimed, so a bad request leaves no row behind.

### 2.3 Idempotency check

**Implemented, in PostgreSQL.** No Redis is used on this path.

1. **Fingerprint.** `request_hash(body)` is SHA-256 of canonical JSON (sorted keys, no whitespace), so field order doesn't matter (`backend/app/application/transactions.py:154-157`). It hashes the dumped body with `exclude_unset=True` plus a defaulted `capture_mode` (`backend/app/api/transactions.py:82-83`). Omitting `capture_mode` and sending `"AUTO"` therefore hash the same.
2. **Claim.** One DB transaction runs `INSERT INTO idempotency_keys (..., state) VALUES (..., 'IN_FLIGHT') ON CONFLICT DO NOTHING RETURNING 1` (`backend/app/infrastructure/postgres_transactions.py:104-108`).
   - **Key was new:** insert a `transactions` row in `INITIATED`, link it to the key, write the audit row `transaction.create`, and return the new id (`backend/app/infrastructure/postgres_transactions.py:124-138`).
   - **Key existed:** read `request_hash, state, response` (`:110-113`), then:
     - hash differs → `Claim(conflict=True)` (`:114-115`) → **409** `IDEMPOTENCY_KEY_CONFLICT`, `VALIDATION_ERROR`, `retryable: false` (`backend/app/application/transactions.py:220-221`, `backend/app/api/errors.py:26`, `:44`)
     - `state = 'IN_FLIGHT'` → `Claim(in_flight=True)` (`backend/app/infrastructure/postgres_transactions.py:116-117`) → **409** `IDEMPOTENCY_KEY_CONFLICT`, `SYSTEM_ERROR`, `retryable: true` (`backend/app/application/transactions.py:222-223`, `:36-38`, `backend/app/api/errors.py:27`, `:44`)
     - otherwise → the stored response is replayed with **201** (`backend/app/infrastructure/postgres_transactions.py:118`; `backend/app/application/transactions.py:224-225`; `backend/app/api/transactions.py:95`)
3. **Payment-intent refusal.** The whole claim rolls back, which releases the key (`backend/app/infrastructure/postgres_transactions.py:119-123`). The client gets **409** `IntentNotPayable` (`backend/app/application/transactions.py:218-219`).
4. **Settle the key** inside `finish()`, in the same DB transaction as the status change:
   - `store_response=True` → `state = 'DONE'`, `response = <TransactionResponse>` (`backend/app/infrastructure/postgres_transactions.py:259-262`)
   - `store_response=False` (a retryable failure) → **the key row is deleted** so a retry runs again (`:263-266`)

**Where it is stored:** table `idempotency_keys`, `PRIMARY KEY (merchant_id, idempotency_key)` (`db/migrations/007_transactions.sql:35-43`). **Keys are scoped per merchant**, while the spec doesn't say what the scope is.

**Not on this path:**
- **Expiry or cleanup of DONE keys: NOT IMPLEMENTED IN BACKEND.** No TTL column is defined (`db/migrations/007_transactions.sql:35-43`). A sweep elsewhere may exist; it wasn't traced.
- `transactions.idempotency_key` has **no unique constraint** (`db/migrations/007_transactions.sql:7`). After a retryable failure, the retry inserts a **second** `transactions` row under the same key, and the first stays `FAILED`. This looks deliberate, since each attempt keeps its audit trail, but it means one key can map to several transactions.

### 2.4 Terminal authorization and limits (after the claim)

- Terminal and method authorization, then the daily limit (midnight Asia/Kolkata) (`backend/app/application/transactions.py:229-235`).
- A denial is **not** an HTTP error. It's written as `FAILED` with `error_code: FORBIDDEN`, `HARD_DECLINE`, and stored, then returned with **201** (`backend/app/application/transactions.py:236-239`).

### 2.5 Routing and sending

- **Routing.** When enabled, it picks the acquirer shortlist (`backend/app/application/transactions.py:243-246`).
  - No healthy host → `FAILED`, `HOST_UNAVAILABLE`, `SYSTEM_ERROR`, retryable, key released, **201** (`:247-249`, `:164-165`).
  - No certified acquirer → `FAILED`, `FORBIDDEN`, `HARD_DECLINE`, stored, **201** (`:252-258`).
- **Lock.** `mark_pending` moves the transaction to `PENDING`. If a sweep already failed it, the handler returns the current row and sends nothing (`backend/app/application/transactions.py:266-268`).
- **Cascade** (adapters with `SUPPORTS_HOST_ROUTING`, i.e. CARD: `backend/app/infrastructure/methods/card.py:85`). `cascade()` tries up to 3 hosts (`MAX_RETRIES = 2`, `backend/app/application/routing.py:20`). It moves on only while the result is **retryable and not PENDING** (`backend/app/application/routing.py:131`, `:137-138`). The decision uses the `retryable` flag, not `error_category == SOFT_DECLINE`.
- **No cascade** (any other method): one call to `adapter.initiate` (`backend/app/application/transactions.py:290`).
- **Adapter exceptions** (`backend/app/application/transactions.py:291-303`):

| Exception | Row written | Key | HTTP |
| :--- | :--- | :--- | :--- |
| `AdapterUnavailable` (service unreachable, unknown error) | `FAILED`, `INTERNAL_ERROR`, retryable | released | **503** (`backend/app/api/errors.py:32`) |
| `InvalidMethodDetails` (card service said 400/422) | `FAILED`, `INVALID_REQUEST` | released | **400** (`backend/app/api/errors.py:31`) |
| `OutcomeUnknown` (sent, no answer) | `PENDING`, no error | **stored** (so a retry can't double charge) | **201** |

### 2.6 Writing the result

`repo.finish(...)` locks the row (`SELECT ... FOR UPDATE`) and checks the state machine. An illegal transition is audited as `transaction.discrepancy` and changes nothing (`backend/app/infrastructure/postgres_transactions.py:217-228`).

Otherwise, in **one** DB transaction it:
- updates the status and error (`:230-239`)
- posts the ledger sale once (`:249-252`)
- settles a linked payment intent (`:253-256`)
- queues the merchant webhook, unless the status is `PENDING` (`:257-258`)
- settles or deletes the idempotency key (`:259-266`)
- writes the audit row `transaction.finish` (`:271-272`)

The handler then always returns **201** with that body (`backend/app/api/transactions.py:93-95`).

---

## 3. Where a payment is decided "failed" (e.g. insufficient funds)

**The Python backend never decides an issuer decline. It copies the decline from the adapter's result.**

- `INSUFFICIENT_FUNDS` appears **nowhere** in `backend/app/` (searched all `*.py`).
- **CARD:**
  - The card service returns `status` and `error` as JSON, and `HttpCardProcessor` copies them verbatim (`backend/app/infrastructure/card_service_client.py:45-49`).
  - `CardMethodAdapter.send` passes them on unchanged (`backend/app/infrastructure/methods/card.py:108-111`).
  - The ISO 8583 response code → `INSUFFICIENT_FUNDS` mapping happens inside the Rust card service, which was not read for this doc.
- **WALLET:**
  - The provider's error `code` passes through. Its category and retryable flag come from `WALLET_ERRORS` (`backend/app/infrastructure/methods/wallet.py:135-143`).
  - Insufficient balance is `WALLET_INSUFFICIENT_BALANCE` → **`SOFT_DECLINE`, `retryable: true`** (`backend/app/infrastructure/methods/wallet.py:72`).
  - The adapter turns it into `status="FAILED"` (`backend/app/infrastructure/methods/wallet.py:196-199`).
- **UPI:** a PSP `FAILURE` becomes `FAILED`, `UPI_DECLINED`, `HARD_DECLINE` (`backend/app/infrastructure/methods/upi.py:86-90`).
- **The line that commits a decline as a transaction state:** `backend/app/application/transactions.py:305-306` (no cascade) or `:287-289` (cascade), both via `repo.finish(... result.status, result.error ...)`.

**HTTP status: 201, not 400.** `finish()` returns the `TransactionResponse` dict (`backend/app/infrastructure/postgres_transactions.py:273`). `create()` returns it (`backend/app/application/transactions.py:305-306`). The handler always sends it with `status_code=201` (`backend/app/api/transactions.py:95`). This matches the spec (01 §6.2).

One difference: the `retryable` flag decides whether the key is kept (`store_response=not result.retryable`, `backend/app/application/transactions.py:289`, `:306`; `MethodResult.retryable` at `backend/app/application/methods.py:124-126`).
- A **hard** decline is stored, so a retry with the same key replays the same `FAILED` 201.
- A **soft** decline (e.g. wallet insufficient balance) releases the key, so a retry with the same key **re-runs the payment**.

---

## 4. Where the backend differs from the spec

| # | Difference | Backend ref | Spec ref |
| :--- | :--- | :--- | :--- |
| 1 | OAuth on `POST /v1/transactions` not implemented: mTLS only, else 401 | `backend/app/application/transactions.py:191-193` | `spec/openapi.yaml:11-13` |
| 2 | Unknown terminal returns **404**; the spec lists 422 for it and doesn't declare 404 on this operation | `backend/app/application/transactions.py:196-198`, `backend/app/api/errors.py:22` | `spec/openapi.yaml:106-111`, `:1509-1510` |
| 3 | "Still processing" reuses `IDEMPOTENCY_KEY_CONFLICT` with 409 + `SYSTEM_ERROR` + retryable; the spec only documents the non-retryable conflict | `backend/app/application/transactions.py:36-38`, `backend/app/api/errors.py:27` | `spec/openapi.yaml:1523-1528` |
| 4 | Error codes written that aren't in the spec's `error_code` enum: `HOST_UNAVAILABLE`, `UPI_DECLINED`, `WALLET_DECLINED`, `WALLET_INSUFFICIENT_BALANCE` (and any provider code passed through) | `backend/app/application/transactions.py:248`, `backend/app/infrastructure/methods/upi.py:89`, `backend/app/infrastructure/methods/wallet.py:72`, `:140`, `:180` | `spec/openapi.yaml:2289-2318` |
| 5 | Wallet insufficient funds is `SOFT_DECLINE` / retryable; the spec's wallet example is `INSUFFICIENT_FUNDS` / `HARD_DECLINE` / not retryable | `backend/app/infrastructure/methods/wallet.py:72` | `spec/openapi.yaml:1650-1654` |
| 6 | Terminal authorization denial uses `error_code: FORBIDDEN` inside a 201, the same code the spec uses for a 403 | `backend/app/application/transactions.py:237-239` | `spec/openapi.yaml:1507-1508` |
| 7 | Amount upper bound 999,999,999,999 is enforced; the spec has no `maximum` | `backend/app/api/transactions.py:31` | 01 §5 |
| 8 | The card service failing returns **503**, and so does any unmapped adapter error; the spec only says 5XX | `backend/app/api/errors.py:28`, `:32` | `spec/openapi.yaml:111` |
