# Step 10A — the UPI adapter and the mock PSP

UPI is HTTP/JSON and asynchronous: you send a collect, the customer approves in their own app, and the outcome
arrives seconds later. That single fact is why the contract has `is_synchronous`, and why this adapter returns
`PENDING` instead of a result. Nothing in the transaction engine changed to add it — one line in `main.py`
registers it, which was the point of Step 8.

The public webhook endpoint is **Step 10B**, deliberately: raw-body HMAC, replay windows and idempotency
locking are the part where a mistake is a security incident, so they get their own review.

## What shipped

| Piece | Where |
| :--- | :--- |
| Mock PSP (offline, deterministic) | `mock-psp/mock_psp.py` |
| PSP HTTP client | `backend/app/infrastructure/upi_client.py` |
| `UpiMethodAdapter` | `backend/app/infrastructure/methods/upi.py` |
| Capability descriptor + error mapping | same file |
| Polling fallback | `python -m app.jobs upi-poll` |
| Registry wiring | `backend/app/main.py` |
| Tests | `backend/tests/test_upi.py` (21) |

## The mock PSP

`python mock-psp/mock_psp.py` prints `LISTENING <port>`. It is deterministic by amount, the way
`host-connector/mock_host.py` is for ISO 8583:

| Amount | Outcome |
| :--- | :--- |
| `% 1000 == 100` (₹51.00) | the collect ultimately FAILS |
| `% 1000 == 200` (₹52.00) | stays PENDING forever — the lost-webhook case the poller exists for |
| anything else | succeeds |

Routes: `POST /psp/v1/validate-vpa`, `POST /psp/v1/collect`, `GET /psp/v1/status/{id}`,
`POST /psp/v1/refund`, plus test levers `POST /mock/advance`, `/mock/outcome`, `/mock/trigger-webhook`,
`GET /mock/state`.

Every collect is answered `PENDING`. That is not a simplification — it is what a PSP does, because the
customer has not entered their PIN yet.

## Declines are results; failures are exceptions

The distinction drives the whole design:

| The PSP... | Adapter | Engine |
| :--- | :--- | :--- |
| answers 4xx (bad VPA, limit, not settled) | returns `MethodResult(status="FAILED", error=...)` with `HARD_DECLINE` / `SOFT_DECLINE` | stores FAILED, frees the idempotency key if retryable |
| answers 429 | `SOFT_DECLINE`, retryable | stored as retryable |
| times out, 5xx, or answers garbage | `PspUnavailable` → `AdapterUnavailable` | FAILED, retryable, nothing charged, not stored |

An exception means "we could not ask"; a result means "we asked and the answer was no". Conflating them is how
a timeout gets recorded as a decline and a customer is told their card was refused when nobody ever looked.

## Stateless adapters, so the reference travels

`status()` and `refund()` need the PSP's transaction id (`psp_...`), which the engine stored in
`transactions.method_reference`. Adapters have no database access, so both calls take an optional `reference`
argument — an additive contract change in this step, documented on the protocol. `test_status_needs_the_stored_reference`
pins that they refuse to guess.

## Polling fallback

```bash
UPI_PSP_URL=http://127.0.0.1:<port> python -m app.jobs upi-poll
```

Every 5 seconds it asks for UPI transactions still `PENDING` after `UPI_POLL_STALE_SECONDS` (default 300),
calls `status()`, and — if the answer is anything but PENDING — hands it to `apply_method_result()` in the
engine, which writes the same audit row and webhook outbox entry the synchronous path does. The adapter never
writes state.

## Running it by hand

```bash
python mock-psp/mock_psp.py --port 8080 &
UPI_PSP_URL=http://127.0.0.1:8080 CARD_SERVICE_URL=... uvicorn app.main:create_app --factory
```

```bash
curl -s -X POST localhost:8000/api/v1/transactions \
  -H "x-terminal-id: $TERMINAL_ID" -H 'content-type: application/json' \
  -d '{"idempotency_key":"'"$(uuidgen)"'","amount":1500,"currency":"INR","payment_method":"UPI",
       "method_details":{"vpa":"asha@okhdfcbank","flow_type":"COLLECT"},
       "terminal_id":"'"$TERMINAL_ID"'","merchant_id":"'"$MERCHANT_ID"'"}'
# → 201, status PENDING, method_reference psp_...
```

## Shortcuts

- `INTENT` and `MANDATE` flows validate but raise `UnsupportedOperation` — the deep-link and e-mandate
  machinery is 10.5 territory.
- `validate_vpa` is a method on the adapter, not an endpoint; the SDK-facing route comes with the checkout work.
- The poller is a job, not a scheduler: wiring it to cron/Kubernetes is deployment.
- No retry/backoff on `PspUnavailable` inside the adapter — the engine's idempotency key makes retrying safe,
  and retry policy belongs to the caller.

## Next

**10B**: `POST /api/v1/webhooks/upi` — raw body, HMAC-SHA256, timestamp replay window, idempotent delivery,
then `apply_method_result()`. The mock PSP already exposes `/mock/trigger-webhook` with a signature so the
handler can be tested against it.
