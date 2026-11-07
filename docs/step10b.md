# Step 10B — the UPI webhook endpoint

`POST /api/v1/webhooks/upi`. Public, unauthenticated in the HTTP sense, and therefore the most dangerous
surface in the system: anyone can POST to it, and a forged `{"status":"SUCCESS"}` would hand over goods for
free. Everything here exists to make a forged or replayed callback worthless.

## The five checks, in order

1. **Raw bytes.** `await request.body()` — FastAPI never parses this route's JSON. A signature computed over a
   parsed-and-reserialised body does not match the provider's, because key order and whitespace change.
   `test_the_raw_bytes_are_what_is_signed` re-serialises the same object with `indent=2` and proves it fails.
2. **Timestamp window.** 300 seconds, in *both* directions. An hour in the future is a forged stamp, not a slow
   network.
3. **HMAC-SHA256**, compared with `hmac.compare_digest` — constant time. A plain `==` leaks how many leading
   bytes matched.
4. **Idempotency.** The provider's `event_id` is claimed with `INSERT ... ON CONFLICT DO NOTHING RETURNING 1`,
   so two workers handling the same retry cannot both apply it. No read-then-write race, no Redis needed.
5. **Hand-off.** The verified update goes to `apply_method_result()` — the same call the poller and the
   synchronous engine use, so the audit row and the merchant webhook outbox are written identically.

The adapter verifies and normalises; the engine changes state. An adapter that wrote state would bypass the
state machine, the audit trail and the idempotency key at once.

## Two deliberate deviations from the brief

**The signature covers `<timestamp>.<raw body>`, not the body alone.** A body-only signature can be replayed
by capturing it and sending it with a fresh timestamp header — the window check would pass forever. Binding
the timestamp into the signed message means the whole thing expires together. (This is why the header is
`X-UPI-Timestamp` + `X-UPI-Signature` rather than one combined header; it is Stripe's scheme, for the same
reason.)

**PSP traffic arrives on its own listener, not through the terminal gateway.** `gateway/envoy.yaml` now has
`psp_webhooks` on :8444 with server TLS only and no `ext_authz`. The mTLS listener requires a client
certificate from our CA, which a PSP does not have, and a per-route `disabled: true` inside the terminal
listener would be one forgotten config away from exposing everything. The trust boundary is the socket.

Adding the endpoint to the contract made this **spec 1.6.0**.

## Response codes

| Situation | Status |
| :--- | :--- |
| valid, applied | 200 |
| valid, duplicate `event_id` | 200 (`duplicate: true`, nothing changes) |
| valid, unknown payment | 200 (`applied: false`) — a 4xx would make the PSP retry for hours over a bug retrying cannot fix |
| bad or missing signature | 401 |
| stale/future timestamp, bad JSON, bad payload | 400 |
| no secret configured | 503 — fail closed, never accept unsigned callbacks |

## Tests

`backend/tests/test_upi_webhook.py`, 12 cases, no database:

- valid webhook settles once and stores the result;
- bad signature → 401, **nothing** looked up or applied;
- missing `X-UPI-Signature` / `X-UPI-Timestamp` → 401;
- 301s-old timestamp → 400; +1h timestamp → 400;
- the same event twice → 200 both times, one state change;
- a re-signed replay of the same event → still deduplicated by `event_id`;
- unknown payment → 200, nothing moved;
- FAILURE webhook → FAILED with `HARD_DECLINE`;
- body that is not JSON → 400;
- unconfigured secret → 503;
- re-serialised body → 401 (the HMAC trap).

## Shortcuts

- Deduplication is permanent: `webhook_events` grows forever. A real deployment prunes rows older than the
  provider's retry window (72h) — the delivery ids cannot recur after that.
- No queue in front of the handler. It is one indexed lookup plus one update, well under the 500ms a PSP
  tolerates; when that stops being true, the handler publishes to Kafka and returns 200 immediately.
- `UPI_WEBHOOK_SECRET` is a plain env var. It belongs in a secrets manager next to — but separate from — the
  API keys, per the design note; rotating it is a redeploy today.

## Gate

| Requirement | Status |
| :--- | :--- |
| Raw bytes, JSON parsing bypassed | ✅ |
| Constant-time HMAC comparison | ✅ |
| Timestamps older than 5 minutes rejected | ✅ (and future ones) |
| Duplicate `event_id` returns 200, no second transition | ✅ |
| Valid webhook routes through the engine and the audit log | ✅ (via `apply_method_result`) |
| Security tests for spoof, replay, duplicate | ✅ 12 cases |
| Endpoint in the contract | ✅ spec 1.6.0 |
