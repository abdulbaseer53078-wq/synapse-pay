# Step 6: the merchant SDKs

Merchant apps and websites now take payments through Synapse without handling card numbers, API secrets in the
browser, idempotency or 3-D Secure themselves. Try it: [quickstart](quickstart.md).

## How an online payment works

```text
Merchant server ──(secret key)──▶ POST /v1/payment_intents {amount}        amount fixed server-side
      │ client_secret
      ▼
Merchant page ── Synapse card frame (Synapse's origin, iframe)
                   │ encrypts PAN + CVV to the HSM's checkout key (sp2: ECDH P-256 + AES-GCM)
                   ▼
                 POST /v1/payment_intents/{id}/confirm ──▶ backend ──▶ card service
                                                                      ├─ 3-D Secure (simulated)
                 REQUIRES_ACTION ◀── issuer wants an OTP ◀────────────┘
      bank's OTP page in a modal ──▶ OTP ok ──▶ authorize (ISO 8583) ──▶ acquirer
      ▼
Merchant page: SUCCEEDED            Merchant server: signed webhook (HMAC-SHA256)
```

- **The amount can't be tampered with.** The browser only holds a `client_secret` for one intent.
- **The card never reaches the merchant or the Python backend.** It's encrypted inside Synapse's frame (or
  native card view) to a key only the HSM can open, like terminal card data in Step 5.
- **3-D Secure is built in.** RBI requires extra authentication for online card payments; the SDK shows the
  bank's page and continues afterwards.
- **No double charges.** Confirming an intent that's already moving returns its current state; server SDK
  retries resend the same idempotency key.
- **A decline isn't the end.** The intent returns to `REQUIRES_PAYMENT_METHOD` with `last_payment_error`, so
  the customer can try another card.

## Terminal checkout (web POS → physical terminal)

The merchant's server creates an intent with `terminal_id`. The terminal long-polls
`GET /v1/terminals/{id}/checkout` (through the mTLS gateway), shows the amount, takes the card, and pays with
`POST /v1/transactions` carrying `payment_intent_id`. The web POS waits with `waitForTerminalPayment`. They
never need to be on the same network. Long polling instead of WebSockets keeps it within the existing Envoy
gateway (`wait` ≤ 10 s, under Envoy's 15 s route timeout).

## What's in the repo

| Piece | Where | Tested here? |
| :--- | :--- | :--- |
| Payment intents, confirm, 3DS sandbox page, terminal checkout, API keys, webhooks | `backend/` | ✅ unit + real-stack browser tests |
| Checkout key, ECIES decryption, simulated 3DS, CVV check | `card-service/` | ✅ |
| Hosted card frame | `backend/app/checkout/` | ✅ in Chromium |
| Node.js server SDK `@synapsepay/node` | `sdks/node/` | ✅ unit + used by the browser tests |
| Web SDK `@synapsepay/web` | `sdks/web/` | ✅ unit + Chromium end to end |
| Android SDK: Java core (crypto, validation, API) | `sdks/android/` | ✅ on a JVM against the real card service |
| Android SDK: Kotlin views, 3DS WebView, payment sheet | `sdks/android/` | ❌ not compiled (no Android SDK here) |
| Flutter plugin (Android) | `sdks/flutter/` | ❌ not compiled (no Flutter here) |
| Sandbox in one command, example shop | `backend/app/sandbox.py`, `examples/node-shop/` | ✅ run end to end |

## Step 6 gate

| Gate item | Status |
| :--- | :--- |
| Server SDK creates a PaymentIntent and returns a client_secret | ✅ Node.js |
| Client SDK captures the card in an iframe / secure view and sends it to the cloud | ✅ web; Android written, not compiled |
| SDKs handle idempotency keys and safe retries | ✅ |
| Server SDK verifies webhook signatures (HMAC-SHA256) | ✅ |
| A web POS wakes a physical terminal and completes a transaction | ✅ server and web side, with a simulated terminal; needs the Step 5B terminal app |
| Quickstart: a test payment in under 5 minutes | ✅ once the card service has built |
| Published to NPM, PyPI, Maven Central | ❌ needs your accounts (below) |

## Publishing (needs your accounts)

- **npm:** create the `@synapsepay` organisation on npmjs.com, then in `sdks/node` and `sdks/web`:
  `npm login`, `npm publish --access public` (remove `"license": "UNLICENSED"` or set a licence first).
- **Maven Central:** register the `com.synapsepay` namespace on central.sonatype.com (you need the domain),
  add signing, then `./gradlew :synapsepay:publish` in `sdks/android`.
- **pub.dev:** remove `publish_to: none` from `sdks/flutter/pubspec.yaml`, then `flutter pub publish`.
- **PyPI:** there's no Python server SDK yet; Node came first.

## Shortcuts and what's left

Marked `shortcut:` in the code where they live.

- **Simulated 3-D Secure.** No 3DS server or directory-server connection; the sandbox bank page stands in for
  the issuer's. Going live needs a certified 3DS server (or a provider) and passing ECI/CAVV to the acquirer.
- **CVV is checked, not forwarded** (the synthetic host dialect has no field for it), and **DE 22** still says
  chip for online payments.
- **Checkout private key** comes from a file; it belongs inside the HSM.
- **Webhook secrets** are stored as is; they belong in a secret store. Webhooks carry no timestamp, so receivers
  should treat events idempotently (by `transaction_id`) rather than rely on replay protection.
- **Client secrets** are stored so the merchant can read them back; they only pay their own intent and expire
  in an hour.
- **E-commerce terminal and merchant IDs** (DE 41/42) are derived from the merchant UUID.
- **Saved cards** aren't supported: RBI requires card-network tokenisation for card-on-file, a later step.
- **iOS, React Native and a Python server SDK** aren't started. **The Step 5B terminal app** still doesn't exist.
- **`PROCESSING` intents** (bank answer lost and reversal failed) wait for a reconciliation job that isn't built.
