# SynapsePay

**A Terminal-to-Cloud payment network that routes every payment method through one unified contract, designed to keep accepting payments when the internet drops.**

> **Status:** Stage 1 in progress, sandbox only. Websites take card payments end to end (Synapse card frame → 3-D Secure → ISO 8583 → mock acquirer → signed webhook), and so do terminals via the API. Still to come: the terminal app (Step 5B) and the audit log (Step 7).

---

## What is SynapsePay?

SynapsePay is a payment network built on a **Terminal-to-Cloud (T2C) architecture**. Instead of routing card-present transactions through a traditional gateway intermediary, terminals connect **directly** to a cloud processing host, collapsing `terminal → gateway → host` into `terminal → host`.

It is not just a card network. Cards, UPI, wallets, QR and offline payments are pluggable adapters under a **single unified transaction model**. One API contract, many rails.

The name is deliberate: a synapse is the junction where signals pass between neurons. SynapsePay is the junction where payment methods, terminals and processing hosts connect, without a toll-collecting intermediary in the middle.

## Why it exists

Merchants already have payment gateways. What they need is a **brain that chooses between the rails they already have**, and a network that keeps working when connectivity does not.

| Problem | SynapsePay's answer |
| :--- | :--- |
| Gateway intermediaries add fees, compliance scope and failure points | Terminals connect directly to the processing host |
| Each payment method needs a separate integration | One unified transaction model; new methods are adapters, not rewrites |
| Connectivity loss halts card-present acceptance | An on-premise edge node screens and accepts transactions locally, then syncs on reconnection |
| Merchants are locked into one terminal vendor | A universal terminal adapter across Android POS, Linux POS, SoftPOS and more |

## Architecture

The target design. What exists today is listed under Current status.

```text
┌──────────────────────────────────────────────────────────┐
│               MERCHANT APP / POS APP                     │
│              (SynapsePay Merchant SDK)                   │
└────────────────────────────┬─────────────────────────────┘
                             │ HTTPS: OAuth 2.0 (backends) / mTLS (terminals)
┌────────────────────────────▼─────────────────────────────┐
│                   SYNAPSEPAY CLOUD                       │
│                                                          │
│   API edge         auth, rate limiting, mTLS termination │
│   Terminal Registry        X.509 identity, certification │
│   Transaction Engine            ISO 8583 parse / build   │
│   Payment Methods    CARD · UPI · WALLET · QR · OFFLINE  │
│   Routing & Cascade Engine         rule-based → ML       │
│   Host Connector Pool       multi-acquirer, failover     │
└────────────────────────────┬─────────────────────────────┘
                             │ ISO 8583 over TLS
┌────────────────────────────▼─────────────────────────────┐
│              ACQUIRER / PROCESSING HOST                  │
└──────────────────────────────────────────────────────────┘

┌─────────────────────────────┐
│   EDGE NODE (on-premise)    │
│   • Local rule cache        │
│   • Local transaction engine│
│   • Local fraud screening   │
│   • Offline queue + sync    │
└─────────────────────────────┘
```

## Current status

| Component | Status |
| :--- | :--- |
| Unified Transaction Model (OpenAPI 3.1) | ✅ Step 1 (spec now v1.2.0, additive only) |
| Terminal Registry, mTLS gateway (Envoy), heartbeats, authorization | ✅ Step 2 (`backend/`, `gateway/`) |
| ISO 8583 parser / packer | ✅ Step 3 (`iso8583/`) |
| Host Connector: mTLS link, pool, echo, audit, reversals | ✅ Step 4 (`host-connector/`) |
| `POST /api/v1/transactions` (card, terminals) | ✅ Step 5A (`backend/`) |
| Card service + simulated HSM | ✅ Step 5A (`card-service/`) |
| Terminal app (Android, simulated card reader) | ⏳ Step 5B |
| Terminal app on PAX hardware | ⏳ Step 5C |
| Payment intents, hosted card frame, 3-D Secure (simulated), webhooks, terminal checkout | ✅ Step 6 |
| Node.js server SDK, web SDK | ✅ Step 6 (`sdks/node`, `sdks/web`) |
| Android SDK, Flutter plugin | 🟡 Step 6: written; Java core tested, Kotlin/Flutter not compiled yet |

**Try it:** [take a test payment in 5 minutes](docs/quickstart.md).

How it works: [terminal payments (Step 5)](docs/step5.md), [merchant SDKs (Step 6)](docs/step6.md).

## The contract

Everything lives in [`spec/openapi.yaml`](spec/openapi.yaml).

| Endpoint | Purpose |
| :--- | :--- |
| `POST /api/v1/transactions` | Create a transaction for any payment method |
| `GET /api/v1/capabilities/{payment_method}` | Static capability descriptor for a method; fetch once and cache |
| Webhook `transactionStatus` | Final status sent to the request's `webhook_url`, signed with `X-Signature` |

### Design principles

1. **Method-agnostic top level, method-specific payload.** `amount`, `currency`, `terminal_id`, `merchant_id` and `status` are the same for every method. Method-specific data lives in `method_details`, whose shape is chosen by `payment_method`.
2. **Amounts are integers in the smallest currency unit.** ₹499.99 is `49999` paise. The API never accepts a decimal.
3. **Idempotency is mandatory.** Every transaction carries a client-generated `idempotency_key`. Replaying the key returns the original response without reprocessing. Reusing it with a different body returns `409`.
4. **Errors are categorised for routing.** Every failure has an `error_category` (`SOFT_DECLINE`, `HARD_DECLINE`, `SYSTEM_ERROR`, `VALIDATION_ERROR`, `AUTHENTICATION_ERROR`) and a `retryable` flag. The cascade engine reads these to decide whether to try another acquirer.
5. **Capabilities are declared, not assumed.** Each method publishes a descriptor: refunds, partial refunds, chargebacks, recurring, offline, allowed state transitions, and which dispute framework applies.
6. **Auth is layered by trust boundary.** OAuth 2.0 client credentials for merchant backends, mutual TLS for terminals, HMAC-SHA256 signatures for webhooks.

### Transaction lifecycle

```text
INITIATED → PENDING → AUTHORIZED → CAPTURED → SETTLED
               │           │           │          │
               ▼           ▼           ▼          ▼
            FAILED      VOIDED   REFUNDED / PARTIALLY_REFUNDED
                                         (partial refunds can repeat)
```

Methods may skip states: UPI goes `PENDING → SETTLED`, OFFLINE goes `AUTHORIZED → SETTLED` on sync. Each capability descriptor lists the exact transitions its method allows.

### Payment methods (v1)

Values come from the capability descriptors in the spec.

| Method | Auth | Settlement | Refunds | Dispute framework |
| :--- | :--- | :--- | :--- | :--- |
| **CARD** | Issuer authorization | T+1 | Full and partial | Card scheme (Visa / Mastercard / RuPay) |
| **UPI** | VPA collect | Instant | Full and partial | NPCI UPI |
| **WALLET** | OTP | T+0 | Full only | None |
| **QR** | Inherits rail | Inherits rail | Inherits rail | Inherits rail (`qr_encoded_rail`) |
| **OFFLINE** | Local fraud screening | T+1 on sync | None in v1 | None in v1 |

A QR payment is recorded as `QR`, but its rules come from the rail it encodes (UPI, card scheme or wallet). The QR descriptor itself applies only when the rail is `UNKNOWN`.

### Versioning

v1.0.0 is frozen. Any breaking change to the contract goes through a versioned process (for example a `/v2` endpoint).

## Repository structure

```text
synapse-pay/
├── spec/             # The Unified Transaction Model (OpenAPI) and its contract tests
├── backend/          # FastAPI: terminal registry, transactions API (Python)
├── gateway/          # Envoy config: terminal mTLS, registry check before the backend
├── iso8583/          # ISO 8583 message library (Rust)
├── host-connector/   # Acquirer connection: mTLS, pool, echo, audit, reversals (Rust) + mock acquirer
├── card-service/     # Simulated HSM + card flow; the only process that sees a card number (Rust)
├── sdks/             # Merchant SDKs: node (server), web, android, flutter
├── examples/         # A complete example shop
├── db/migrations/    # PostgreSQL schema
└── docs/             # How each step works and how to run it
```

## Running the contract tests

Prerequisites: **Node.js 18+**, **Python 3.10+**, and a bash shell with `curl` (on Windows, Git Bash).

```bash
pip install -r spec/requirements.txt
bash spec/contract-test.sh
```

The script:

1. Validates all examples in `openapi.yaml` and checks the contract's rules (required fields, enums, method-specific payloads, error format).
2. Starts a Prism mock server from the spec (a pinned version, via `npx`).
3. Runs Schemathesis-generated requests against the mock and checks every response against the spec.

To lint the spec:

```bash
npx @redocly/cli@1.34.0 lint spec/openapi.yaml
```
