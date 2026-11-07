# SynapsePay

**An open payment network, from the card reader to the acquirer: one API for cards, UPI, wallets, QR and
offline payments, with the hard parts of payments built in the open.**

Payments look simple from the outside: one API call and a 200. Underneath are binary protocols from the 1980s,
connections that drop mid-transaction, money that must move exactly once, and auditors who want every decision for
five years. SynapsePay is a sandbox implementation of the whole path, written to be read:

```text
merchant site / terminal ──► gateway (mTLS) ──► API ──► card service (HSM) ──► host connector ──► acquirer
                                                  │                                ISO 8583 over TLS
                                                  ├──► UPI · wallets · QR adapters ──► PSPs
                                                  └──► Postgres (outbox) ──► Kafka · hash-chained WORM audit
```

> **Status:** sandbox only, test cards only. Steps 1–15 are on `main`; the resilience steps (16–17) are in review.
> Nothing here may touch a real card.

## Try it in 5 minutes

Pay ₹500 with a test card, OTP step included, through a real ISO 8583 exchange with a mock acquirer. You need
Python 3.12+, Rust (`cargo`), Node.js 18+ and PostgreSQL:

```bash
docker compose up -d db                    # PostgreSQL (or point DATABASE_URL at your own)
cd backend && pip install -r requirements.txt
python -m app.sandbox                      # mock acquirer + card service + API; prints sk_test_... and whsec_...
```

Then start the example shop and pay with `4111 1111 1111 1111` (OTP `123456`): **[the full quickstart](docs/quickstart.md)**.
Amount ₹51.00 is declined; ₹20.00 makes the bank go silent so you can watch the timeout and the automatic reversal.

## What's interesting in here

Each of these is small enough to read in one sitting.

| | Where |
| :--- | :--- |
| **A zero-copy ISO 8583 parser and builder in Rust.** Bitmaps up to 192 fields, ASCII and packed BCD, per-acquirer JSON dialects instead of code, property tests proving it never panics on hostile input. | [`iso8583/`](iso8583/) |
| **An acquirer connection that handles the network failing.** Persistent mutual TLS, many transactions on one socket matched by STAN, 0800 echo keep-alive, and a timeout that kills the socket, then sends a reversal (0400) instead of guessing. | [`host-connector/`](host-connector/) |
| **Card numbers live in one process.** A simulated HSM decrypts card data in the card service only. Logs and audit records get `411111******1111`, never the PAN or PIN block. | [`card-service/`](card-service/) |
| **Exactly-once money.** Every transaction carries an idempotency key: same key and body replays the answer, a duplicate of one still in flight is told to retry, a different body is refused. | [`backend/app/application/transactions.py`](backend/app/application/transactions.py) |
| **A tamper-evident audit trail.** A transactional outbox in Postgres feeds a SHA-256 hash chain on S3 Object Lock (COMPLIANCE, 5-year RBI retention), checked hourly by a verifier. | [`backend/app/audit/`](backend/app/audit/), [docs](docs/step7.md) |
| **One engine, many rails.** Cards, UPI (collect, webhooks, polling fallback), wallets and QR (which dispatches to the rail it encodes) are adapters behind one interface. | [`backend/app/infrastructure/methods/`](backend/app/infrastructure/methods/) |
| **Offline payments.** Terminals keep selling with the internet down and sync signed sales later. A tampered amount fails the signature check. | [`backend/app/application/offline_sync.py`](backend/app/application/offline_sync.py) |
| **Multi-acquirer routing.** Circuit breakers per host, rule-based routing, and a cascade that moves to another acquirer on a soft decline or a dead host, and never reports an unknown outcome as a clean, retryable failure. | [`backend/app/application/hosts.py`](backend/app/application/hosts.py) |

In review (Steps 16–17):
- **Terminal failover:** Wi-Fi → cellular within a second of a cable pull, with exactly one charge
  ([`feat/step16-multipath`](https://github.com/abdulbaseer53078-wq/synapse-pay/tree/feat/step16-multipath)).
- **Region failover:** Mumbai ↔ Hyderabad, with a game-day chaos test that proves no acknowledged payment is
  lost ([`feat/step17-region-failover`](https://github.com/abdulbaseer53078-wq/synapse-pay/tree/feat/step17-region-failover)).

## Repository map

| Directory | What | Language |
| :--- | :--- | :--- |
| [`spec/`](spec/) | The Unified Transaction Model: OpenAPI 3.1 contract (v1.8.1) and its contract tests | YAML |
| [`backend/`](backend/) | API, terminal registry, transaction engine, payment-method adapters, audit log, jobs | Python (FastAPI) |
| [`gateway/`](gateway/) | Envoy: terminal mutual TLS and the registry check before the backend | Envoy config |
| [`iso8583/`](iso8583/) | ISO 8583 message library | Rust |
| [`host-connector/`](host-connector/) | Acquirer connections: mTLS link, pool, echo, reversals, redacted audit, mock acquirer | Rust (+ Python mock) |
| [`card-service/`](card-service/) | Simulated HSM and the card flow; the acquirer fleet | Rust |
| [`sdks/`](sdks/) | Merchant SDKs: Node (server), web (card frame, 3-D Secure), Android, Flutter | TypeScript, Java/Kotlin, Dart |
| [`examples/node-shop/`](examples/node-shop/) | A complete shop integration in one file | JavaScript |
| [`mock-psp/`](mock-psp/), [`mock-wallet/`](mock-wallet/) | Sandbox UPI PSP and wallet provider | Python |
| [`db/migrations/`](db/migrations/) | PostgreSQL schema | SQL |
| [`infra/`](infra/) | Terraform: the audit WORM bucket | HCL |
| [`docs/`](docs/) | How each step works and how to run it | |

## Running the tests

Every component tests on its own. From the repo root, one line at a time:

```bash
docker compose up -d db kafka                    # Postgres for the backend; Kafka for the event tests
cd backend && pytest                             # API, registry, transactions, adapters, audit
cd iso8583 && cargo test                         # parser, builder, never-panics property tests
cd host-connector && cargo test                  # needs Python 3 on PATH for the mock acquirer
cd card-service && cargo test
cd sdks/node && npm test                         # likewise sdks/web
bash spec/contract-test.sh                       # contract: examples, Prism mock, Schemathesis
```

## The contract

Everything starts from [`spec/openapi.yaml`](spec/openapi.yaml). v1 is frozen; 1.x versions only add to it.

1. **Method-agnostic top level, method-specific payload.** `amount`, `currency`, `terminal_id`, `status` mean the
   same for every rail; rail details live in `method_details`.
2. **Integer amounts in the smallest unit.** ₹499.99 is `49999`. No decimals, ever.
3. **Idempotency is mandatory.** Same key, same body: the original answer. Same key, different body: `409`.
4. **Errors are categorised for routing.** `SOFT_DECLINE`, `HARD_DECLINE`, `SYSTEM_ERROR`, `VALIDATION_ERROR` or
   `AUTHENTICATION_ERROR`, plus `retryable`. The cascade reads these to decide whether another acquirer may try.
5. **Capabilities are declared, not assumed.** Each rail publishes what it supports: refunds, chargebacks,
   offline, its state transitions and its dispute framework.
6. **Auth follows the trust boundary.** Secret API keys and OAuth 2.0 for merchant servers, mutual TLS for
   terminals, HMAC signatures for webhooks.

```text
INITIATED → PENDING → AUTHORIZED → CAPTURED → SETTLED
               │           │           │          │
               ▼           ▼           ▼          ▼
            FAILED      VOIDED   REFUNDED / PARTIALLY_REFUNDED
```

| Rail | Settlement | Refunds | Disputes |
| :--- | :--- | :--- | :--- |
| CARD | T+1 | Full and partial | Card scheme (Visa / Mastercard / RuPay) |
| UPI | Instant | Full and partial | NPCI UPI |
| WALLET | T+0 | Full only | None |
| QR | Inherits the rail it encodes | | |
| OFFLINE | T+1 after sync | None in v1 | None in v1 |

## Roadmap

| Steps | What | Status |
| :--- | :--- | :--- |
| 1–7 | Contract, terminal registry, ISO 8583, host connector, card payments, merchant SDKs, audit log | ✅ on `main` ([step docs](docs/)) |
| 8–12 | Method adapters: UPI, QR, wallets | ✅ on `main` |
| 13 | Offline payments and signed batch sync | ✅ on `main` |
| 14–15 | Host health, circuit breakers, routing, cross-acquirer cascade | ✅ on `main` |
| 16–17 | Terminal multi-path failover, region failover | 🔄 in review |
| Next | Terminal app on Android POS hardware, more acquirers and rails | ⏳ |

The Android and Flutter SDKs are written, but only their Java core is compiled and tested so far.

## Contributing

Issues and pull requests are welcome, especially from anyone who has worked on acquirer integrations, ISO 8583
dialects, or payment infrastructure in India.

- Each step is documented in [`docs/`](docs/). Read the one for the area you're changing first; most design
  choices are explained there, including the ones that look odd.
- Keep the contract additive: a breaking change to `spec/openapi.yaml` needs a new major version.
- Tests come with the change, and nothing may log a card number, PIN block or secret.
- Test cards only. Never commit real card data, keys or certificates.
