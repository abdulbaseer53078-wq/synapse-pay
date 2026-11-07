# Step 5A: the card path, terminal to acquirer

A card payment from a terminal now travels the whole stack and back. Step 5B (the Android terminal app) and
Step 5C (PAX hardware) plug into this without changing it.

## How a payment flows

```text
Terminal (secure element encrypts the card; PIN pad encrypts the PIN)
   │  POST /api/v1/transactions, mutual TLS
   ▼
Envoy gateway         verifies the client certificate, checks the terminal is ACTIVE,
   │                  passes the terminal's ID on as x-terminal-id
   ▼
API backend           checks terminal, merchant, certification and daily limit; idempotency;
   │  (Python)        stores the transaction (BIN + last 4 only); never sees a card number
   ▼  encrypted card data only
Card service          decrypts in the HSM (simulated), checks the PIN block,
   │  (Rust)          sends ISO 8583 0200/0100, reverses (0400) if the answer never comes
   ▼  ISO 8583 over mutual TLS
Acquirer host         (mock_host.py in development)
```

Only the card service ever holds a clear card number, and only for the length of one request. It wipes it
from memory afterwards. Everything stored or logged anywhere shows at most `411111******1111`.

## Outcomes

| What happened | Status | Retry with the same idempotency_key? |
| :--- | :--- | :--- |
| Issuer approved | `CAPTURED` (or `AUTHORIZED` for `capture_mode: MANUAL`) | Replays the stored answer |
| Issuer declined | `FAILED`, `error.error_category` `HARD_DECLINE` / `SOFT_DECLINE` | Replays the stored answer |
| Host didn't answer, reversal confirmed | `FAILED`, `HOST_TIMEOUT`, `retryable: true` | Processed again (nothing was charged) |
| Host didn't answer, reversal failed too | `PENDING` | Replays `PENDING`: never charge twice; reconciliation settles it |
| Card service unreachable | HTTP 503, `retryable: true` | Processed again (nothing was sent) |
| Card data can't be decrypted | HTTP 400 `INVALID_REQUEST` | Fix the data |
| Terminal over its limit, unhealthy, uncertified | `FAILED`, `FORBIDDEN`, reason in the message | Replays |
| Same key, different body | HTTP 409 `IDEMPOTENCY_KEY_CONFLICT` | No |
| Same key, first request still running | HTTP 409, `retryable: true` | Yes, shortly |

## Card data format (simulated DUKPT)

`encrypted_card_data` and `pin_block` use the same envelope:

```text
sp1.<10-byte KSN, base64url>.<12-byte nonce + AES-256-GCM ciphertext and tag, base64url>
```

The key for each transaction is HKDF-SHA256 of the base derivation key (BDK) with the KSN as salt; the
additional authenticated data is `data` or `pin`. The plaintext is the PAN's digits, or an ISO 9564
format 0 PIN block. `backend/tests/card_sim.py` is a Python terminal that produces these; the Android app
will do the same in its simulated card reader.

**This is a stand-in.** Before any real card: an X9.24-3 AES DUKPT on the terminals, keys injected at a key
injection facility, and a real payment HSM holding the BDK. The card service's `Hsm` trait is where the real
one plugs in.

## Running it

You need PostgreSQL 16, Python 3.12+, Rust (cargo) and the `openssl` command.

```bash
# 1. Database
docker compose up -d db          # or any local PostgreSQL with user postgres / password postgres

# 2. Python dependencies
pip install -r backend/requirements.txt

# 3. Everything, including the end-to-end card payments (builds card-service on the first run)
cd backend && python -m pytest

# Just the end-to-end payments, with the measured latency printed
python -m pytest tests/test_transactions_e2e.py -s
```

The Rust parts have their own tests:

```bash
cd host-connector && cargo test
cd card-service && cargo test
```

### Running the card service by hand

```bash
cd card-service
SIM_HSM_BDK_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
HOST_ADDR=127.0.0.1:9000 HOST_SERVER_NAME=localhost \
HOST_CA=ca.pem HOST_CLIENT_CERT=client.pem HOST_CLIENT_KEY=client-key.pem \
HOST_DIALECT=../iso8583/dialects/synthetic-host.json AUDIT_LOG_PATH=iso-audit.jsonl \
cargo run
```

That BDK is the public test key. Never use it, or any key committed to a repository, for real cards.

The backend finds the card service at `CARD_SERVICE_URL` (default `http://127.0.0.1:7070`).

## Known shortcuts (marked `shortcut:` in the code)

- **Simulated HSM**, keyed from an environment variable (above).
- **PIN blocks are checked, not forwarded.** A real HSM re-encrypts the PIN for the acquirer (DE 52); the
  synthetic dialect has no DE 52 yet.
- **Acquirer terminal and merchant IDs** (DE 41/42) are derived from registry UUIDs. Acquirers assign these at
  onboarding; store them on the terminal and merchant records then.
- **Reversal records live in memory.** If the card service restarts between a timeout and its reversal, the
  transaction stays `PENDING`. A background reversal and reconciliation job is still to build, and so is
  cleanup of idempotency keys left `IN_FLIGHT` by a crash.
- **Card service API is plain HTTP on loopback.** In production it runs beside the HSM inside the PCI
  cardholder-data environment, reachable only from the backend (Unix socket or mutual TLS).
- **Terminals only.** Merchant backends (OAuth) get `401` from `/transactions` until the Merchant SDK (Step 6).
- **CARD only.** Other methods return `422`.
- **Daily limits use India time** for every merchant.

## Before real money

Synapse is where card data gets decrypted, so the card service and HSM are in full PCI DSS scope (P2PE
reduces the merchant's scope, not ours). Live cards also need an acquirer or sponsor bank, their certification
of the ISO 8583 integration, and the RBI authorisation that matches the business model.
