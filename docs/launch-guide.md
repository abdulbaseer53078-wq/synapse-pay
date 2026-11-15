# Synapse Pay — Launch Guide

This guide walks you through running the full sandbox, logging into the merchant flow, and processing your first test payment.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Docker Desktop | any recent | https://www.docker.com/products/docker-desktop |
| Python | 3.12+ | https://www.python.org/downloads |
| Rust / cargo | stable | https://rustup.rs |
| PowerShell | 7+ | pre-installed on Windows 11 |

---

## 1. Start the full stack

Open a PowerShell 7 terminal at the repo root and run:

```powershell
.\run_dev.ps1
```

This script does the following automatically:

1. **Generates dev keys** — RSA key pair and mTLS CA certificate (first run only).
2. **Starts Postgres** via `docker compose up -d db`.
3. **Applies all migrations** in `db/migrations/` in order.
4. **Creates a sandbox merchant** and prints its credentials — save these.
5. **Starts the mock bank** (`host-connector/mock_host/`) — simulates HDFC's ISO 8583 host.
6. **Builds and starts the Rust card service** — handles encryption, HSM key derivation, and ISO 8583.
7. **Starts FastAPI** at `http://localhost:8000`.

The script prints something like:

```
[✓] Sandbox merchant created:
    merchant_id  : 3f7e...
    secret_key   : sk_test_XXXXXXXXXXXXXXXXXXXX
    webhook_secret: whsec_XXXXXXXXXXXXXXXXXXXX
```

**Copy the `secret_key`** — it is shown only once.

---

## 2. Verify the backend is up

```powershell
curl http://localhost:8000/live
```

Expected: `{"status":"ok"}` (or similar). The Swagger UI is at `http://localhost:8000/docs`.

---

## 3. Open the Merchant Dashboard

Serve the frontend and open the dashboard:

```powershell
python -m http.server 3000 --directory frontend
```

Visit `http://localhost:3000/dashboard/index.html` and sign in with your `sk_test_…` key.

The dashboard includes Overview, Settlements, Risk Holds, API Keys, and KYC pages.

## 4. Submit KYC (required for live keys)

In the dashboard, navigate to **KYC** (`http://localhost:3000/dashboard/kyc.html`).

1. Enter a valid PAN (`ABCDE1234F`) and GST (`29ABCDE1234F1Z5`) number.
2. Click **Submit for Review**.

In the sandbox you can manually approve KYC via psql:

```sql
UPDATE merchant_kyc SET status = 'APPROVED' WHERE merchant_id = '<your-merchant-id>';
```

Once approved, the KYC page shows a green banner and you can generate `sk_live_` keys.

---

## 5. Generate a live API key

```powershell
curl -X POST http://localhost:8000/api/v1/api-keys `
  -H "Authorization: Bearer sk_test_XXXX" `
  -H "Content-Type: application/json"
```

This returns a `sk_live_...` key. The key is shown only once. Without approved KYC you get:

```json
{ "error_code": "KYC_REQUIRED", "error_message": "KYC must be approved before generating live keys" }
```

---

## 6. Process a test payment

Open `frontend/demo.html` in a browser. Edit the two constants at the top of the `<script>`:

```js
const BACKEND_URL = "http://localhost:8000";
const API_KEY     = "sk_live_XXXX";   // ← replace with the key from step 5
```

Click **Pay ₹500**. The SDK will:

1. Fetch the RSA public key from `/api/v1/checkout/key`.
2. Create a checkout session via the backend.
3. Open an inline form, RSA-encrypt the card data in the browser, and POST it to `/api/v1/checkout/sessions/{id}/pay`.

**Test card numbers** (accepted by the mock bank):

| Number | Expiry | CVV | Result |
|--------|--------|-----|--------|
| `4111 1111 1111 1111` | any future | any | APPROVED |
| `4000 0000 0000 0002` | any future | any | DECLINED |

---

## 7. Check settlements

You can also view settlements in the dashboard at `http://localhost:3000/dashboard/settlements.html`, or via the API:

```powershell
curl http://localhost:8000/api/v1/settlements `
  -H "Authorization: Bearer sk_live_XXXX"
```

Each settlement row shows gross amount, MDR (0% for subscription merchants), GST, and net payout.

---

## 8. Run the tests

```powershell
# Python backend
cd backend
pytest -q

# Rust card-service
cd ../card-service
cargo test

# Rust ISO 8583 parser
cd ../iso8583
cargo test

# Edge node offline engine
cd ../edge-node
pytest -q
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `docker compose up` fails | Ensure Docker Desktop is running |
| `cargo build` fails | Run `rustup update stable` |
| `KYC_REQUIRED` on key create | Approve KYC in psql (step 4) |
| `FRAUD_DETECTED` 429 | 5+ failed attempts in 60 s from your IP; wait 1 minute |
| Card service unreachable | Check the Rust process started (step 1 output) |

---

## Architecture summary

```
Browser / POS  →  Envoy (mTLS)  →  FastAPI  →  Rust card-service  →  Mock bank
                                       ↓
                                  PostgreSQL
                                  (idempotency, settlements, audit)
```

For a full architecture diagram see [`README.md`](../README.md).
