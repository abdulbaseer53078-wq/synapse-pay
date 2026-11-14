# 01 — API contract

Source of truth: `spec/openapi.yaml` (OpenAPI 3.1.0, API version 1.15.0; `spec/openapi.yaml:1-4`).
All paths are served under the `/api` server prefix (`spec/openapi.yaml:8-9`).

Every reference is `file:line`, relative to the repo root. Only the specification files (`spec/`) were read;
the backend was not consulted. Anything the spec does not state is marked **NOT IN SPEC**.

---

## 1. Authentication schemes

| Scheme | What it is | Ref |
| :--- | :--- | :--- |
| Default (when an operation has no `security` key) | `OAuth2ClientCredentials [transactions:write]` **or** `MutualTLS` | `spec/openapi.yaml:10-13` |
| `OAuth2ClientCredentials` | OAuth 2 client credentials, token URL `/v1/oauth/token`, scopes `transactions:write`, `transactions:read`, `registry:read`, `registry:write`, `registry:admin`, `certification:run`, `registry:authorize`, `audit:read` | `spec/openapi.yaml:1463-1476` |
| `SecretKey` | HTTP bearer, `sk_test_...` / `sk_live_...` (merchant server) | `spec/openapi.yaml:1477-1481` |
| `MutualTLS` | Terminal X.509 client cert; terminal_id is the URI SAN `urn:synapsepay:terminal:{terminal_id}` | `spec/openapi.yaml:1482-1491` |
| `security: []` / `[{}]` | No platform credential. Endpoints authenticate some other way (HMAC header, registration token, signed challenge, client_secret) or are public | per row below |

In the table below, **Auth Required** names the scheme, then the reference to its `security` line.

## 2. Endpoints

### 2.1 Inbound paths

| Method | Path | Summary | Auth Required |
| :--- | :--- | :--- | :--- |
| POST | `/v1/transactions` | Create a transaction (`spec/openapi.yaml:71-73`) | Yes, default: OAuth `transactions:write` or mTLS (no `security` key, so `spec/openapi.yaml:11-13` applies) |
| GET | `/v1/capabilities/{payment_method}` | Get the static capability descriptor for a payment method (`spec/openapi.yaml:113-115`) | Yes, OAuth `transactions:read` or mTLS (`spec/openapi.yaml:120-122`) |
| POST | `/v1/payment_intents` | Create a payment intent (merchant server) (`spec/openapi.yaml:150-152`) | Yes, SecretKey (`spec/openapi.yaml:156-157`) |
| GET | `/v1/payment_intents/{payment_intent_id}` | Retrieve a payment intent (`spec/openapi.yaml:180-182`) | Optional: SecretKey, **or** none with `?client_secret` (`spec/openapi.yaml:186-194`) |
| POST | `/v1/payment_intents/{payment_intent_id}/cancel` | Cancel a payment intent that's still waiting for the customer (`spec/openapi.yaml:204-206`) | Yes, SecretKey (`spec/openapi.yaml:207-208`) |
| POST | `/v1/payment_intents/{payment_intent_id}/confirm` | Pay a payment intent with a card (`spec/openapi.yaml:220-222`) | No platform credential; `client_secret` in body (`spec/openapi.yaml:228`, `:1907-1909`) |
| GET | `/v1/checkout/key` | The HSM's public checkout key (JWK, EC P-256) (`spec/openapi.yaml:248-250`) | No (`spec/openapi.yaml:251`) |
| GET | `/v1/merchants/me/recovery-stats` | Payments a backup acquirer saved (`spec/openapi.yaml:268-270`) | Yes, SecretKey (`spec/openapi.yaml:274-275`) |
| POST | `/v1/certifications` | Record a scheme certification for one exact firmware (`spec/openapi.yaml:290-292`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:298`) |
| GET | `/v1/certifications` | The certification matrix (`spec/openapi.yaml:314-316`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:317`) |
| POST | `/v1/certification-runs` | Record a certification test harness run (`spec/openapi.yaml:334-336`) | Yes, OAuth `certification:run` (`spec/openapi.yaml:343`) |
| PATCH | `/v1/certifications/{certification_id}` | Suspend, reactivate or re-date a certification (`spec/openapi.yaml:391-393`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:395`) |
| PUT | `/v1/device-models/{device_model}/minimum-firmware` | Set a model's minimum secure firmware (`spec/openapi.yaml:419-421`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:425`) |
| POST | `/v1/card-tokens` | Save a card for later payments, **deprecated** (`spec/openapi.yaml:453-456`) | Yes, SecretKey (`spec/openapi.yaml:461-462`) |
| DELETE | `/v1/card-tokens/{card_token}` | Forget a saved card, **deprecated** (`spec/openapi.yaml:486-489`) | Yes, SecretKey (`spec/openapi.yaml:492-493`) |
| POST | `/v1/transactions/{transaction_id}/refund` | Refund all or part of a payment (`spec/openapi.yaml:501-503`) | Yes, SecretKey (`spec/openapi.yaml:511-512`) |
| POST | `/v1/transactions/{transaction_id}/capture` | Capture an authorized payment in full (`spec/openapi.yaml:547-549`) | Yes, SecretKey (`spec/openapi.yaml:553-554`) |
| POST | `/v1/transactions/{transaction_id}/void` | Release an authorization that was never captured (`spec/openapi.yaml:568-570`) | Yes, SecretKey (`spec/openapi.yaml:574-575`) |
| GET | `/v1/reconciliation/runs` | Settlement reconciliation runs, newest first (`spec/openapi.yaml:589-591`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:595`) |
| GET | `/v1/reconciliation/runs/{run_id}` | One run and every item it found (`spec/openapi.yaml:611-613`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:614`) |
| GET | `/v1/reconciliation/runs/{run_id}/report.csv` | The run as CSV (`spec/openapi.yaml:633-635`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:636`) |
| GET | `/v1/chargebacks/{chargeback_id}` | One of the merchant's chargebacks (`spec/openapi.yaml:649-651`) | Yes, SecretKey (`spec/openapi.yaml:653-654`) |
| POST | `/v1/chargebacks/{chargeback_id}/evidence` | Defend a chargeback, once, before its deadline (`spec/openapi.yaml:666-668`) | Yes, SecretKey (`spec/openapi.yaml:672-673`) |
| POST | `/v1/webhooks/chargebacks` | The acquirer reports a chargeback (`spec/openapi.yaml:702-704`) | No platform credential; HMAC `X-Signature` over `"<X-Timestamp>.<raw body>"` (`spec/openapi.yaml:706-713`) |
| POST | `/v1/webhooks/chargebacks/resolution` | The acquirer reports a chargeback's outcome (`spec/openapi.yaml:738-740`) | No platform credential; same HMAC (`spec/openapi.yaml:741-745`) |
| GET | `/v1/terminals` | List the merchant's terminals (`spec/openapi.yaml:765-767`) | Yes, OAuth `registry:read`, `:write` or `:admin` (`spec/openapi.yaml:768`) |
| POST | `/v1/terminals` | Create a terminal record (registration phase 1) (`spec/openapi.yaml:793-795`) | Yes, OAuth `registry:write` (`spec/openapi.yaml:799-800`) |
| POST | `/v1/terminals/{terminal_id}/register` | Submit a CSR (registration phase 2) (`spec/openapi.yaml:819-821`) | No platform credential; `registration_token` in body (`spec/openapi.yaml:823`, `:826`) |
| POST | `/v1/terminals/{terminal_id}/activate` | Prove key possession and activate (phase 3) (`spec/openapi.yaml:845-847`) | No platform credential; signed challenge (`spec/openapi.yaml:848-849`) |
| POST | `/v1/terminals/{terminal_id}/suspend` | ACTIVE → SUSPENDED (`spec/openapi.yaml:871-873`) | Yes, OAuth `registry:write` or `:admin` (`spec/openapi.yaml:874`) |
| POST | `/v1/terminals/{terminal_id}/reinstate` | SUSPENDED → ACTIVE, admin only (`spec/openapi.yaml:887-889`) | Yes, OAuth `registry:admin` (`spec/openapi.yaml:890`) |
| POST | `/v1/terminals/{terminal_id}/revoke` | → REVOKED, revokes the cert at the CA (`spec/openapi.yaml:895-897`) | Yes, OAuth `registry:write` or `:admin` (`spec/openapi.yaml:898`) |
| POST | `/v1/terminals/{terminal_id}/decommission` | → DECOMMISSIONED, merchant only (`spec/openapi.yaml:903-905`) | Yes, OAuth `registry:write` (`spec/openapi.yaml:906`) |
| GET | `/v1/terminals/{terminal_id}/checkout` | The next payment intent this terminal should take, long poll (`spec/openapi.yaml:911-913`) | Yes, mTLS (`spec/openapi.yaml:917-918`) |
| POST | `/v1/terminals/{terminal_id}/heartbeat` | Signed terminal heartbeat (`spec/openapi.yaml:939-941`) | No platform credential; `X-Signature` with the terminal cert's key (`spec/openapi.yaml:949-958`) |
| GET | `/v1/terminals/{terminal_id}` | Read one terminal (`spec/openapi.yaml:990-992`) | Yes, OAuth `registry:read`, `:write` or `:admin` (`spec/openapi.yaml:993`) |
| PATCH | `/v1/terminals/{terminal_id}` | Replace the terminal's metadata (`spec/openapi.yaml:1005-1007`) | Yes, OAuth `registry:write` or `:admin` (`spec/openapi.yaml:1011`) |
| GET | `/v1/terminals/{terminal_id}/certificates` | Certificate history, newest first (`spec/openapi.yaml:1035-1037`) | Yes, OAuth `registry:read`, `:write` or `:admin` (`spec/openapi.yaml:1038`) |
| GET | `/v1/terminals/{terminal_id}/heartbeats` | Recent heartbeats, newest first (`spec/openapi.yaml:1055-1057`) | Yes, OAuth `registry:read`, `:write` or `:admin` (`spec/openapi.yaml:1058`) |
| GET | `/v1/terminals/{terminal_id}/events` | Complete status change history (`spec/openapi.yaml:1078-1080`) | Yes, OAuth `registry:read`, `:write` or `:admin` (`spec/openapi.yaml:1081`) |
| GET | `/v1/terminals/{terminal_id}/authorization` | May this terminal run this method for this amount now? (`spec/openapi.yaml:1098-1100`) | Yes, OAuth `registry:authorize` (`spec/openapi.yaml:1108`) |
| POST | `/v1/transactions/sync` | Upload a batch of transactions accepted offline (`spec/openapi.yaml:1132-1134`) | Yes, mTLS or OAuth `transactions:write` (`spec/openapi.yaml:1165-1167`) |
| POST | `/v1/webhooks/wallet` | Wallet provider callback (`spec/openapi.yaml:1260-1262`) | No platform credential; HMAC `X-Wallet-Signature` (`spec/openapi.yaml:1268-1278`) |
| POST | `/v1/webhooks/upi` | PSP/NPCI callback for a UPI payment (`spec/openapi.yaml:1310-1312`) | No platform credential; HMAC `X-UPI-Signature` (`spec/openapi.yaml:1321-1332`) |
| GET | `/v1/audit/events` | Read the append-only audit log (`spec/openapi.yaml:1368-1370`) | Yes, OAuth `audit:read` (`spec/openapi.yaml:1377`) |
| GET | `/v1/audit/chain` | Current position of the audit hash chain (`spec/openapi.yaml:1416-1418`) | Yes, OAuth `audit:read` (`spec/openapi.yaml:1422`) |

### 2.2 Outbound webhooks (Synapse Pay → merchant)

| Method | Name | Summary | Auth |
| :--- | :--- | :--- | :--- |
| POST | `transactionStatus` | Final transaction status, sent to the request's `webhook_url` (`spec/openapi.yaml:42-45`) | HMAC-SHA256 `X-Signature` over the raw body, per-merchant secret (`spec/openapi.yaml:46-59`) |
| POST | `chargebackStatus` | A chargeback opened, won or lost (`spec/openapi.yaml:15-18`) | Same `X-Signature` as transactionStatus (`spec/openapi.yaml:20`, `:24-28`) |

---

## 3. Core data models

Required fields only, as the task asks. Types are the spec's JSON Schema types.

### 3.1 `TransactionRequest` (body of `POST /v1/transactions`): `spec/openapi.yaml:2103-2185`

`additionalProperties: false` (`spec/openapi.yaml:2105`). Required list: `spec/openapi.yaml:2106-2113`.

| Field | Type | Constraints | Ref |
| :--- | :--- | :--- | :--- |
| `idempotency_key` | string | `format: uuid` | `spec/openapi.yaml:2115-2120` |
| `amount` | integer | `format: int64`, `minimum: 1`, minor units | `spec/openapi.yaml:2121-2127` |
| `currency` | string | `^[A-Z]{3}$`, ISO 4217 | `spec/openapi.yaml:2128-2132` |
| `payment_method` | string | enum `CARD, UPI, WALLET, QR, OFFLINE` | `spec/openapi.yaml:2133-2135` |
| `method_details` | object | shape chosen by `payment_method` via `allOf` if/then | `spec/openapi.yaml:2136-2138`, `:2175-2185` |
| `terminal_id` | string | `minLength: 1` | `spec/openapi.yaml:2139-2142` |
| `merchant_id` | string | `minLength: 1` | `spec/openapi.yaml:2143-2146` |

Optional: `customer_ref`, `capture_mode` (`AUTO`/`MANUAL`, default `AUTO`), `description`, `metadata` (string→string),
`webhook_url` (`^https://`), `payment_intent_id` (`^pi_[0-9a-f]{32}$`) (`spec/openapi.yaml:2147-2172`).

### 3.2 `method_details` variants

| Model | Required fields (type) | Ref |
| :--- | :--- | :--- |
| `CardDetails` | `card_network` (string enum `VISA, MASTERCARD, RUPAY, AMEX`), plus exactly one of {`encrypted_card_data` (string) + `card_expiry` (string `MM/YY`)} or {`card_token` (string, deprecated)} | `spec/openapi.yaml:2597-2634` |
| `UpiDetails` | `vpa` (string, pattern), `flow_type` (string enum `COLLECT, INTENT, MANDATE`); `mandate_details` (object) required iff `MANDATE` | `spec/openapi.yaml:2652-2670` |
| `WalletDetails` | `wallet_provider` (string enum `PAYTM, PHONEPE, AMAZON_PAY`); `wallet_token` optional | `spec/openapi.yaml:2672-2686` |
| `QrDetails` | `qr_data` (string), `qr_standard` (string enum), `qr_encoded_rail` (string enum `UPI, CARD_SCHEME, WALLET, UNKNOWN`) | `spec/openapi.yaml:2688-2711` |
| `OfflineDetails` | `offline_reference` (string), `offline_limits` (object: `per_transaction`, `per_day`, both integer int64), `local_fraud_score` (number) | `spec/openapi.yaml:2713-2736` |

### 3.3 `TransactionResponse`: `spec/openapi.yaml:2187-2243`

| Field | Type | Ref |
| :--- | :--- | :--- |
| `transaction_id` | string | `spec/openapi.yaml:2199-2201` |
| `idempotency_key` | string, uuid (reuses request def) | `spec/openapi.yaml:2203` |
| `status` | `TransactionStatus` | `spec/openapi.yaml:2204` |
| `amount` | integer int64 (reuses request def) | `spec/openapi.yaml:2205` |
| `currency` | string (reuses request def) | `spec/openapi.yaml:2206` |
| `payment_method` | string enum (reuses request def) | `spec/openapi.yaml:2207` |
| `created_at` | string, date-time | `spec/openapi.yaml:2226-2229` |
| `updated_at` | string, date-time | `spec/openapi.yaml:2230-2233` |
| `error` | `Error`: required **iff** `status == FAILED`, forbidden otherwise | `spec/openapi.yaml:2234-2236`, `:2241-2243` |

Optional: `method_reference`, `auth_code`, `next_action` {`type`: `WALLET_REDIRECT`/`THREE_DS_REDIRECT`, `url`}, `payment_intent_id`, `metadata` (`spec/openapi.yaml:2208-2240`).

### 3.4 `TransactionStatus`: `spec/openapi.yaml:2249-2282`

String enum: `INITIATED, PENDING, PENDING_OFFLINE, AUTHORIZED, CAPTURED, SETTLED, VOIDED, FAILED, REFUNDED, PARTIALLY_REFUNDED` (`spec/openapi.yaml:2251-2261`).
Allowed transitions: `spec/openapi.yaml:2269-2274`. `PENDING_OFFLINE` is never written by the cloud (`spec/openapi.yaml:2265-2268`).

### 3.5 `CreatePaymentIntentRequest`: `spec/openapi.yaml:1891-1903`

| Field | Type | Constraints | Ref |
| :--- | :--- | :--- | :--- |
| `idempotency_key` | string | uuid | `spec/openapi.yaml:1896` |
| `amount` | integer | int64, `minimum: 100` (₹1.00) | `spec/openapi.yaml:1897` |
| `currency` | string | enum `[INR]` only | `spec/openapi.yaml:1898` |

Required list: `spec/openapi.yaml:1894`.

### 3.6 `PaymentIntent`: `spec/openapi.yaml:2057-2092`

Required (`spec/openapi.yaml:2059`): `id` (string, `pi_` + 32 hex; `:2061`), `status` (string enum `REQUIRES_PAYMENT_METHOD, REQUIRES_ACTION, PROCESSING, SUCCEEDED, CANCELED`; `:2062-2068`), `amount` (integer int64; `:2069`), `currency` (string; `:2070`), `capture_mode` (string enum `AUTO, MANUAL`; `:2071`), `created_at`, `updated_at`, `expires_at` (string date-time; `:2090-2092`).

### 3.7 `ConfirmPaymentIntentRequest`: `spec/openapi.yaml:1904-1922`

Required: `client_secret` (string), `card` (object) (`spec/openapi.yaml:1907-1911`). `card` requires `encrypted_card_data` (string), `card_expiry` (string `MM/YY`), `card_network` (string enum) (`spec/openapi.yaml:1914-1921`).

### 3.8 `CheckoutJob`: `spec/openapi.yaml:2093-2102`

Required: `payment_intent_id` (string), `amount` (integer int64), `currency` (string), `capture_mode` (string enum), `expires_at` (string date-time) (`spec/openapi.yaml:2095-2102`).

### 3.9 `Refund`: `spec/openapi.yaml:2007-2023`

Required (`spec/openapi.yaml:2010`): `refund_id` (string `^rfnd_[0-9a-f]{32}$`; `:2012`), `transaction_id` (string `^txn_[0-9a-f]{32}$`; `:2013`), `amount` (integer, min 1; `:2014`), `status` (string enum `PENDING, COMPLETED, FAILED`; `:2015-2018`), `created_at`, `updated_at` (date-time; `:2022-2023`).
Refund request body requires only `amount` (integer, min 1, minor units) (`spec/openapi.yaml:526-528`).

### 3.10 `Chargeback`: `spec/openapi.yaml:1954-1972`

Required (`spec/openapi.yaml:1956`): `chargeback_id` (string `^cb_[0-9a-f]{32}$`), `amount` (integer, min 1), `currency` (string), `reason_code` (string), `status` (string enum `PENDING, UNDER_REVIEW, WON, LOST`), `evidence_deadline`, `created_at` (date-time) (`spec/openapi.yaml:1958-1971`).

### 3.11 Offline sync item (`POST /v1/transactions/sync`): `spec/openapi.yaml:1181-1234`

Required (`spec/openapi.yaml:1184-1185`): `offline_reference` (string uuid), `local_timestamp` (string date-time), `idempotency_key`, `amount`, `currency`, `payment_method`, `terminal_id`, `merchant_id` (all `$ref` to the `TransactionRequest` definitions; `:1198-1203`), `underlying_rail` (string enum `CARD, UPI, WALLET, QR`; `:1204-1210`), `method_details` (`:1211`), `signature` (string, base64; `:1229-1234`). Batch: 1–100 items (`spec/openapi.yaml:1178-1180`).

### 3.12 `Error`: `spec/openapi.yaml:2284-2337`

Required (`spec/openapi.yaml:2287`): `error_code` (string enum; `:2289-2322`), `error_message` (string; `:2323-2325`), `error_category` (string enum `SOFT_DECLINE, HARD_DECLINE, SYSTEM_ERROR, VALIDATION_ERROR, AUTHENTICATION_ERROR`; `:2326-2331`), `retryable` (boolean; `:2332-2337`).
Declines are not HTTP errors: they return 201 with `status: FAILED` and the error inside the transaction (`spec/openapi.yaml:1510-1511`).

### 3.13 `Terminal`: `spec/openapi.yaml:2514-2531`

Required (`spec/openapi.yaml:2516-2517`): `terminal_id` (uuid), `merchant_id` (uuid), `device_serial`, `device_model` (string), `firmware_version` (string|null), `status` (`TerminalStatus`), `health_state` (enum `HEALTHY, DEGRADED, UNREACHABLE`), `last_heartbeat_at` (date-time|null), `certification_profile_id` (uuid|null), `registered_at` (date-time), `activated_at` (date-time|null), `status_changed_at` (date-time), `metadata` (object string→string) (`spec/openapi.yaml:2519-2531`).

---

## 4. Idempotency

**There are two mechanisms, and which one applies depends on the endpoint.**

### 4.1 Body field `idempotency_key` (not a header)

| Endpoint | Required? | Ref |
| :--- | :--- | :--- |
| `POST /v1/transactions` | **Required**, UUID, client-generated | `spec/openapi.yaml:2107`, `:2115-2120` |
| `POST /v1/payment_intents` | **Required**, UUID | `spec/openapi.yaml:1894`, `:1896` |
| `POST /v1/transactions/sync` (per item) | **Required**, UUID; `offline_reference` is the per-item key of the batch | `spec/openapi.yaml:1184`, `:1190`, `:1198` |

Contract:
- Same key, same body → the original response, not reprocessed; `createTransaction` answers **201** again (`spec/openapi.yaml:88-90`).
- Payment intents: same key, same body → **200** with the same intent; a different body → **409** (`spec/openapi.yaml:154`, `:169-170`).
- Same key, different body → **409** `IDEMPOTENCY_KEY_CONFLICT`, `VALIDATION_ERROR`, not retryable (`spec/openapi.yaml:1507-1509`, `:1523-1528`).
- A `retryable: true` failure must **not** be stored as the key's result, so a retry re-runs (`spec/openapi.yaml:2332-2337`).

Left open by the spec:
- Key scope (global, per merchant, or per terminal): **NOT IN SPEC**; it only says "if the same key is sent twice" (`spec/openapi.yaml:2119`).
- How "same body" is compared (byte-equal vs canonical JSON): **NOT IN SPEC**.
- Response to a retry while the first request is still in flight: **NOT IN SPEC**.
- Key retention / expiry: **NOT IN SPEC**.

### 4.2 `Idempotency-Key` HTTP header: refunds only

- `POST /v1/transactions/{transaction_id}/refund` takes an `Idempotency-Key` header, **required**, UUID (`spec/openapi.yaml:515-518`).
- Same key → the same refund (**200**) whatever state it reached; same key, different body → **409** (`spec/openapi.yaml:505-506`, `:536-537`).
- First call → **201** with the refund (`spec/openapi.yaml:531`).
- Status for a missing or malformed header: **NOT IN SPEC** (400 is listed for the operation, `spec/openapi.yaml:541`, but not tied to the header).
- No other endpoint declares an `Idempotency-Key` header: **NOT IN SPEC** elsewhere.

### 4.3 Idempotent without a key

| Endpoint | Behaviour | Ref |
| :--- | :--- | :--- |
| `POST .../capture` | capturing twice returns the same result | `spec/openapi.yaml:551-552` |
| `POST .../void` | voiding twice returns the same result | `spec/openapi.yaml:572-573` |
| `POST .../confirm` | an intent not in `REQUIRES_PAYMENT_METHOD` is returned as is, never charged again | `spec/openapi.yaml:225-226` |
| `POST /v1/card-tokens` | the same card returns the same token | `spec/openapi.yaml:459-460` |
| Inbound UPI webhook | deduplicated on `event_id`; a repeat gets 200 and changes nothing | `spec/openapi.yaml:1317-1319`, `:1345` |
| Inbound wallet webhook | same contract as UPI, delivery ids namespaced per provider | `spec/openapi.yaml:1264-1267` |
| Inbound chargeback notices | applied once per `event_id` and once per `case_id` | `spec/openapi.yaml:709`, `:741` |
| Edge sync | a resent item must be identical, and the next one must continue the chain | `spec/openapi.yaml:1159-1160` |
| Outbound `chargebackStatus` | **may arrive more than once**, so receivers must dedupe | `spec/openapi.yaml:22` |

---

## 5. Monetary amounts

**Integer minor units, never floats.**

- `TransactionRequest.amount`: `type: integer`, `format: int64`, `minimum: 1`, "Smallest currency unit (paise for INR). 50000 = ₹500.00. Never use floats." (`spec/openapi.yaml:2121-2127`). The response, sync items and capability lookups `$ref` this same definition (`spec/openapi.yaml:2205`, `:1199`).
- Currency is a separate field, ISO 4217, `^[A-Z]{3}$` (`spec/openapi.yaml:2128-2132`). Payment intents accept **only `INR`** (`spec/openapi.yaml:1898`).
- Other money fields, all integers in minor units:

| Field | Ref |
| :--- | :--- |
| Payment intent `amount` (int64, min 100 = ₹1.00) | `spec/openapi.yaml:1897`, `:2069` |
| Refund request `amount` ("Minor units") | `spec/openapi.yaml:528` |
| Authorization query `amount` ("Minor units.") | `spec/openapi.yaml:1115-1119` |
| `TerminalAuthorization.limits` ("Minor units.") | `spec/openapi.yaml:2588-2594` |
| `OfflineDetails.offline_limits` (int64, "smallest currency unit") | `spec/openapi.yaml:2726-2731` |
| `CapabilityDescriptor.offline_limits.max_per_txn` ("Minor units") | `spec/openapi.yaml:2388` |
| `Chargeback.amount`, chargeback notice `amount` | `spec/openapi.yaml:1960`, `:728` |
| `RecoveryStats.recovered_amount[].amount` ("minor units") | `spec/openapi.yaml:2049-2056` |
| Reconciliation `bank_credited`, `expected_/gross_/fee_/net_amount` | `spec/openapi.yaml:1982`, `:2002-2005` |

- The only `type: number` fields aren't money: `local_fraud_score` (`spec/openapi.yaml:2732-2733`) and the checkout `wait` seconds (`spec/openapi.yaml:927`).
- Upper bound on any amount (`maximum`): **NOT IN SPEC**.
- Currency exponent (how many minor units per major unit, e.g. JPY 0, KWD 3): **NOT IN SPEC**; only the INR example is given (`spec/openapi.yaml:2121-2127`).

---

## 6. Error handling

### 6.1 Error body

Every error uses the `Error` schema: `error_code`, `error_message`, `error_category`, `retryable`, all required, no extra properties (`spec/openapi.yaml:2284-2288`). Field types are in §3.12. `error_category` drives the Cascade Engine: `SOFT_DECLINE` cascades to another acquirer, `HARD_DECLINE` stops (`spec/openapi.yaml:2326-2331`). Clients must handle an unknown `error_code` by its `error_category` (`spec/openapi.yaml:2321-2322`).

### 6.2 Declines are not HTTP errors

A payment declined by the issuer/network (insufficient funds included) returns **HTTP 201** with `status: FAILED` and the `Error` inside the transaction's `error` field (`spec/openapi.yaml:1510-1511`, `:2234-2236`, `:2241-2243`).

**Insufficient funds**: `error_code: INSUFFICIENT_FUNDS` (`spec/openapi.yaml:2292`), shown as `HARD_DECLINE`, `retryable: false` in the card, wallet and offline failure examples (`spec/openapi.yaml:1573-1577`, `:1650-1654`, `:1727-1731`), delivered in a 201 response (`spec/openapi.yaml:87`, `:97`). The schema does not pin a category per code; the category comes only from the examples, so a fixed `INSUFFICIENT_FUNDS → HARD_DECLINE` mapping is **NOT IN SPEC**.

A soft-decline example: `HOST_TIMEOUT` with `SOFT_DECLINE` (`spec/openapi.yaml:1690-1692`).

### 6.3 HTTP status codes (request rejected before a transaction exists)

The shared `Error` response defines them (`spec/openapi.yaml:1504-1511`):

| Status | Meaning per spec | Ref |
| :--- | :--- | :--- |
| 400 | invalid body | `spec/openapi.yaml:1506` |
| 401 | not authenticated | `spec/openapi.yaml:1507` |
| 403 | missing scope, or `terminal_id` doesn't match the client certificate | `spec/openapi.yaml:1507-1508` |
| 404 | unknown terminal on a terminal path | `spec/openapi.yaml:1508` |
| 409 | `idempotency_key` reused with a different body, or a conflicting state | `spec/openapi.yaml:1508-1509` |
| 422 | unknown terminal or merchant, or an unapproved device model | `spec/openapi.yaml:1509-1510` |
| 5XX | server error | `spec/openapi.yaml:1510` |
| 422 (capture) | `OPERATION_NOT_SUPPORTED` for a rail that can't capture yet | `spec/openapi.yaml:552` |
| 503 | inbound webhooks: no secret configured | `spec/openapi.yaml:736`, `:763`, `:1308`, `:1366` |

`POST /v1/transactions` declares 201, 400, 401, 403, 409, 422, 5XX (`spec/openapi.yaml:87-111`); 404 is not among them.

### 6.4 Codes with no HTTP status assigned

The enum lists `TRANSACTION_NOT_REFUNDABLE`, `TRANSACTION_NOT_CAPTURABLE`, `TRANSACTION_NOT_VOIDABLE`, `REFUND_EXCEEDS_AMOUNT`, `OUTCOME_UNKNOWN`, `NETWORK_REFUSED`, `CHARGEBACK_NOT_DISPUTABLE`, `CHARGEBACK_EVIDENCE_LATE`, `TRANSACTION_IN_DISPUTE` (`spec/openapi.yaml:2307-2318`). Which HTTP status each returns is **NOT IN SPEC**. The refund, capture and void operations declare both 409 and 422 (`spec/openapi.yaml:544-545`, `:565-566`, `:586-587`) without saying which code maps to which.

---

## 7. Inconsistencies found while reading

Each of these is verifiable at the reference given.

1. **Example IDs don't match the ID patterns.** The examples use `txn_01JC8Z1K2M3N4P5Q6R7S8T9V0W` (ULID-style; `spec/openapi.yaml:1551`), but paths require `^txn_[0-9a-f]{32}$` (`spec/openapi.yaml:514`). Likewise, example `terminal_id: term_blr_001` and `merchant_id: merch_1001` (`spec/openapi.yaml:1542-1543`) aren't UUIDs, but terminals and merchants are UUIDs everywhere else (`spec/openapi.yaml:1454`, `:2432`). `TransactionRequest.terminal_id`/`merchant_id` are only `minLength: 1` (`spec/openapi.yaml:2139-2146`), so the schema doesn't catch this.
2. **409 covers two cases with one example.** 409 means "reused with a different body **or** a conflicting state" (`spec/openapi.yaml:1508-1509`), but the only 409 example is `IDEMPOTENCY_KEY_CONFLICT` / `VALIDATION_ERROR` / not retryable (`spec/openapi.yaml:1523-1528`). The code and category for a conflicting state: **NOT IN SPEC**.
3. **QR rail naming.** The capabilities endpoint says to use the descriptor of `qr_encoded_rail` "(UPI, CARD or WALLET)" (`spec/openapi.yaml:118-119`), but the enum value is `CARD_SCHEME`, not `CARD` (`spec/openapi.yaml:2708`).
4. **OFFLINE transitions disagree.** `OfflineCapabilities` lists `AUTHORIZED → SETTLED` but no transition into `AUTHORIZED` (`spec/openapi.yaml:1830-1835`). `TransactionStatus` says OFFLINE goes `INITIATED → PENDING → AUTHORIZED → SETTLED` (`spec/openapi.yaml:2280`).
5. **ID formats disagree.** `ReconciliationItem.transaction_id` is `format: uuid` (`spec/openapi.yaml:2000`), while every other public `transaction_id` is `txn_…` (`spec/openapi.yaml:1959`, `:2013`).
6. **Token endpoint is missing from the spec.** OAuth `tokenUrl: /v1/oauth/token` (`spec/openapi.yaml:1467`) has no path definition.
7. **Error codes missing from the enum.** `CERTIFICATION_RUN_REQUIRED` (`spec/openapi.yaml:296`) and the sync reasons `EDGE_MISMATCH` / `OFFLINE_DAILY_LIMIT_EXCEEDED` (`spec/openapi.yaml:1155`, `:1163`) aren't in `Error.error_code` (`spec/openapi.yaml:2290-2318`). The spec says clients must handle unknown codes by category (`spec/openapi.yaml:2321-2322`), so this is tolerated, but the enum is incomplete.
8. **Chargeback currency has no pattern.** `Chargeback.currency` is a bare string (`spec/openapi.yaml:1961`), but the notice that creates it requires `^[A-Z]{3}$` (`spec/openapi.yaml:729`).
