# 03 — Rust card-service

Scope: `card-service/` only (`src/` and `tests/`). Every reference is `file:line`, relative to the repo root.

**Out of scope, and where it matters.** card-service depends on two sibling crates (`card-service/Cargo.toml:10-11`):
- `host_connector`: TLS links, connection pools, STAN source, ISO 8583 message building, and the
  response-code → `INSUFFICIENT_FUNDS` mapping.
- `iso8583`: the field dictionary.

These weren't read, as you asked. Every statement below about what happens inside them is marked
**NOT IN CARD-SERVICE**.

Items tagged **PRODUCTION RISK** are simulated, hardcoded, or explicitly marked `shortcut:` in the code.

---

## 1. Entry point

| What | Ref |
| :--- | :--- |
| Process entry, `#[tokio::main] async fn main` | `card-service/src/main.rs:122-123` |
| Listens on `CARD_SERVICE_ADDR`, default `127.0.0.1:7070` | `card-service/src/main.rs:219-220` |
| Router: `POST /card/transactions` → `transaction` | `card-service/src/http.rs:31` |
| Handler: reads `x-trace-id` (only 32 lowercase hex, else dropped), calls `CardFlow::process` | `card-service/src/http.rs:43-53` |
| Success → **200** + `CardResult` JSON | `card-service/src/http.rs:50` |
| `BadCardData` → **422**, `BadRequest` → **400** (no host contacted) | `card-service/src/http.rs:55-64` |
| Request body `CardRequest` (`transaction_id`, `kind` PURCHASE/AUTHORIZATION, `amount` u64, `currency`, acquirer TID/MID, `encrypted_card_data`, `card_expiry`, `pin_block`, `emv_data`, `host_hint`, …) | `card-service/src/flow.rs:24-58` |

The Python backend posts to `/card/transactions`. The 400 and 422 above become the backend's `BadCardData`; any other non-200 becomes "outcome unknown" (see doc 02).

> **PRODUCTION RISK: unauthenticated internal API.** "Never expose it: it is not authenticated." Plain HTTP on
> loopback, flagged `shortcut:` to become a Unix socket or mTLS sidecar inside the PCI cardholder-data environment
> (`card-service/src/http.rs:1-4`). Anything that can reach the port can submit card transactions and read the
> fleet health. Binding to a non-loopback `CARD_SERVICE_ADDR` exposes it.

### Startup wiring (`main`)

1. Refuse to start if card-data storage is requested without `CARD_DATA_STORAGE=sandbox` (PCI freeze) (`card-service/src/main.rs:124-130`).
2. Load the checkout key, or generate one (`:131-141`).
3. Build the `SimHsm` from `SIM_HSM_BDK_HEX` (`:142`).
4. Open the append-only audit file `AUDIT_LOG_PATH` (`:143-145`).
5. Create the STAN source, with one slot per instance (`:147-150`).
6. Start one pool per acquirer. Single-host mode if `HOSTS` is empty, fleet mode otherwise (`:151-178`). Then wait up to 10 s for each pool to be ready (`:180-183`).
7. Wrap the pools in a `Fleet`, which is the only `HostConnector` the flow sees (`:185-188`).
8. Optionally create the vault and the durable reversal queue (`:190-215`), then build `CardFlow` (`:216`).

---

## 2. Execution path of one payment (`CardFlow::process`)

`card-service/src/flow.rs:218-281`

| # | Step | Ref |
| :--- | :--- | :--- |
| 1 | Get the clear PAN: decrypt `encrypted_card_data` in the HSM, or resolve `card_token` from the vault. Exactly one must be given | `card-service/src/flow.rs:198-216`, `:219` |
| 2 | `MM/YY` → `YYMM` (DE 14); reject a bad month or length | `card-service/src/flow.rs:164-173`, `:220` |
| 3 | If there is a `pin_block`, check it in the HSM (it is not forwarded; see §3.4) | `card-service/src/flow.rs:221-223` |
| 4 | Keep BIN (first 6) and last 4 for the response | `card-service/src/flow.rs:224`, `card-service/src/hsm.rs:89-96` |
| 5 | `emv_data` → bytes: even-length uppercase hex, ≤ 255 bytes (DE 55) | `card-service/src/flow.rs:175-182`, `:225` |
| 6 | Build the connector `Transaction` (see §4) | `card-service/src/flow.rs:226-237` |
| 7 | One deadline for the whole send, `HOST_TIMEOUT_MS`, default 1500 ms; pass along the host hint | `card-service/src/flow.rs:240-241`, `card-service/src/main.rs:185` |
| 8 | `self.host.send_transaction(...)`, where `host` is the `Fleet` (§5) | `card-service/src/flow.rs:242` |
| 9 | Record which host actually answered | `card-service/src/flow.rs:244-247` |
| 10 | Map the result to `Outcome` via `host_connector::unified::outcome`: **NOT IN CARD-SERVICE** (this is where a response code becomes `INSUFFICIENT_FUNDS` etc.) | `card-service/src/flow.rs:9`, `:248` |
| 11 | If the outcome is `Pending` (unknown), send a reversal (§5.3) | `card-service/src/flow.rs:250-276` |
| 12 | Wipe the PAN copy and return `CardResult` with outcome, reversal, BIN, last 4 and `host_used` | `card-service/src/flow.rs:277-280`, `:70-81` |

The clear PAN is a `ClearPan(Zeroizing<String>)`: wiped on drop, and `Debug` prints only the last 4 (`card-service/src/hsm.rs:70-103`).

---

## 3. The simulated HSM

### 3.1 What it is

- `trait Hsm` is the seam: decrypt the PAN, verify a PIN block, verify a CVV, give out the checkout public key, seal and open vault entries, and compute the PAN fingerprint (`card-service/src/hsm.rs:105-140`).
- `SimHsm` is the only implementation. It holds the BDK in a `Zeroizing<Vec<u8>>` and an optional P-256 checkout key (`card-service/src/hsm.rs:142-145`).
- The BDK must be 16 or 32 bytes and is parsed from hex (`card-service/src/hsm.rs:148-166`).

> **PRODUCTION RISK: software HSM, BDK from an environment variable.** The BDK is read from `SIM_HSM_BDK_HEX`
> (`card-service/src/main.rs:6`, `:142`) and lives in process memory (`card-service/src/hsm.rs:143`). The module
> says: "Replace with a real HSM (and X9.24-3 on the terminals) before any live card"
> (`card-service/src/hsm.rs:9-11`).

> **PRODUCTION RISK: hardcoded test BDK.** Both test suites use
> `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` (`card-service/tests/flow.rs:19`,
> `card-service/tests/vault.rs:22`). This is test-only inside card-service. The runtime value is supplied by files
> outside card-service (`backend/app/sandbox.py` and the e2e test harness set `SIM_HSM_BDK_HEX`). Those weren't read,
> so whether a deployed environment reuses this sequential key is **unverified**.

### 3.2 Key derivation ("SIM-DUKPT"): **not ANSI X9.24-3**

The terminal envelope is `sp1.<KSN, 10 bytes, base64url>.<12-byte nonce || AES-GCM ciphertext+tag, base64url>` (`card-service/src/hsm.rs:13-17`).

| Step | Algorithm | Ref |
| :--- | :--- | :--- |
| Per-transaction key | **HKDF-SHA256**, IKM = BDK, salt = KSN, info = `"synapsepay/sim-dukpt/v1/<usage>"`, 32-byte output | `card-service/src/hsm.rs:185-191` |
| Cipher | **AES-256-GCM**, 12-byte nonce, AAD = usage (`"data"`, `"pin"`, `"cvv"`) so one kind can't be replayed as another | `card-service/src/hsm.rs:212-218`, `:19` |
| Envelope checks | exactly 3 parts, KSN exactly 10 bytes, body longer than nonce + tag | `card-service/src/hsm.rs:193-211` |
| PAN check after decrypt | 13–19 digits + Luhn | `card-service/src/hsm.rs:75-83`, `:277-289`, `:302-306` |

> **PRODUCTION RISK: non-standard DUKPT.** "SIM-DUKPT is HKDF-SHA256(BDK, salt = KSN) + AES-256-GCM, not X9.24-3"
> (`card-service/src/hsm.rs:9-10`). It has DUKPT's shape (one base key, a fresh key per KSN), but real PIN pads
> and payment HSMs won't interoperate with it. It also has no transaction-counter progression: any KSN value is
> accepted and nothing records used KSNs (`card-service/src/hsm.rs:204-212`), so the **same envelope decrypts any
> number of times**.

### 3.3 Browser/app checkout envelope (sp2, ECIES)

- Format: `sp2.<ephemeral P-256 public key, 65-byte SEC1>.<nonce || AES-GCM ct+tag>` (`card-service/src/hsm.rs:22-29`).
- Key: ECDH(checkout private key, ephemeral public key), then HKDF-SHA256 with salt = ephemeral public key bytes and info = `"synapsepay/checkout/v1/<usage>"`, then AES-256-GCM (`card-service/src/hsm.rs:221-247`).
- The public key is published as a JWK (`card-service/src/hsm.rs:336-338`, `card-service/src/http.rs:144-150`).

> **PRODUCTION RISK: checkout private key outside an HSM.** It's loaded from a PEM file (`SIM_HSM_CHECKOUT_KEY`).
> If that variable is unset, a key is **generated at startup and lost on restart**, so every card encrypted to the
> old public key becomes undecryptable (`card-service/src/main.rs:7`, `:131-141`; `shortcut:` at
> `card-service/src/hsm.rs:31-32`).

### 3.4 PIN, CVV, vault keys

- **PIN block:** decrypted (usage `"pin"`), XORed with the ISO 9564 format 0 PAN field, then checked for format 0, length 4–12, and digit/padding nibbles (`card-service/src/hsm.rs:291-299`, `:308-326`).
  > **PRODUCTION RISK: PIN not sent to the issuer.** "a real HSM translates it to the acquirer's zone PIN key for
  > DE 52; the synthetic host dialect has no DE 52 yet, so the block is checked here and not forwarded"
  > (`card-service/src/hsm.rs:109-112`). Online-PIN verification by the issuer doesn't happen.
- **CVV:** checked as 3–4 digits, never forwarded (`card-service/src/hsm.rs:114-118`, `:328-334`).
- **Vault keys:** the KEK and the fingerprint key are both derived from the BDK with HKDF-SHA256, using no salt and info `"synapsepay/vault/v1/<purpose>"` (`card-service/src/hsm.rs:168-177`). Vault ciphertexts are AES-256-GCM with AAD = token (`:340-369`). The fingerprint is HMAC-SHA256 over `merchant_id|PAN` (`:371-379`).
  > **PRODUCTION RISK: one key compromises everything.** The terminal decryption keys, the vault KEK and the
  > fingerprint key all derive from the single BDK (`card-service/src/hsm.rs:169-170` says so as a `shortcut:`).
  > Leaking `SIM_HSM_BDK_HEX` exposes in-flight card data **and** every stored card.

### 3.5 Simulated 3-D Secure

The outcome depends only on the PAN: `4242424242424242` → frictionless, `4000000000003238` → rejected, anything else → challenge (`card-service/src/flow.rs:113-122`).
> **PRODUCTION RISK: simulated 3-D Secure.** There's no directory server or ACS (`card-service/src/flow.rs:114`).

---

## 4. ISO 8583 message: what card-service populates

**card-service does not build or encode ISO 8583 messages.** It fills a `host_connector::Transaction` struct (`card-service/src/flow.rs:226-237`). The `host_connector` crate maps that onto data elements using a dialect dictionary loaded from JSON (`HOST_DIALECT`; `card-service/src/main.rs:12`, `:108-112`). Field numbers, formats (n/an/b), length prefixes and bitmap encoding are **NOT IN CARD-SERVICE**.

What card-service provides, and the DE number its own code or comments give:

| DE | Meaning | Value card-service supplies | Ref |
| :--- | :--- | :--- | :--- |
| 2 | PAN | `card.pan` = clear PAN from the HSM or vault. DE number: **NOT IN CARD-SERVICE** | `card-service/src/flow.rs:236` |
| 3 | Processing code | **NOT IN CARD-SERVICE.** card-service only passes `kind` = `Purchase` / `Authorization` / `Reversal{original}`; the connector derives MTI and DE 3 from it | `card-service/src/flow.rs:228-231`, `:288` |
| 4 | Amount, transaction | `amount_minor` = the request's `amount` (u64 minor units), unchanged. Padding/width: **NOT IN CARD-SERVICE** | `card-service/src/flow.rs:232` |
| 11 | STAN | Minted **once per transaction** by the Fleet, reused across hosts and for the reversal | `card-service/src/fleet.rs:9-11`, `:78`, `:121` |
| 14 | Expiry | `YYMM` from `MM/YY` | `card-service/src/flow.rs:164-173`, `:236` |
| 41 / 42 | Terminal ID / Merchant ID | `acquirer_terminal_id` / `acquirer_merchant_id` from the request | `card-service/src/flow.rs:24`, `:234-235` |
| 49 | Currency | `currency` string as given; numeric conversion **NOT IN CARD-SERVICE** | `card-service/src/flow.rs:233` |
| 52 | PIN data | **not sent** (§3.4) | `card-service/src/hsm.rs:109-112` |
| 55 | ICC / EMV data | `card.icc` = bytes from `emv_data` | `card-service/src/flow.rs:47`, `:175-182`, `:236` |
| 7 + MTI + STAN of the original | Reversal data | saved by the reversal queue | `card-service/src/reversals.rs:5-6`, `:86-87` |

- **Framing:** a 2-byte binary length header, max 8192 bytes, **hardcoded for every host** (`card-service/src/main.rs:114-115`, marked `shortcut:`).
- **Audit:** every message goes to one JSON Lines file. Redaction happens inside `host_connector` (`card-service/src/main.rs:15`, `:100-101`, `:143-145`).
- **STAN uniqueness across instances** relies on each instance being given a distinct `STAN_INSTANCE`. Two instances with the same slot send duplicate STANs (`card-service/src/main.rs:16`, `:147-150`).

> **PRODUCTION RISK:** a misconfigured `STAN_INSTANCE` silently produces duplicate STANs. Nothing in
> card-service detects it (`card-service/src/main.rs:147-150`; the default is slot 0 of 1, `:149`).

---

## 5. Routing to acquirers and failover

### 5.1 Pools and the Fleet

- **Single-host mode:** one pool named `ACQUIRER_ID` (default `acquirer_a`) (`card-service/src/main.rs:153-157`).
- **Fleet mode:** `HOSTS=acquirer_a,acquirer_b,...`, one pool per host. Each host needs `<ID>_ADDR`; certificates and dialect fall back to the shared `HOST_*` values (`card-service/src/main.rs:21-25`, `:69-92`, `:158-178`).
- Each pool uses mutual TLS to its host (`HOST_CA`, `HOST_CLIENT_CERT`, `HOST_CLIENT_KEY`) and has 4 connections by default (`card-service/src/main.rs:11`, `:13`, `:94-98`, `:117-118`).
- `Fleet` owns all the pools and implements `HostConnector`, so the flow can't tell one host from five (`card-service/src/fleet.rs:1-5`, `:30-34`, `:74`).

### 5.2 Choosing a host (`Fleet::send_transaction`, `card-service/src/fleet.rs:75-145`)

1. Mint the STAN once (`:78`).
2. Candidates = the caller's `host_hint` in order, or **every pool** if the hint is empty (`:79-84`). Unknown hosts and hosts with **no live socket are skipped** (`:86-91`).
   - No candidates → `Unavailable` (`:92-94`).
3. If the first hinted host was skipped, emit `FAILOVER_TRIGGERED` with `reason: UNAVAILABLE` (`:95-103`).
4. Try candidates in order. Each attempt gets **whatever is left of one shared deadline**, not a slice of it (`:105-113`), and each failed attempt is logged as `HOST_ATTEMPT_FAILED` with the STAN (`:122-131`).
   - **Answer** (approve or decline) → return it, with `host_used` set to the host that answered (`:133-137`). "A decline is an answer, never a reason to move on" (`:15-16`).
   - **Never sent** (`Unavailable`) → try the next host (`:140`).
   - **Outcome unknown** → **stop**. The next host is not asked, because the first may have approved and a second host could charge the card twice (`:12-15`, `:138-139`).
5. Every candidate failed or the deadline ran out → `Unavailable` (`:143`).

Which `HostError` variants count as `outcome_unknown()` is defined in `host_connector`, **NOT IN CARD-SERVICE**. The module comment names timeout and connection loss (`card-service/src/fleet.rs:13-15`). How `Protocol` is classified is unverified.

### 5.3 Does a timeout fall back to another acquirer? **No, not inside card-service.** It reverses instead.

1. A host timeout ends the Fleet attempt with an unknown outcome. There's no retry on another host (`card-service/src/fleet.rs:138-139`).
2. `outcome()` turns that into `Status::Pending`, and `CardFlow` sends a **reversal** (`card-service/src/flow.rs:250-251`):
   - Same transaction, `kind = Reversal{original_transaction_id}`, id suffixed `-rev` (`:285-290`).
   - Up to **3 attempts**, **2 s** each, **200 ms** apart (`:143-152`, `:292-296`).
   - An **empty host hint**, so the Fleet tries every host (`:297-300`).
   - Only an `Approved` reply counts as reversed. Any other reply stops the loop as `Failed` (`:301-307`). Transport errors are retried (`:308-310`).
3. **Reversed** → the outcome is rewritten to `FAILED`, `HOST_TIMEOUT`, `SYSTEM_ERROR`, **`retryable: true`** (`card-service/src/flow.rs:261-275`). Because it's retryable, the Python backend's cascade may then try the next acquirer (doc 02 §2.5). **So cross-acquirer fallback after a timeout happens in Python, only after a confirmed reversal.**
4. **Reversal failed** → the outcome stays `PENDING`, and the reversal is written to the durable queue (`card-service/src/flow.rs:252-260`):
   - The queue stores the HSM-sealed PAN, the original's MTI, STAN and DE 7, and the host that holds it (`card-service/src/reversals.rs:3-8`).
   - A background loop resends up to 100 pending reversals every `REVERSAL_RETRY_MS` (default 10 s) and wipes the sealed PAN once resolved (`card-service/src/main.rs:205-212`, `card-service/src/reversals.rs:84-104`, `:141-143`).

> **PRODUCTION RISK: an owed reversal can be lost.** The reversal queue exists only when `VAULT_DATABASE_URL` is
> set (`card-service/src/main.rs:205-214`). That in turn requires `CARD_DATA_STORAGE=sandbox`, which is refused
> outside sandbox pending the PCI review (`card-service/src/main.rs:124-130`). **So in a non-sandbox deployment
> today, an owed reversal is only printed to stderr** (`REVERSAL OWED ... no reversal queue configured`,
> `card-service/src/flow.rs:258`) and is lost when the request ends. The customer may have been charged, and only
> reconciliation would catch it.

> **Unverified:** the reversal's empty hint makes the Fleet try hosts in `HashMap` order
> (`card-service/src/fleet.rs:79-81`). Whether a host that doesn't hold the original answers `Unavailable` (so the
> Fleet moves on) or declines (so `reverse` stops as `Failed`) depends on `host_connector`: **NOT IN CARD-SERVICE**.
> `Fleet::original` shows only one pool holds it (`card-service/src/fleet.rs:52-56`).

### 5.4 Health

- `GET /health`: `DOWN` only if no pool is up, `DEGRADED` if some are (still 200), `UP` otherwise (`card-service/src/http.rs:152-162`, `card-service/src/fleet.rs:147-165`).
- `GET /internal/v1/hosts/health`: one row per acquirer, `UP` if it has any live socket, sorted (`card-service/src/http.rs:178-189`).

---

## 6. PRODUCTION RISK summary

| # | Risk | Ref |
| :--- | :--- | :--- |
| 1 | Software HSM; BDK from an env var, held in process memory | `card-service/src/hsm.rs:9-11`, `:143`; `card-service/src/main.rs:6`, `:142` |
| 2 | Sequential test BDK `0001…1f` in tests; runtime value set outside card-service, unverified | `card-service/tests/flow.rs:19`, `card-service/tests/vault.rs:22` |
| 3 | SIM-DUKPT (HKDF + AES-GCM) instead of ANSI X9.24-3; no KSN replay tracking | `card-service/src/hsm.rs:9-10`, `:185-191`, `:204-212` |
| 4 | Vault KEK and fingerprint key derived from the same BDK | `card-service/src/hsm.rs:168-177` |
| 5 | Checkout private key in a PEM file, or generated and lost on restart | `card-service/src/main.rs:131-141`, `card-service/src/hsm.rs:31-32` |
| 6 | Unauthenticated plain-HTTP internal API | `card-service/src/http.rs:1-4` |
| 7 | PIN block checked but not sent (no DE 52); CVV not sent | `card-service/src/hsm.rs:109-118` |
| 8 | Simulated 3-D Secure keyed on PAN | `card-service/src/flow.rs:113-122` |
| 9 | Owed reversals only logged when there's no reversal DB, which is every non-sandbox deployment today | `card-service/src/flow.rs:254-259`, `card-service/src/main.rs:124-130`, `:205-214` |
| 10 | Framing hardcoded to a 2-byte binary header for all acquirers | `card-service/src/main.rs:114-115` |
| 11 | Duplicate STANs if `STAN_INSTANCE` is misconfigured | `card-service/src/main.rs:147-150` |
