# 06 — Edge node (offline payments)

Scope: `edge-node/` (Python + SQLite) and the cloud code that receives its sync batches, `backend/app/application/transaction_sync.py`, `backend/app/domain/edge_chain.py` and `backend/app/infrastructure/postgres_edge_chain.py`, because what the cloud re-checks decides what tampering actually costs. Every reference is `file:line`, relative to the repo root.

**Threat model used below.** The edge is a box in a shop. Anyone with access to its filesystem can read and edit:
- the SQLite file (`EDGE_DB_PATH`, default `edge.sqlite3`; `edge-node/edge_node/config.py:28`)
- **the edge's private signing key**: an unencrypted PEM read from `EDGE_KEY_PATH` (`edge-node/edge_node/config.py:24`, `:31`) and loaded with `password=None` (`edge-node/edge_node/crypto.py:27-28`)

So "the edge signed it" only proves the payment came from someone with access to that box.

---

## 1. Layout

| Module | Job | Ref |
| :--- | :--- | :--- |
| `__main__.py` | Starts the local API (uvicorn, `0.0.0.0:8080`) and the sync worker thread | `edge-node/edge_node/__main__.py:41-51` |
| `engine.py` | `POST /local/v1/transactions`: rules, limits, idempotency, sign, chain, queue | `edge-node/edge_node/engine.py:51-147` |
| `rules.py` | Signed offline rules: verify, bind, version, expiry, clock guard | `edge-node/edge_node/rules.py:1-11` |
| `sync.py` | Delivers the queue to `POST /api/v1/transactions/sync` | `edge-node/edge_node/sync.py:1-13` |
| `alerts.py` | Signed webhook to the merchant when a synced sale fails | `edge-node/edge_node/alerts.py:1-6` |
| `db.py` | One SQLite file, WAL, `synchronous=FULL`; tables `rules_cache`, `clock_guard`, `offline_queue`, `merchant_alerts`, `chain_head` | `edge-node/edge_node/db.py:11-72`, `:75-83` |
| `crypto.py` | ECDSA P-256 over canonical JSON; SHA-256 chain hash | `edge-node/edge_node/crypto.py:1-38` |

---

## 2. Processing a payment offline (`POST /local/v1/transactions`)

`edge-node/edge_node/engine.py:62-129`, in order:

| # | Check | Failure | Ref |
| :--- | :--- | :--- | :--- |
| 1 | Body: `idempotency_key` UUID, `amount > 0`, `currency ^[A-Z]{3}$`, terminal/merchant 1–64 chars; unknown fields **ignored** | 400 | `edge-node/edge_node/engine.py:29-39` |
| 2 | `payment_method` ∈ `CARD, UPI, WALLET, QR` | 400 | `edge-node/edge_node/engine.py:25`, `:65-66` |
| 3 | A rule set exists, verifies, and hasn't expired (§4) | 503 `RULES_MISSING` / `RULES_EXPIRED` / `RULES_TAMPERED` | `edge-node/edge_node/engine.py:70-78` |
| 4 | `merchant_id` = this edge's merchant; `terminal_id` ∈ the rules' terminal list (**skipped if the list is empty**) | 403 | `edge-node/edge_node/engine.py:79-80` |
| 5 | `BEGIN IMMEDIATE`, so the limit check and the insert are atomic | none | `edge-node/edge_node/engine.py:82` |
| 6 | Idempotency: same key and same body hash → replay 200; different body → 409 | 409 | `edge-node/edge_node/engine.py:84-92` |
| 7 | `amount ≤ offline_limits.per_transaction` | 422 `OFFLINE_LIMIT_EXCEEDED` | `edge-node/edge_node/engine.py:93-97` |
| 8 | Rolling 24 h per terminal: sum of this terminal's non-FAILED rows created in the last 24 h **or still unsynced** + amount ≤ `per_day` | 422 | `edge-node/edge_node/engine.py:98-107`, `:24` |
| 9 | Build the sync item (`payment_method: OFFLINE`, `underlying_rail`, `edge_node_id`, …), add `edge_seq = last+1` and `prev_hash`, **sign everything**, insert, advance `chain_head`, commit | none | `edge-node/edge_node/engine.py:108-125` |
| 10 | Answer **201** `PENDING_OFFLINE` + receipt note "OFFLINE - AWAITING BANK APPROVAL" | none | `edge-node/edge_node/engine.py:129`, `:150-153`, `:26` |

Not checked on the edge:
- **`max_age_minutes`** is parsed from the rules (`edge-node/edge_node/rules.py:46`, `:79-80`) but never used by the engine. Only the cloud enforces it (§3.3).
- **Card-level controls.** `card_ref_hash` (the Step 22 blocklist) is a column that nothing writes (`edge-node/edge_node/db.py:43`). `fraud_thresholds` and `token_index` are signed in but not enforced (`edge-node/README.md:57`).
- **Terminal authentication.** `terminal_id` comes from the body, **not bound to the client certificate** (`edge-node/edge_node/engine.py:5-7`, `edge-node/README.md:55-56`). TLS with required client certs is **opt-in**: without `EDGE_TLS_CERT`, the API is plain HTTP on `0.0.0.0:8080` with no authentication at all (`edge-node/edge_node/__main__.py:46-50`).

---

## 3. Sync to the cloud

### 3.1 The edge's worker (`SyncWorker.run_once`, `edge-node/edge_node/sync.py:106-134`)

1. **Recover:** rows stuck in `SYNCING` for more than 2 minutes go back to `PENDING_OFFLINE` (`edge-node/edge_node/sync.py:27`, `:52-56`).
2. **Fetch the rules** via `GET /internal/v1/edge/rules`. A failure means "offline": back off and send nothing (`edge-node/edge_node/sync.py:113-114`, `edge-node/edge_node/__main__.py:28-29`).
3. **Claim** the oldest 50 `PENDING_OFFLINE` rows as `SYNCING`, atomically (`edge-node/edge_node/sync.py:26`, `:58-70`).
4. **Send** the stored payloads byte for byte: `POST /api/v1/transactions/sync` over mTLS (`edge-node/edge_node/sync.py:121`, `edge-node/edge_node/__main__.py:18-21`, `:31-33`). A network error or non-200 releases the rows for the next pass (`edge-node/edge_node/sync.py:122-129`).
5. **Apply** each result by `offline_reference` (`edge-node/edge_node/sync.py:76-104`):
   - no result, or `error.retryable` → `PENDING_OFFLINE` (`:85-89`)
   - `status == FAILED` → `FAILED` + a merchant alert in the same transaction (`:90-94`, `edge-node/edge_node/alerts.py:21-29`)
   - anything else → `SYNCED` (`edge-node/edge_node/sync.py:95-99`)
6. **Backoff:** 2 s doubling to 60 s (`edge-node/edge_node/sync.py:29`, `:36-37`, `:155-158`). Synced rows are purged after 30 days (`:30`, `:138-145`).

Re-sending is the recovery strategy: every item keeps its `idempotency_key`, so the cloud replays earlier answers (`edge-node/edge_node/sync.py:10-12`).

### 3.2 The cloud's receiver (`sync_edge`, `backend/app/application/transaction_sync.py:91-134`)

| # | Check | On failure | Ref |
| :--- | :--- | :--- | :--- |
| 1 | The edge is registered and active, with a certificate | whole batch refused | `backend/app/application/transaction_sync.py:92-95` |
| 2 | One sync per edge at a time (`exclusive`) | none | `backend/app/application/transaction_sync.py:99` |
| 3 | The edge isn't already flagged for review | whole batch 403 | `backend/app/application/transaction_sync.py:100-102` |
| 4 | Per item: `edge_node_id` and `merchant_id` match | item `EDGE_MISMATCH` | `backend/app/application/transaction_sync.py:106-110` |
| 5 | Per item: `terminal_id` is a UUID | item `TERMINAL_MISMATCH` | `backend/app/application/transaction_sync.py:111-115` |
| 6 | Per item: ECDSA signature against the edge's registered public key | item `SIGNATURE_INVALID` | `backend/app/application/transaction_sync.py:116-120` |
| 7 | Hash chain: `edge_seq` contiguous from the stored head, `prev_hash` matches, a resent seq must be byte-identical | **whole batch 403, edge flagged, critical ops alert** | `backend/app/application/transaction_sync.py:123-129`, `:136-160`; `backend/app/domain/edge_chain.py:18-31` |
| 8 | `amount ≤ per_transaction` (**the cloud's own** registered limit, not the rules the edge holds) | `OFFLINE_LIMIT_EXCEEDED` | `backend/app/application/transaction_sync.py:96-97`, `:169-170` |
| 9 | `now − local_timestamp ≤ max_age_minutes` | `OFFLINE_TRANSACTION_EXPIRED` | `backend/app/application/transaction_sync.py:172-177` |
| 10 | Rolling 24 h per terminal: accepted, non-failed offline sales with `offline_local_timestamp` in `[local_timestamp − 24h, local_timestamp]` + amount ≤ `per_day` | `OFFLINE_DAILY_LIMIT_EXCEEDED` | `backend/app/application/transaction_sync.py:178-184`; `backend/app/infrastructure/postgres_edge_chain.py:58-67` |
| 11 | Run it as a normal transaction for that terminal: the full doc 02 path, so the terminal must belong to the merchant and be ACTIVE, and the issuer decides | the transaction's status | `backend/app/application/transaction_sync.py:186-200` |

### 3.3 Conflicts

- **The same card on two edges, or twice on one edge: not detected offline.** The edge never sees a clear card (`method_details` is the encrypted envelope), and the blocklist hash is unused (§2). Each sale is a separate payment: at sync each one goes to the issuer, which approves or declines it on its own; a decline → `FAILED` → merchant alert. The **merchant** carries the loss for goods already handed over. This is the inherent offline risk, bounded only by the limits.
- **The same `idempotency_key` from two edges of one merchant:**
  - Cloud keys are scoped per merchant (doc 02 §2.3), and the cloud adds `metadata.offline_reference`, which differs per edge (`backend/app/application/transaction_sync.py:192-193`).
  - So the bodies differ and the second gets `IDEMPOTENCY_KEY_CONFLICT`, which `_one` turns into `FAILED` (`backend/app/application/transaction_sync.py:194-198`).
  - Result: one charge, and the other sale is alerted as failed.
- **The same item resent by one edge:** the identical body replays the stored response (doc 02 §2.3), and the chain accepts a byte-identical resend (`backend/app/domain/edge_chain.py:24-25`).

> **HIGH (correctness, not a tampering flaw): the edge can't tell a temporary failure from a permanent one.**
> - The edge retries only when a result has `error.retryable` (`edge-node/edge_node/sync.py:84-85`).
> - The real cloud never sends an `error` object. Refusals are `{"offline_reference", "status": "FAILED", "reason"}` (`backend/app/application/transaction_sync.py:56-57`), and processed items carry only `status` (`:199-200`).
> - So **every temporary cloud failure is treated as final**: card-service unavailable, which is a `RegistrationError` caught at `:196-198`, and a reversed host timeout or no healthy host, which are `FAILED` + retryable in doc 02 §2.5. The sale is marked `FAILED`, never retried, and the merchant is alerted with `"error": null` (`edge-node/edge_node/alerts.py:21`). The customer was never charged.
> - The edge's tests don't catch this because their fake cloud returns the shape the edge expects, with `error` and `retryable` (`edge-node/tests/conftest.py:86-95`), not the real one.

---

## 4. Signed rules: how tampering is detected

| Protection | How | Ref |
| :--- | :--- | :--- |
| Authenticity | ECDSA P-256 / SHA-256 signature over canonical JSON (sorted keys, no whitespace, `signature` excluded), checked against the rules key **pinned at registration** (`EDGE_RULES_PUBLIC_KEY_PATH`) | `edge-node/edge_node/crypto.py:1-3`, `:14-16`, `:31-38`; `edge-node/edge_node/rules.py:71-72`; `edge-node/edge_node/config.py:13`, `:30` |
| Binding | `edge_node_id` and `merchant_id` inside the signed body must be this edge's | `edge-node/edge_node/rules.py:73-74` |
| Monotonic versions | install only if `(rules_version, issued_at)` is newer than the newest held; older → rejected | `edge-node/edge_node/rules.py:96-115` |
| Re-verified on every read | `current_rules` re-checks the signature and binding of the stored body each time, so an edited `body_json` → `RulesTampered` → payments refused (fails closed) | `edge-node/edge_node/rules.py:118-126`, `edge-node/edge_node/engine.py:76-78` |
| Expiry | `expires_at` is signed; refuse when `effective_now ≥ expires_at` | `edge-node/edge_node/rules.py:127-130` |
| Clock guard | `effective_now = max(clock, high_water)`, where `high_water` is the latest time ever seen (own clock or a rule set's `issued_at`), so winding the clock back can't revive expired rules | `edge-node/edge_node/rules.py:85-93`, `:110`, `:127` |
| Failed fetch | keep the last good set, log `CLOUD_SYNC_FAILED` | `edge-node/edge_node/rules.py:133-140` |

These hold against someone who can **edit a rule body**. They don't hold against someone who can **delete rows**, because the anti-rollback state lives in the same writable file (§5.1).

---

## 5. Tampering and limit bypasses

> **CRITICAL EDGE FLAW 1: future-dated sales slip past the cloud's daily limit.**
>
> - The cloud's rolling-24 h check looks only **backwards** from each sale's own `local_timestamp`, counting sales stamped in `[ts − 24h, ts]` (`backend/app/application/transaction_sync.py:181-183`; `backend/app/infrastructure/postgres_edge_chain.py:63-66`).
> - The only time check rejects sales that are too **old** (`now − ts > max_age`); a timestamp in the **future** always passes (`backend/app/application/transaction_sync.py:176`), and nothing else checks it (searched the sync code for a future or skew guard).
> - So a set of sales stamped `now`, `now+24h`, `now+48h`, … each see an empty window and each get a fresh `per_day` allowance.
>
> **Who can do it:** anyone who can read the edge's key file (`edge-node/edge_node/config.py:24`, `:31`; unencrypted, `edge-node/edge_node/crypto.py:28`). They sign the items themselves, and as long as they extend the hash chain correctly, the cloud's signature and chain checks pass.
>
> **Exposure:**
> - unbounded total per terminal, limited only by `per_transaction` per sale and the number of the merchant's ACTIVE terminals
> - every sale still needs the issuer's approval at sync, so the loss is declined sales the merchant already handed goods over for
> - plus whatever the business relied on the daily cap to limit
>
> **Fix:** refuse `local_timestamp > now + small_skew` at `backend/app/application/transaction_sync.py:176`, one line. Or count unsynced and future-stamped sales in the window, as the edge does.

> **CRITICAL EDGE FLAW 2: editing SQLite, without the key, rolls the edge back to older, looser rules and revives expired ones.**
>
> - `INSERT OR REPLACE` keeps **every** rule version ever fetched (`edge-node/edge_node/rules.py:108-109`), and `current_rules` reads the highest **row** that's left (`edge-node/edge_node/rules.py:120`).
> - Deleting the newer `rules_cache` rows makes an older, genuinely signed set current again, and its signature still verifies.
> - The rollback and expiry guards depend on `clock_guard`, which lives in the same file (`edge-node/edge_node/db.py:20-23`). Delete its row and `high_water` resets to whatever the box clock says (`edge-node/edge_node/rules.py:87-92`). Wind the OS clock back, and an expired set is valid again, which defeats "a wound-back clock can't extend" (`edge-node/README.md:10`).
>
> **The cheaper variant:** `offline_queue.status` isn't signed. Flipping earlier unsynced rows to `FAILED` removes them from the exposure sum (`edge-node/edge_node/engine.py:100-103`). Flip them back to `PENDING_OFFLINE` before the worker claims them, and they sync normally.
>
> **Backstop:** the cloud checks `per_transaction`, `max_age` and `per_day` against **its own** registered limits (`backend/app/application/transaction_sync.py:96-97`, `:169-184`). So sales beyond the real limits are refused at sync, and with honest timestamps the platform isn't exposed. The **merchant** is: the edge has already printed "awaiting bank approval" receipts and the goods are gone. Combined with flaw 1, the cloud backstop is gone too.

> **HIGH: the edge API has no authentication unless TLS is configured, and even then terminals aren't identified.**
> - Without `EDGE_TLS_CERT`: plain HTTP on `0.0.0.0:8080` (`edge-node/edge_node/__main__.py:46-50`).
> - With TLS, client certs are required, but `terminal_id` still comes from the body (`edge-node/edge_node/engine.py:5-7`).
> - If the signed rules carry an empty terminal list, **any** terminal id is accepted (`edge-node/edge_node/engine.py:79`). The cloud then refuses unknown ones at sync, after goods are handed over.
> - So any device on the shop LAN can queue sales, or use up a terminal's daily allowance as a denial of service.

**What holds:**
- An edited **rule body** fails closed (`edge-node/edge_node/rules.py:123-126`).
- An edited **queued payload** fails the cloud's signature check (`backend/app/application/transaction_sync.py:116-120`). Without the key, a deleted or reordered payload breaks the hash chain, and the cloud freezes the edge and pages ops (`backend/app/application/transaction_sync.py:123-129`).
- The edge's own rolling window does count unsynced rows whatever their timestamp (`edge-node/edge_node/engine.py:98-103`), so moving the **edge's** clock forward frees nothing there. The cloud lacks the same rule, which is flaw 1.

---

## 6. Summary

| # | Finding | Severity | Ref |
| :--- | :--- | :--- | :--- |
| 1 | Future-dated `local_timestamp` bypasses the cloud's rolling daily limit (needs the edge key, an unencrypted file on the box) | **CRITICAL EDGE FLAW** | `backend/app/application/transaction_sync.py:176`, `:181-183` |
| 2 | Deleting SQLite rows rolls back to older rules and revives expired ones; unsigned `status` frees the edge's daily allowance | **CRITICAL EDGE FLAW** (the cloud backstops it unless combined with #1) | `edge-node/edge_node/rules.py:87-92`, `:108-109`, `:120`; `edge-node/edge_node/engine.py:100-103` |
| 3 | Edge treats every real-cloud refusal as final; temporary failures never retried; tests use a different result shape | High | `edge-node/edge_node/sync.py:84-94`; `backend/app/application/transaction_sync.py:56-57`, `:199-200`; `edge-node/tests/conftest.py:86-95` |
| 4 | No auth without TLS; `terminal_id` not bound to the certificate; an empty terminal list accepts any id | High | `edge-node/edge_node/__main__.py:46-50`; `edge-node/edge_node/engine.py:5-7`, `:79` |
| 5 | Edge signing key is an unencrypted PEM on disk (no TPM or secure element) | High (enables #1) | `edge-node/edge_node/config.py:24`, `:31`; `edge-node/edge_node/crypto.py:28` |
| 6 | `max_age_minutes`, card blocklist, fraud thresholds and token index not enforced on the edge | Medium | `edge-node/edge_node/rules.py:46`; `edge-node/edge_node/db.py:43`; `edge-node/README.md:57` |
