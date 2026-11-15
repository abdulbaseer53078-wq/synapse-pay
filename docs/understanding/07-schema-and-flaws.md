# 07 — Database schema and master flaw list

Every reference is `file:line`, relative to the repo root. Earlier docs in this folder are cited as "doc NN §x".

---

## Part 1 — Database schema (`db/migrations/`)

19 migrations, 34 tables, PostgreSQL / Aurora 13+ (`db/migrations/001_terminal_registry.sql:2`).

### 1.1 Core tables

**`merchants`** (`db/migrations/001_terminal_registry.sql:12-16`)
- `merchant_id` UUID primary key, `webhook_secret_id`, `created_at`
- later gains `webhook_secret` (`db/migrations/008_payment_intents.sql:18`)
- intentionally minimal: "so terminals.merchant_id has something to reference" (`db/migrations/001_terminal_registry.sql:10`)

**`terminals`** (`db/migrations/001_terminal_registry.sql:18-37`)

| Column | Notes | Ref |
| :--- | :--- | :--- |
| `terminal_id` | UUID primary key | `:19` |
| `merchant_id` | `NOT NULL REFERENCES merchants` | `:20` |
| `device_serial` | `UNIQUE` | `:21` |
| `status` | enum `PENDING, ACTIVE, SUSPENDED, REVOKED, DECOMMISSIONED, REJECTED` | `:6-7`, `:25` |
| `certificate_id` | composite foreign key `(certificate_id, terminal_id)` → `certificates`, so a terminal's current cert must be its own | `:26`, `:53-55` |
| `certification_profile_id` | foreign key added later | `db/migrations/004_certification_profiles.sql:17` |
| CHECK | ACTIVE ⇒ has a certificate and `activated_at` | `db/migrations/001_terminal_registry.sql:35-36` |

**`transactions`** (`db/migrations/007_transactions.sql:5-29`, extended later)

| Column | Notes | Ref |
| :--- | :--- | :--- |
| `transaction_id` | UUID primary key, exposed as `txn_<hex>` | `db/migrations/007_transactions.sql:6` |
| `idempotency_key` | UUID, **not unique** (a retry after a retryable failure inserts a new row) | `db/migrations/007_transactions.sql:7` |
| `merchant_id` | `NOT NULL REFERENCES merchants` | `db/migrations/007_transactions.sql:8` |
| `terminal_id` | `REFERENCES terminals`; made nullable for online payments, with `CHECK ((channel='TERMINAL') = (terminal_id IS NOT NULL))` | `db/migrations/007_transactions.sql:9`, `db/migrations/008_payment_intents.sql:53-58` |
| `amount` | `BIGINT CHECK (amount > 0)`, minor units | `db/migrations/007_transactions.sql:10` |
| `currency` | `CHAR(3)`, no format check | `db/migrations/007_transactions.sql:11` |
| `status` | CHECK of the 9 cloud statuses | `db/migrations/007_transactions.sql:14-15` |
| `card_bin`, `card_last4` | PCI-allowed only; "The full PAN is never stored" | `db/migrations/007_transactions.sql:16-19` |
| `error` | JSONB; `CHECK ((status='FAILED') = (error IS NOT NULL))` | `db/migrations/007_transactions.sql:22`, `:28` |
| `metadata` | JSONB; also carries `offline_local_timestamp` for edge sales (doc 06 §3.2) | `db/migrations/007_transactions.sql:25` |
| `payment_intent_id` | `REFERENCES payment_intents` | `db/migrations/008_payment_intents.sql:55` |
| `refunded_amount` | with a CHECK that it stays within `amount` | `db/migrations/017_refunds.sql:33-34` |

**`idempotency_keys`** (`db/migrations/007_transactions.sql:35-45`)
- `PRIMARY KEY (merchant_id, idempotency_key)`, `merchant_id REFERENCES merchants`, `transaction_id REFERENCES transactions`
- `state` is `IN_FLIGHT` or `DONE`; `CHECK ((state='DONE') = (response IS NOT NULL))`
- see doc 02 §2.3 for how it's used

### 1.2 How they link

```
merchants ─┬─< terminals ─┬─< certificates      (terminals.certificate_id → certificates, composite FK)
           │              ├─< heartbeats
           │              └─< transactions >── payment_intents (both directions, 008:55, 008:59)
           ├─< transactions ─┬─< journal_entries ─< ledger_postings   (016)
           │                 ├─< refunds                             (017)
           │                 ├─< reconciliation_items                (018)
           │                 └─< chargebacks                         (019)
           ├─< idempotency_keys ──> transactions (nullable)
           ├─< payment_intents, api_keys, edge_nodes ─< edge_sync_items
```

`transactions` carries **both** `merchant_id` and `terminal_id` as independent foreign keys (`db/migrations/007_transactions.sql:8-9`). Nothing in the schema says the terminal belongs to that merchant; only the application checks it (`backend/app/application/transactions.py:196-200`).

### 1.3 Missing indexes, unbounded growth, and integrity gaps

Each was checked against a real query in `backend/app/`.

| # | Problem | Query that hits it | Effect at scale | Fix |
| :--- | :--- | :--- | :--- | :--- |
| S1 | `idempotency_keys` has **no index on `state` / `created_at`** | Stuck-key sweep `WHERE k.state='IN_FLIGHT' ... AND k.created_at < ...` (`backend/app/infrastructure/postgres_transactions.py:205-209`); metrics gauge, same predicate, every scrape (`backend/app/infrastructure/db_metrics.py:69-71`) | Sequential scan of the whole table on every sweep and every scrape, on a table that only grows (S2) | `CREATE INDEX ... ON idempotency_keys (created_at) WHERE state = 'IN_FLIGHT'` |
| S2 | **No retention** for `idempotency_keys` (no TTL column, no purge job) | none: the only `DELETE` is for retryable failures (`backend/app/infrastructure/postgres_transactions.py:263-266`); the backend's other `DELETE FROM` is unrelated (`backend/app/infrastructure/postgres_terminals.py:133`) | One row per payment, forever, each holding a full JSONB response | Purge `DONE` keys older than the replay window (e.g. 30 days), in batches |
| S3 | **No retention for `heartbeats`** | written on every heartbeat (`db/migrations/001_terminal_registry.sql:57-67`) | Terminals × heartbeats per day, forever: soon the largest table in the database | Time-partition it and drop old partitions, or roll up and delete |
| S4 | Rolling offline limit filters on a **JSONB value** | `offline_total`: `WHERE terminal_id=… AND metadata ? 'offline_local_timestamp' AND (metadata->>'offline_local_timestamp')::timestamptz BETWEEN …` (`backend/app/infrastructure/postgres_edge_chain.py:62-66`) | Uses `transactions_terminal_created_idx` for `terminal_id` only (`db/migrations/007_transactions.sql:30`), then reads **every transaction the terminal ever made**, per synced item | Store `offline_local_timestamp` as a real column, index `(terminal_id, offline_local_timestamp)` |
| S5 | Metrics recompute ledger totals over **all postings** every scrape | `journal_entries JOIN ledger_postings GROUP BY` (`backend/app/infrastructure/db_metrics.py:63-65`) | Full join of the two largest money tables, every scrape | Keep running totals, or compute incrementally |
| S6 | No index on `transactions.merchant_id` | no current query, but every merchant-facing list or report will need one (`db/migrations/007_transactions.sql:8`) | Future seq scans; slow foreign-key checks if merchants are ever deleted | `(merchant_id, created_at)` index when the first list endpoint lands |
| S7 | Foreign-key columns without an index: `transactions.payment_intent_id` (`db/migrations/008_payment_intents.sql:55`), `payment_intents.transaction_id` (`:59`), `idempotency_keys.transaction_id` (`db/migrations/007_transactions.sql:39`) | none hot today | Slow lookups and foreign-key checks if those parents are updated or deleted | Index each, or drop the reverse link nobody queries |
| S8 | Mock settlement-file query filters `payment_method`, `status`, `created_at` with no matching index | `backend/app/infrastructure/postgres_reconciliation.py:166-171` | Sequential scan; mock only, but a real settlement job will copy it | `(payment_method, created_at)` partial index on money-moved statuses |
| S9 | No schema rule that a transaction's terminal belongs to its merchant | §1.2 | A bug elsewhere could write a cross-merchant row | Composite FK `(terminal_id, merchant_id) → terminals (terminal_id, merchant_id)` (needs a unique constraint on that pair) |
| S10 | `currency CHAR(3)` has no check (`db/migrations/007_transactions.sql:11`) | none | Bad data from any non-API writer | `CHECK (currency ~ '^[A-Z]{3}$')` |

---

## Part 2 — Master flaw list: top 10 to fix before production

Ordered by **what it costs if exploited or triggered**: money moved wrongly or card data exposed first, then availability and scale.

| # | Flaw | Evidence | Fix (one sentence) |
| :--- | :--- | :--- | :--- |
| **1** | **Envoy bypass: anyone on the internet can forge terminal identity.** The public ALB forwards every path straight to the backend, which trusts `x-terminal-id`, `x-edge-node-id` and `x-forwarded-client-cert` as if Envoy had set them (doc 05 §4). | `infra/ecs/modules/region/main.tf:271-281`; `backend/app/api/auth.py:52-59`; `backend/app/api/transactions.py:87-93` | Add a shared secret that Envoy injects and the backend requires before trusting identity headers, and have the ALB strip all three headers on the way in. |
| **2** | **The BDK is a committed test key that nothing refuses, and it reaches production as a plaintext env var.** One key derives every terminal key, the vault key and the fingerprint key (doc 03 §3, doc 04 §4). | `backend/app/sandbox.py:29`; `card-service/tests/flow.rs:19`; `docs/step5.md:87`; `card-service/src/hsm.rs:148-166`, `:168-191`; `card-service/src/main.rs:142`; `infra/ecs/modules/region/main.tf:144` | Move key custody to a real payment HSM (or at minimum KMS-wrapped keys), and make `SimHsm` refuse the known test key unless `CARD_DATA_STORAGE=sandbox`. |
| **3** | **Owed reversals are lost outside the sandbox, so a customer can be charged with no record.** The durable reversal queue needs `VAULT_DATABASE_URL`, which is only allowed with `CARD_DATA_STORAGE=sandbox`; otherwise a failed reversal is a stderr line. The in-memory originals are lost on restart too (doc 03 §5.3, doc 04 §3.5). | `card-service/src/main.rs:124-130`, `:205-214`; `card-service/src/flow.rs:254-259`; `host-connector/src/iso_host.rs:17-18`, `:224-228` | Give the reversal queue its own database (it stores only HSM-sealed PANs), separate from the frozen vault flag, and make card-service refuse to start without it. |
| **4** | **Edge sales with future timestamps bypass the cloud's daily offline limit.** The window only looks backwards from each sale's own timestamp, and only too-old sales are rejected. Anyone holding the edge's on-disk key gets unlimited allowance (doc 06 §5). | `backend/app/application/transaction_sync.py:176`, `:181-183`; `backend/app/infrastructure/postgres_edge_chain.py:63-66`; `edge-node/edge_node/config.py:24`, `:31` | Reject `local_timestamp > now + max_clock_skew` at sync, and count not-yet-synced sales in the window the way the edge does. |
| **5** | **No rate limiting, WAF or connection limits at any layer**, against the project's own baseline. One valid terminal cert can drive a database lookup per request (doc 05 §5). | `gateway/envoy.yaml:53-68`, `:100-108`; `infra/ecs/modules/region/main.tf:271-281`; `backend/app/main.py:159-171` | Add an AWS WAF with rate-based rules on the ALB, Envoy `local_ratelimit` per client certificate, and per-merchant limits in the backend. |
| **6** | **The edge's local API is open by default, and terminals aren't authenticated even with TLS.** It's plain HTTP on `0.0.0.0` unless `EDGE_TLS_CERT` is set, `terminal_id` comes from the body, an empty terminal list accepts any id, and the signing key is an unencrypted PEM (doc 06 §2, §5). | `edge-node/edge_node/__main__.py:46-50`; `edge-node/edge_node/engine.py:5-7`, `:79`; `edge-node/edge_node/crypto.py:28` | Refuse to start without TLS and client certificates, take `terminal_id` from the client certificate, and keep the edge key in a TPM or secure element. |
| **7** | **The edge treats every real-cloud refusal as final, so temporary failures permanently lose offline sales.** The edge retries only on `error.retryable`, but the real cloud returns `{status, reason}` with no `error`. The edge's tests use a fake cloud with the other shape (doc 06 §3.3). | `edge-node/edge_node/sync.py:84-94`; `backend/app/application/transaction_sync.py:56-57`, `:194-200`; `edge-node/tests/conftest.py:86-95` | Make the cloud return the spec's `Error` object (with `retryable`) per sync item, and run the edge's sync tests against the real backend contract. |
| **8** | **The PIN never reaches the issuer.** DE 52 isn't built, no dialect defines it, and the HSM only checks the PIN block's shape. CVV is likewise checked and dropped (doc 03 §3.4, doc 04 §2.2). | `card-service/src/hsm.rs:109-118`; `host-connector/src/iso_host.rs:342-357`; `iso8583/dialects/synthetic-host.json:1-21` | Translate the PIN block to the acquirer's zone PIN key in the HSM and send it as DE 52 (and CVV2 in the acquirer's field), per acquirer dialect. |
| **9** | **The idempotency and heartbeat tables grow forever, and the hot sweeps scan them in full.** At volume, the stuck-key sweep, the metrics gauge and the offline-limit check slow down with the age of the system, not with load (Part 1, S1–S4). | `db/migrations/007_transactions.sql:35-45`; `backend/app/infrastructure/postgres_transactions.py:205-209`; `backend/app/infrastructure/db_metrics.py:69-71`; `backend/app/infrastructure/postgres_edge_chain.py:62-66` | Add the partial `IN_FLIGHT` index, a batched retention job for `DONE` keys and old heartbeats, and a real indexed `offline_local_timestamp` column. |
| **10** | **A SQLite edit rolls the edge back to older, looser rules, or revives expired ones, without the key.** Every rule version is kept, and the clock guard lives in the same writable file. The unsigned `status` column also frees daily allowance (doc 06 §5). | `edge-node/edge_node/rules.py:87-92`, `:108-109`, `:120`; `edge-node/edge_node/engine.py:100-103` | Delete superseded rule versions on install, and anchor the version and clock high-water mark somewhere the shop can't edit (a TPM monotonic counter, or require a fresh cloud-signed timestamp after a restart). |

### Raised but not in the top 10

| Item | Why it's lower | Ref |
| :--- | :--- | :--- |
| **201 for declined payments** | **Not a flaw.** The spec requires a decline to be a 201 with `status: FAILED` and the error inside the transaction, and the backend matches it (doc 01 §6.2, doc 02 §3). A 4xx would wrongly tell SDKs the *request* was invalid and break idempotent replay of declines. | `spec/openapi.yaml:1510-1511`; `backend/app/api/transactions.py:95` |
| card-service is unauthenticated plain HTTP | Only reachable on the task's loopback today (doc 05 §3.2); becomes critical only if #1 is left open or `CARD_SERVICE_ADDR` is overridden | `card-service/src/http.rs:1-4`; `card-service/src/main.rs:219` |
| CRL loaded only at startup | The registry `ACTIVE` check still blocks revoked terminals, except on the heartbeat route | `gateway/envoy.yaml:8-9`, `:41-46` |
| OAuth not implemented on `POST /v1/transactions` | A missing feature (merchant servers can't create transactions), not a hole; it fails closed with 401 | `backend/app/application/transactions.py:191-193` |
| DE 3 hardcoded `000000`; DE 12/13 sent as UTC | Wrong once refunds or cash go through ISO 8583, or near midnight IST settlement cut-off | `host-connector/src/iso_host.rs:344`, `:348` |
| Unknown DE 39 codes become hard declines; only `51` is specific | Fails safe (no double charge); costs conversion, not money | `host-connector/src/iso_host.rs:399-400`; `host-connector/src/unified.rs:103` |
| Spec drift: error codes outside the enum, wallet insufficient funds is soft, unknown terminal is 404 vs 422 | Contract-hygiene items for the restructuring | doc 02 §4 |
| Duplicate STANs if `STAN_INSTANCE` is misconfigured | Ops misconfiguration with a documented guard in Terraform | `card-service/src/main.rs:147-150`; `infra/ecs/modules/region/main.tf:7-8` |

### Suggested order of work

- **Before any real traffic:** #1, #2, #3.
- **Before enabling offline mode:** #4, #6, #7, #10.
- **Before load:** #5, #9.
- **Before card-present PIN cards:** #8.

#1, #4 and #7 are each a small, contained code change, and #4 is a single line. The rest need infrastructure or HSM work.
