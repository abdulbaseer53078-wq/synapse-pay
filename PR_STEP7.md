**Stacked on #6** (`feat/step5-transaction-path`). **Base this PR on `feat/step5-transaction-path`, not `main`** — Step 6 is not on `main` yet, so a `main` base would drag the whole SDK diff into the review. If you'd rather land Steps 6 and 7 together, retarget to `main` and expect that larger diff.

Full write-up: [`docs/step7.md`](docs/step7.md).

### What this gives you

Every state change becomes an immutable, hash-chained event. One `correlation_id` returns the whole story of a payment — request, terminal authorization, host response, webhook — in order, years later, even after every mutable row has moved on.

- **Universal event schema** (`spec/audit-event.schema.json`): `event_id`, `timestamp`, `event_type`, `actor`, `entity_id`, `correlation_id`, `payload`. The stored form adds `sequence`, `prev_hash`, `hash`.
- **Hash chain** (`app/audit/chain.py`): `hash(n) = SHA-256(hash(n-1) ‖ "\n" ‖ canonical_json(event n))`. Edit any record and the break is pinpointed at exactly one sequence number.
- **WORM storage** (`app/infrastructure/audit_worm.py`): a read-only local sink for development, and S3 Object Lock in COMPLIANCE mode (1,825 days) behind the same interface. Bucket in `infra/s3-audit-bucket.tf`; the policy permits `PutObject` only with `if-none-match: *`, so the ingester can append but never overwrite.
- **PAN/PII masking** (`app/audit/sanitize.py`): key rules for `pan`/`cvv`/`pin_block`/`encrypted_card_data`, plus a value rule that Luhn-checks any 13–19 digit run anywhere in the payload — so a PAN someone put in `metadata.note` is caught too. Masked before hashing, never after.
- **Query and replay API**: `GET /api/v1/audit/events?correlation_id=…` (scope `audit:read`), filters, keyset paging; `GET /api/v1/audit/chain` for ingestion lag.
- **Integrity verification**: `verify-audit` recomputes the chain from the WORM objects, then checks the database's sequence/hash pairs against them. Two passes, because they catch different attacks: an edited object, and an edited index row.
- **Kafka fan-out**: `audit.events`, keyed by `correlation_id`, carrying sequence and hashes so external consumers can verify what they received.

### Design decisions

**No retrofit.** Step 2 already wrote registry changes to `audit_log`; Step 5 already wrote every transaction transition there (`transaction.create`, `transaction.send`, `transaction.finish`). Step 7 added `correlation_id` (defaulted by trigger, so producers are unchanged) and `payload`, then derived the universal envelope from rows that already existed. Nothing in the registry or transaction code moved.

**The chain is built from the transaction outbox, not from a Kafka consumer.** The plan put it in a consumer. Building it from `audit_log` gives ordering for free (`audit_id` is monotonic) and exactly-once hashing from a single `FOR UPDATE` writer, instead of consumer-group rebalancing and duplicate suppression. Kafka still gets every event as the fan-out. If volume ever needs partitioned ingestion, the consumer is where to shard — the event schema does not change.

**`audit_events` is an index, not the truth.** If the index and the objects disagree, the objects win and the verifier says so. The index exists because support cannot scan S3.

**The chain is not a blockchain, and the docs say so.** It proves order and detects edits; it does not stop an attacker who rewrites every object from genesis. S3 Object Lock is what makes the record unrewritable. Neither is sufficient alone.

**One detail worth reviewing:** ingestion takes the same advisory lock the registry relay uses (`_OUTBOX_LOCK`) around the batch read. Audit ids are assigned at `INSERT` but rows commit out of order, so without it a slow transaction could commit a lower id after the cursor passed and that fact would disappear. The lock is released before the WORM writes, so a slow object store never blocks the payment path.

### Tests

- `backend/tests/test_audit.py` — 30 cases: event-type mapping, chain linkage across appends, hash determinism under key reordering, Luhn, PAN-in-free-text masking, secret-key redaction, no input mutation.
- `backend/tests/test_audit_pipeline.py` — 11 cases against real Postgres: ingest, idempotent re-ingest, PAN absent from the WORM objects, query API incl. scopes and paging, registry events chained unchanged, intact-chain verification, **edited object caught at sequence 2 with the alert fired**, deleted object caught as a sequence gap, verification ledger.
- `spec/check_spec.py`: 20 examples, all rule checks pass. OpenAPI is **1.4.0** (additive: two paths, two schemas, one scope).
- End to end against Postgres by hand: seed → ingest → mask → query → verify → tamper → detect → alert.

### Shortcuts (all marked `shortcut:` in code)

- The local WORM sink is **not** hardware WORM — content-addressed, read-only and verifier-checked, but root can rewrite it. Only Object Lock gives the actual guarantee.
- One global chain, one ingester. Correct and simple; it serialises at roughly one writer's rate.
- The verifier is a full scan of history. Window it before the log reaches hundreds of millions of events.
- `audit_events` can still be `TRUNCATE`d by the table owner, exactly like `audit_log`. Enforce with database roles when deployment roles exist.
- Search is Postgres. `AuditStore` is the seam for OpenSearch.

### Not in this PR

- OpenSearch/Elasticsearch adapter (Postgres covers today's queries).
- SDK and host-connector producers — the SDK logs locally, and the host connector keeps its own ISO audit log. Both call `app.audit` once they have a backend identity.
- Replay-to-state: the timeline is exposed, the reducer is not.
- Scheduling: `verify-audit` exists, but wiring it to cron/Kubernetes CronJob is deployment work.

### Reviewing it

1. `db/migrations/009_audit_events.sql` — the schema, the append-only trigger, the chain head.
2. `backend/app/audit/` — `chain.py`, `sanitize.py`, `event.py` (pure, no I/O; read these first).
3. `backend/app/infrastructure/postgres_audit.py` — ingest transaction and the lock.
4. `backend/app/application/audit.py` — the verifier's two passes.
5. `backend/app/api/audit.py` + the spec diff.

23 files, +1,846/−23.
