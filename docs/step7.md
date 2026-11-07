# Step 7 — the append-only audit log

Every state change in SynapsePay becomes an immutable, hash-chained event. One `correlation_id` returns the
whole story of one payment — SDK request, terminal authorization, host response, webhook — in order, years
later, even if every mutable row in the database has moved on.

This is the piece that makes the vertical slice auditable, and the piece an RBI inspection asks for first.

## What shipped

| Task | Where |
| :--- | :--- |
| 7.1 Universal event schema | `spec/audit-event.schema.json`, `backend/app/audit/event.py` |
| 7.2 `audit.events` Kafka topic | `backend/app/infrastructure/kafka_audit.py`, producer job `audit-publish` |
| 7.3 SHA-256 hash chaining | `backend/app/audit/chain.py`, `db/migrations/009_audit_events.sql` |
| 7.4 WORM storage | `backend/app/infrastructure/audit_worm.py` (local + S3 Object Lock), `infra/s3-audit-bucket.tf` |
| 7.5 PAN / PII masking | `backend/app/audit/sanitize.py` |
| 7.6 Query and replay API | `backend/app/api/audit.py` — `GET /api/v1/audit/events` |
| 7.7 Integrity verification | `backend/app/application/audit.py` (`AuditVerifier`), job `verify-audit` |

Migrations: `009_audit_events.sql`. Spec: 1.4.0 (additive). Scope: `audit:read`.

## How it fits together

```text
 registry / transactions / SDK / host connector
            │
            │  INSERT audit_log              ← in the same DB transaction as the change
            ▼                                  (the transactional outbox: never blocks the payment path)
    ┌───────────────┐
    │  audit_log    │  append-only by trigger
    └───────┬───────┘
            │  audit-ingest   (exactly one writer)
            ├─ 7.5 sanitise: PAN → ************1234, secrets removed
            ├─ 7.3 chain:    hash = SHA-256(prev_hash ‖ "\n" ‖ canonical(event))
            ├─ 7.4 WORM:     local dir, or S3 Object Lock (COMPLIANCE, 1825 days)
            └─ 7.3 index:    audit_events (queryable, append-only)
            │
            ├── audit-publish → Kafka `audit.events` (key = correlation_id)
            │
            ├── GET /api/v1/audit/events?correlation_id=…    support and dispute tooling
            └── verify-audit (hourly) → recompute from WORM → PagerDuty on mismatch
```

## Design decisions

**One log, not two.** Step 2 already wrote every registry change to `audit_log`, and Step 5 already wrote
every transaction transition there (`transaction.create`, `transaction.send`, `transaction.finish`). Step 7 did
not add a parallel table or touch those producers: it gave `audit_log` a universal face (`correlation_id`,
`payload`) and derived the event envelope from rows that already existed. No retrofit, no duplicate source of
truth.

**The chain is built from the outbox, not from Kafka.** The brief put the hash chain in a Kafka consumer. It is
built from `audit_log` instead, for two reasons: ordering is free (the table already has a monotonic
`audit_id`), and exactly-once hashing falls out of a single `FOR UPDATE` writer rather than consumer-group
rebalancing and duplicate suppression. Kafka still gets every event, with its sequence and hashes, as the
fan-out for external consumers (SIEM, fraud, reconciliation). On a volume that needs partitioned ingestion, the
consumer is the place to shard — the event schema does not change.

**Sanitise before hashing.** Masking after the hash would make the immutable record and the query result
disagree. The masked value *is* the record.

**WORM is the truth; `audit_events` is an index.** If the index and the objects disagree, the objects win and
the verifier says so. The index exists because support queries cannot scan S3.

**The chain is not a blockchain, and the doc says so.** It proves ordering and detects edits. It does not stop
an attacker who can rewrite every object from genesis; S3 Object Lock does that. The two together are the
guarantee, which is why neither is presented as sufficient alone.

## Running it

```bash
docker compose up -d db                       # Postgres 16
cd backend && pip install -r requirements.txt

# apply migrations (any client), then:
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
python -m app.jobs audit-seed                 # writes a 3-event payment, PAN included, and prints its id
python -m app.jobs audit-ingest               # chains, sanitises, writes WORM (run once, Ctrl-C)
python -m app.jobs verify-audit               # exits 0 when the chain is intact, 1 when it is not
python -m app.jobs audit-publish              # needs KAFKA_BOOTSTRAP_SERVERS; fans out to audit.events
```

Read the timeline:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/audit/events?correlation_id=<id>" | jq
```

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `AUDIT_WORM_BACKEND` | `local` | `local` or `s3` |
| `AUDIT_WORM_PATH` | `audit-worm` | root of the local WORM store |
| `AUDIT_S3_BUCKET` / `AUDIT_S3_PREFIX` | — / `audit` | S3 target (Object Lock required) |
| `AUDIT_RETENTION_DAYS` | `1825` | five years |
| `AUDIT_ALERT_WEBHOOK_URL` | — | PagerDuty Events API v2 endpoint; empty disables alerting |

Schedule `verify-audit` hourly and treat a non-zero exit as a security incident. A chain nobody checks is a
decoration.

## Tests

```bash
cd backend && pytest tests/test_audit.py tests/test_audit_pipeline.py
```

`test_audit.py` covers event-type mapping, chain linkage, hash determinism and masking (30 cases, no database).
`test_audit_pipeline.py` covers ingest, masking at rest, the query API and its scopes, paging, and both
tamper-detection paths (edited object, deleted object) against real Postgres.

## Shortcuts

All marked `shortcut:` in code.

- **The local WORM sink is not hardware WORM.** Content-addressed, read-only and verifier-checked, but root can
  rewrite it. Only S3 Object Lock gives "nobody can delete this".
- **One global chain, one ingester.** Correct and simple; it serialises at roughly the rate of one writer. Shard
  by tenant when the audit rate needs it.
- **The verifier is a full scan.** Fine at current volumes; window it (last N days, plus a weekly full pass)
  before the log reaches hundreds of millions of events.
- **`audit_events` can still be TRUNCATEd by the table owner**, exactly like `audit_log`. Enforce with database
  roles (INSERT/SELECT only) when deployment roles exist.
- **Search is Postgres.** The `AuditStore` protocol is the seam for OpenSearch when free-text or
  cross-correlation search is needed.

## Not done

- OpenSearch/Elasticsearch adapter (the brief named it; Postgres covers today's queries).
- SDK and host-connector producers: the SDK logs locally and the host connector has its own ISO audit log. Both
  will call `app.audit` when they get a backend identity.
- Replay-to-state (rebuilding a transaction's state from events) — the timeline is exposed, the reducer is not.
- Hourly scheduling: the job exists; wiring it to cron/Kubernetes CronJob is deployment work.
