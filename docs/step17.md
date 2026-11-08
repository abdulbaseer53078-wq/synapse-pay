# Step 17 — cloud region failover

SynapsePay runs from Mumbai (`ap-south-1`) with Hyderabad (`ap-south-2`) standing by. Both are in India, as RBI
data localization requires. This page is the design and the on-call runbook. **Status: Tasks 17.2 (Postgres) and
17.3 (audit trail) and the 17.6 game-day driver are built, and 17.5 (active-passive) is decided. Everything marked _not built_ below must exist
before a real failover is trusted.**

## What failover really gives us

| | Value | Why |
| :--- | :--- | :--- |
| Topology | Active-passive for writes | Aurora Global Database has one writer. Hyderabad serves reads until promoted. |
| RTO (time to take payments again) | Minutes: detection + human decision + 1–3 min promotion + DNS | Promotion is deliberately a human decision (below). |
| RPO (writes that can be lost) | Planned switchover: none. Unplanned failover: the replication lag at the moment Mumbai died, typically < 1 s | Replication is asynchronous. |

A region outage is therefore **not** invisible: for a few minutes terminals fall back to offline mode and merchant API
calls fail with retryable errors. True active-active writes would need a strongly consistent multi-region database;
our schema (advisory locks, triggers, `SKIP LOCKED`) would have to be rewritten for that.

## Decision: active-passive for v1 (Task 17.5)

Mumbai takes 100% of traffic. Hyderabad is warm:
- **Running:** its database replicates, and its API and host-connector instances stay deployed but receive no
  traffic.
- **Stopped:** the jobs that write (`audit-ingest`, `relay-events`, `audit-publish`, `upi-poll`) stay off until
  promotion (runbook step 5). Against a read-only replica they would only fail, and `audit-ingest` running in two
  regions is exactly how the chain would fork.

**Why not multi-master active-active.** "Last writer wins" conflict resolution is unsafe for money, not just
complex. Two regions could each accept the same `idempotency_key` and charge twice. Two regions could each pass
the same terminal's daily limit (`spent_today`) and double it. Two regions would also each extend the audit chain.
Every invariant this platform enforces assumes one writer.

**If active-active is ever needed, shard instead.** Give each merchant a home region, with each region the only
writer for its merchants and the standby for the other's. Both regions then take traffic with no conflicts to
resolve, but it needs per-merchant routing at the edge and acquirer connectivity in both regions from day one.

**Revisit when** a failover measured on a game day misses the RTO we have committed to, or traffic outgrows one
region's capacity. Neither is true for v1.

## The danger: double charges after an unplanned failover

A payment approved by the acquirer and committed in Mumbai, but not yet replicated when Mumbai dies, does not exist in
Hyderabad. The terminal never got its answer, so it retries with the same `idempotency_key`. Hyderabad has never seen
the key, so it sends the payment to the acquirer again, and the customer is charged twice.

Agreed mitigations:

1. **Deterministic RRN** (_not built_): derive DE 37 from the transaction, not from the clock and a counter
   (`host-connector/src/iso_host.rs` today: `YDDDHH + STAN`), so an acquirer that checks for duplicates rejects the
   retry ("duplicate transmission") instead of approving it again.
2. **Reconciliation after every unplanned failover** (_not built_; manual until then, step 6 of the runbook): find
   acquirer approvals in the lost window that Hyderabad has no record of, and reverse them.

## Infrastructure

`infra/aurora-global/main.tf` (its own Terraform root module):

- Global cluster `synapsepay-payments-global`; writer cluster in Mumbai, read-only secondary in Hyderabad, two
  instances each (in-region failover is separate from, and faster than, regional failover).
- Encrypted with a KMS key per region, 35-day point-in-time recovery, deletion protection, Postgres logs to CloudWatch.
- Alarm `synapsepay-payments-global-replication-lag`: pages when Hyderabad is more than 1 s behind for 3 minutes, or
  when the metric stops arriving. That lag is the window a failover would lose, so the target is watched, not assumed.
- Validated with `terraform validate` against AWS provider 5.100; never planned or applied from this repo.

After any switchover or failover the roles are reversed in AWS: swap the primary and secondary inputs before the next
`terraform apply`, or Terraform will try to undo the failover.

## The audit trail across regions (Task 17.3)

Kafka is not mirrored: no MirrorMaker 2. The audit chain and its WORM copy are built from Postgres
(`audit_log` → `audit-ingest` → S3 Object Lock), and Kafka is only a fan-out. Hyderabad rebuilds its Kafka topics
from the outbox cursors that Aurora replicated. Audit consumers must deduplicate by `event_id`, not `sequence`:
after a failover, a sequence number can appear in two epochs.

What does protect the trail:

- **Aurora Global** (17.2) replicates `audit_log`, `audit_events` and the chain head.
- **S3 replication of the WORM bucket** (`infra/s3-audit-replication.tf`): every `audit/` object is copied to an
  Object-Locked bucket in Hyderabad with Replication Time Control. That's a 15-minute SLA for 99.99% of objects;
  most arrive within seconds. Retention dates are preserved, deletes are never replicated, and an alarm pages on
  failed replication. Objects that existed before the rule was added need one S3 Batch Replication run.
- **Chain epochs.** After an unplanned failover, Hyderabad's chain head is behind Mumbai's by the lost window.
  Chaining on in the same key space would put two different records at the same sequence number in a bucket
  nobody can clean for five years. So Hyderabad starts the next epoch (`python -m app.jobs audit-new-epoch`):
  - its objects go under `audit/epoch-0002/`;
  - its first record links back to the head it inherited;
  - an `AUDIT_CHAIN_EPOCH_STARTED` event records where it forked.

  `verify-audit` checks every epoch and how each one links to the last. It reports Mumbai's records after the fork
  point as the lost window rather than as tampering. **Those records are the evidence for reconciliation:** they're
  what Mumbai did that Hyderabad never saw.

Nothing is "preserved up to the millisecond": every link here is asynchronous. The audit trail's recovery point is
the Aurora lag for the database and the S3 replication lag for the WORM copy.

## Runbook: Mumbai is down

Run every command with credentials that work in Hyderabad. Write down the time of each step in the incident channel.

1. **Confirm it is really Mumbai**, from two independent signals: the AWS Health Dashboard for `ap-south-1`, and our
   own probes from Hyderabad *and* from outside AWS. One failed health check is not a region outage.
   _A false alarm here is how two writers happen. If in doubt, don't fail over._

2. **Decide (incident commander).** Failover is right if Mumbai is unlikely to recover within ~15 minutes or payments
   are already failing. Otherwise, wait: terminals queue offline, and nothing is lost.

3. **Fence Mumbai before promoting anything.**
   - Scale the Mumbai API, workers and host connectors to zero, so nothing in Mumbai can write even if its database
     comes back.
   - Point the public API and terminal gateway DNS at Hyderabad.

   Skipping this step is how a recovering Mumbai keeps accepting payments next to the new writer.

4. **Promote Hyderabad.**
   - If the Mumbai database still answers (degraded region, not dead), use the **switchover**. It waits for
     replication, so nothing is lost:

     ```sh
     aws rds switchover-global-cluster --region ap-south-1 \
       --global-cluster-identifier synapsepay-payments-global \
       --target-db-cluster-identifier <secondary_cluster_arn output>
     ```

   - Otherwise, the **failover**, which accepts losing the unreplicated window:

     ```sh
     aws rds failover-global-cluster --region ap-south-2 \
       --global-cluster-identifier synapsepay-payments-global \
       --target-db-cluster-identifier <secondary_cluster_arn output> \
       --allow-data-loss
     ```

     Record the failover time **T**, and the last `AuroraGlobalDBReplicationLag` value before Mumbai went silent, as
     **L**. The lost window is roughly `[T − L − 1 min, T]`; the extra minute is margin.

5. **Start Hyderabad's services** against the new writer. After a `failover` (not a `switchover`), first run
   `python -m app.jobs audit-new-epoch` once, **before** `audit-ingest` starts. Then start the API,
   `relay-events`, `audit-ingest`, `audit-publish`, `upi-poll`, and the host connectors. The event relay resumes from its outbox cursor in the database. Consumers
   already drop duplicate events by `event_id`.

6. **Reconcile the lost window** (only after a `failover`, not a `switchover`). Until the tooling exists: export the
   acquirer's approvals for the window, from their portal or report, our connector audit records in S3, and the
   lost-window records `verify-audit` reports in the old epoch of the replicated WORM bucket. List
   those whose RRN or STAN has no matching transaction in Hyderabad, and reverse each with the acquirer. Also check
   for terminals that resent a payment in the window: those are the double-charge candidates.

7. **When Mumbai recovers,** a managed failover brings the old Mumbai cluster back as a secondary; it must never take
   writes on its own. Fail back later, in low traffic, with a **switchover** (no data loss), then reverse steps 3
   and 5. Swap the Terraform inputs (see above).

## Game day: the region chaos test (Task 17.6)

Run it in **staging**, wired to the mock acquirer, never in production. `infra/game-day/region_chaos.py`
(standard-library Python):

```sh
python infra/game-day/region_chaos.py --url https://api.staging.synapsepay.example --body body.json     --cert terminal.pem --key terminal-key.pem --duration 600 --failover-at 120     --mode switchover --failover-cmd "./switchover.sh"      # omit --failover-cmd to fail over by hand
```

It sends payments continuously, resending the same idempotency key and body on any failure, as terminals do,
triggers the failover, then checks:

| Check | Pass |
| :--- | :--- |
| No acknowledged payment lost | After the failover, every acknowledged request is re-sent with its key and body; the cloud must replay the same `transaction_id`. A new one means the payment was lost with the old region and has just been charged again. |
| Exactly one outcome | No payment still in doubt at the end. |
| Downtime (longest stretch in which every attempt failed) | `switchover`: under 2 minutes, enforced. `failover`: measured and reported only, because promotion waits for a human (runbook step 2). |

The money checks are enforced in both modes. Expect an unplanned `failover` to report lost payments roughly equal
to the replication lag × traffic until the deterministic RRN and reconciliation exist (see the danger section).
That is the test doing its job. The driver's own correctness is covered by `test_region_chaos.py` (a fake
two-region cluster; `python -m unittest test_region_chaos` from `infra/game-day`).

## Must be true before this runbook can work (_not built_)

- **The acquirer accepts traffic from Hyderabad:** its egress IPs are allowlisted, or a VPN tunnel is up. This is a
  business task and the slowest to arrange; start it first.
- **The terminal CA key and its CRL** are available in Hyderabad. Otherwise terminals can't connect and revocations
  aren't enforced.
- **The card-service HSM keys** exist in Hyderabad. Otherwise card data can't be decrypted.
- **Kafka, Redis, container images and secrets** are provisioned in Hyderabad.
- **DNS failover records and health checks** for the API and the terminal gateway.
- **A game day each quarter**: a planned switchover to Hyderabad and back, on a schedule. A runbook nobody has run
  doesn't work.
