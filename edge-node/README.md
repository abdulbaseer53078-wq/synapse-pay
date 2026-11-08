# Edge Node

The on-premise box that keeps a shop taking payments while its internet is down (Steps 20, 21 and 24). Terminals
send it the same `TransactionRequest` they send the cloud; it enforces the cloud's signed offline rules, signs each
payment with its own key, queues it in SQLite, and answers `PENDING_OFFLINE`. When the cloud is reachable again, its
sync worker delivers the queue, oldest first, and the cloud verifies every signature.

| Module | Step | Job |
| :--- | :--- | :--- |
| `rules.py` | 20 | Signed offline rules: pinned cloud key, bound to this edge and merchant, versions only move forward, 72 h expiry that a wound-back clock can't extend, re-verified on every read |
| `engine.py` | 21 | `POST /local/v1/transactions`: per-payment and per-terminal-per-day limits, idempotency, sign and queue |
| `sync.py` | 24 | FIFO batches of 50 to `POST /api/v1/transactions/sync`, crash recovery, exponential backoff, 30-day purge |
| `alerts.py` | 24.5 | Signed webhook to the merchant app when an offline payment is refused at sync, retried until acknowledged |
| `db.py` | | One SQLite file in WAL mode with `synchronous=FULL`; append-only migrations |

## Guarantees

- **Nothing is charged twice.** Every queued item keeps its idempotency key, and re-sending is always safe: the
  cloud replays an answer it already gave. That's why a dropped connection mid-sync, or a power cut between sending
  and recording, is handled by sending the batch again.
- **The queue survives a reboot.** A payment is answered `PENDING_OFFLINE` only after it is committed to disk.
- **Tampering fails closed.** An edited rule set stops offline payments; an edited queued payment fails the cloud's
  signature check at sync, and the merchant is alerted.
- **Expired rules refuse payments.** After 72 h without the cloud, the edge stops accepting rather than enforce
  limits that may have been tightened since.

## Run

```bash
pip install -r requirements.txt
EDGE_NODE_ID=... EDGE_MERCHANT_ID=... EDGE_CLOUD_URL=https://... \
EDGE_RULES_PUBLIC_KEY_PATH=rules-key.pem EDGE_KEY_PATH=edge-key.pem EDGE_CERT_PATH=edge.pem \
EDGE_CLOUD_CA_PATH=ca.pem EDGE_MERCHANT_WEBHOOK_URL=https://... EDGE_MERCHANT_WEBHOOK_SECRET=... \
EDGE_TLS_CERT=... EDGE_TLS_KEY=... EDGE_TLS_CLIENT_CA=terminal-ca.pem \
python -m edge_node                                   # local API on :8080, sync worker beside it
```

Register the edge first, as a platform admin: `POST /api/v1/edge-nodes` with the merchant, a CSR for the edge's
key, and its offline limits. The answer carries the edge's certificate and the rules public key to pin.

## Test

```bash
pytest                                  # this package, against a fake cloud with the real contracts
cd ../backend && pytest tests/test_edge_e2e.py   # this package against the real cloud
```

## Known limits

- The `terminal_id` in a request is checked against the merchant's terminals in the signed rules, but not yet
  bound to the terminal's TLS client certificate.
- Fraud screening (Step 22) and the token index (Step 23) are signed into the rules payload but not enforced yet.
