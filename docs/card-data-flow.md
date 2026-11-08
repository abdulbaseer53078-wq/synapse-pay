# Card data flow: input for the PCI DSS review (audit finding F-16)

What this codebase does with cardholder data today, so the card-data architecture can be reviewed before any of it
ships. Status: **storage of card data is frozen**. The card service refuses to start with the token vault or the
reversal queue unless `CARD_DATA_STORAGE=sandbox` is set, and `card_token` is deprecated in the API (spec 1.13.1).

## The role this design implies

SynapsePay connects to acquirers directly over ISO 8583 (`host-connector`, `card-service`) and decrypts card
numbers to build those messages. That makes it a **service provider that stores, processes and transmits account
data**: validation by a Report on Compliance or the service-provider SAQ D. Merchant categories (SAQ A, A-EP,
Level 4) don't apply. Replacing the PAN with a network token in DE 2 wouldn't change the role, and tokens that can
themselves authorise a payment are likely in scope too; the assessor decides.

## Where the PAN exists

| # | Where | Form | How long |
|---|-------|------|----------|
| 1 | Terminal (Android SDK) | Read from the chip, encrypted on the device (`sp1`, DUKPT-derived AES-GCM) | In transit |
| 2 | Browser card form (`backend/app/checkout/card-frame.js`) | Encrypted in the page to the checkout key (`sp2`, P-256 ECDH + AES-GCM); CVV separately | In transit |
| 3 | API backend | Opaque `sp1`/`sp2` envelope, never decrypted. Stores BIN + last 4 only. The audit sanitizer masks any Luhn-valid number in logged payloads | Request lifetime |
| 4 | `payment_intents.pending_card` | Encrypted envelope, **no CVV**, while a 3-D Secure challenge is open | Until the challenge completes (a CHECK ties it to `REQUIRES_ACTION`) |
| 5 | Edge node offline queue (SQLite on merchant premises) | Encrypted envelope inside the queued request; the edge can't decrypt it | Until synced, then purged after 30 days |
| 6 | Card service memory | **Clear PAN**, decrypted by `SimHsm`, zeroized after use; PIN block verified there; 3-D Secure lookup | Request lifetime |
| 7 | ISO 8583 to the acquirer | **Clear PAN in DE 2**, expiry in DE 14, chip data in DE 55 (may repeat the PAN, tag 5A), over mutual TLS | In transit |
| 8 | ISO 8583 audit log | DE 2 masked (first 6, last 4); every field not on an allow-list redacted | Retained |
| 9 | `token_vault` (card service's own Postgres) — **frozen** | The encrypted PAN (AES-256-GCM, bound to the token), or for Visa and Mastercard a simulated network token (DPAN) when one is issued. Beside it in clear: expiry (MM/YY), BIN + last 4, `customer_ref`, `merchant_id`, and an HMAC-SHA256 fingerprint keyed from the BDK | **Indefinitely**: revocation only sets `revoked_at` and deletes nothing |
| 10 | `pending_reversals` (same database) — **frozen** | AES-256-GCM, bound to the transaction | Until the reversal lands, then wiped |

## Gaps the review should weigh

- **The HSM is simulated in software.** `SimHsm` derives every key (DUKPT, checkout, vault) from a BDK held in an
  environment variable. Production needs a certified HSM (PCI PTS HSM / FIPS 140-2 Level 3) with keys that never
  leave it; rows 6, 9 and 10 depend on that.
- **Stored card data (rows 9, 10)** brings requirement 3 (protect stored account data) and key management into scope.
- **No purge of revoked or unused saved cards (row 9)**: there is no retention limit, against requirement 3.2.1.
- **Encrypted data at the edge (row 5)** sits on merchant premises for days.
- **An intent left in `REQUIRES_ACTION` (row 4)** keeps its encrypted card until something expires the intent.
- The card service's HTTP API is unauthenticated and meant for loopback only (`card-service/src/http.rs`).

## Options to decide between

1. **Keep direct ISO 8583 processing** and build the full service-provider programme: certified HSM, segmented
   cardholder-data environment, ROC. The vault and reversal queue can then return, behind the HSM.
2. **Route card payments through a licensed partner** (as `CLAUDE.md` intends for money movement): a PCI-validated
   P2PE or SoftPOS solution on terminals and hosted fields online, with SynapsePay holding only the partner's
   tokens. Card data then never reaches SynapsePay systems; the ISO 8583 path stays for sandbox and certification.
3. **A mix**: partner for e-commerce, direct for card-present, with the scope that implies for the direct part.

Nothing is deleted until one of these is chosen.
