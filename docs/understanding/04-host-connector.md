# 04 — host_connector, iso8583, and the runtime BDK

Scope:
- `host-connector/` and `iso8583/` (Rust)
- the Python code that supplies `SIM_HSM_BDK_HEX`
- `host-connector/mock_host/mock_host.py`, read only for which response codes the mock acquirer sends

Every reference is `file:line`, relative to the repo root.

---

## 1. Layout

| Crate | Role | Ref |
| :--- | :--- | :--- |
| `host_connector` | The `HostConnector` trait, the `Transaction` and `HostError` types, ISO 8583 request building and response parsing, mTLS link, pool, STAN source, audit | `host-connector/src/lib.rs`, `host-connector/src/iso_host.rs`, `host-connector/src/unified.rs` |
| `iso8583` | Dialect dictionary (JSON), bitmap, pack/unpack. Knows nothing about payments | `iso8583/src/dictionary.rs`, `iso8583/src/pack.rs`, `iso8583/src/bitmap.rs` |
| Dialects | Per-acquirer field layouts | `iso8583/dialects/synthetic-host.json` (the one the sandbox uses, `backend/app/sandbox.py:151`), `illustrative-visa.json`, `illustrative-rupay.json`, `example.json` |

Pipeline: `Transaction` → data elements → `pack` → length-prefixed frame → mTLS link → wait for the response with the same STAN → `unpack` → `HostResponse` (`host-connector/src/iso_host.rs:1-2`).

---

## 2. Encoding: from card-service's struct to data elements

### 2.1 The input struct

`Transaction { transaction_id, kind, amount_minor: u64, currency, merchant_id, terminal_id, card: Card { pan, expiry YYMM, icc } }` (`host-connector/src/lib.rs:66-89`).
`kind` is `Authorization` | `Purchase` | `Reversal { original_transaction_id }` (`host-connector/src/lib.rs:57-64`).

### 2.2 `build_request` (`host-connector/src/iso_host.rs:322-374`)

**MTI** from `kind`: `Authorization → 0100`, `Purchase → 0200`, `Reversal → 0400` (`host-connector/src/iso_host.rs:324-328`).

| DE | Value | How | Ref |
| :--- | :--- | :--- | :--- |
| **2** PAN | `txn.card.pan` | the clear PAN as ASCII digits, as given | `host-connector/src/iso_host.rs:343` |
| **3** Processing code | **`"000000"` hardcoded** for every message: 0100, 0200 and 0400 | comment: "purchase of goods and services" | `host-connector/src/iso_host.rs:344` |
| **4** Amount | `format!("{:012}", amount_minor)`: zero-padded to 12 digits, minor units, no decimal point; an error if it doesn't fit | | `host-connector/src/iso_host.rs:330-333`, `:345` |
| 7 | `MMDDhhmmss` UTC | | `host-connector/src/iso_host.rs:334-335`, `:346` |
| 11 STAN | from the caller (the card-service Fleet mints one per transaction) | | `host-connector/src/iso_host.rs:218`, `:347` |
| 12 / 13 | local time / date, **actually UTC** (`shortcut: UTC as local time`) | | `host-connector/src/iso_host.rs:348-349` |
| 14 | `card.expiry` (YYMM) | | `host-connector/src/iso_host.rs:350` |
| 22 | `pos_entry_mode`, default `"051"` (chip) for every transaction | | `host-connector/src/iso_host.rs:42-43`, `:55`, `:351` |
| 25 | `"00"` | | `host-connector/src/iso_host.rs:352` |
| 37 RRN | `Y` + `DDD` + `HH` + STAN | | `host-connector/src/iso_host.rs:353` |
| 41 / 42 | `terminal_id` / `merchant_id` | | `host-connector/src/iso_host.rs:354-355` |
| 49 | ISO 4217 numeric from a 6-entry table (INR, USD, EUR, GBP, AED, SGD); any other currency → error, not sent | | `host-connector/src/iso_host.rs:329`, `:356`, `:410-422` |
| 55 ICC | `card.icc` bytes. If the dialect has no DE 55, the request is **refused**, not silently stripped | | `host-connector/src/iso_host.rs:364-371` |
| 90 | reversals only: original MTI + STAN + DE 7 + two 11-digit zero institution IDs | | `host-connector/src/iso_host.rs:336-341`, `:359` |
| **52** PIN block | **NOT BUILT.** DE 52 is not in the field list, and no dialect in `iso8583/dialects/` defines it | | `host-connector/src/iso_host.rs:342-357`; `iso8583/dialects/synthetic-host.json:1-21` |

**Fields the dialect doesn't define are silently skipped** (`host-connector/src/iso_host.rs:319-320`, `:359-363`). Only the dialect's `required` list stops a message from going out without them (`iso8583/src/pack.rs:37-39`). The synthetic dialect requires `[2, 3, 4, 7, 11, 41, 49]` for 0100 and 0200 (`iso8583/dialects/synthetic-host.json:23-24`).

### 2.3 Wire encoding (`iso8583`)

- `pack`:
  1. checks the required fields for the MTI
  2. writes the MTI, then the bitmap built from the fields present
  3. writes each field in ascending order through `Dictionary::write`

  (`iso8583/src/pack.rs:34-50`)
- `Dictionary::write`:
  - FIXED must match the length exactly; LLVAR and LLLVAR must not exceed `max_length` (`iso8583/src/dictionary.rs:344-355`)
  - the value must match its format (`n` = ASCII digits only) (`iso8583/src/dictionary.rs:356-358`, `:47`)
  - then comes the length prefix, if any, then the value (`iso8583/src/dictionary.rs:359-364`)
- Encodings default to ASCII. `"encoding": "bcd"` packs two digits per byte, left-padding odd counts with a 0 nibble (`iso8583/src/dictionary.rs:7-11`, `:92-99`). The MTI and bitmap formats are dialect-level settings (`iso8583/src/dictionary.rs:13-15`).

What that means for the synthetic host (`iso8583/dialects/synthetic-host.json:2-4`):

| DE | Dialect | Bytes on the wire for PAN `4111111111111111`, ₹500.00 |
| :--- | :--- | :--- |
| 2 | `LLVAR`, max 19, `n`, ASCII | `"16"` + `"4111111111111111"` (18 bytes) |
| 3 | `FIXED` 6, `n`, ASCII | `"000000"` |
| 4 | `FIXED` 12, `n`, ASCII | `"000000050000"` |

The illustrative Visa dialect packs the same three fields as BCD with a BCD length prefix on DE 2 (`iso8583/dialects/illustrative-visa.json:2-4`).

Framing is a 2-byte binary length header, max 8192 bytes, hardcoded in card-service for every host (doc 03 §4).

### 2.4 Before and after sending

- **Audit first.** The outbound message is redacted and written to the audit sink. **If that write fails, the message isn't sent** (`Unavailable`) (`host-connector/src/iso_host.rs:158-161`).
- **The original is recorded** (MTI, STAN, DE 7) before sending, in memory, keeping the last 10,000 per host, so a reversal can quote it (`host-connector/src/iso_host.rs:81-82`, `:235-241`).
- Responses are matched **by STAN only** (`host-connector/src/iso_host.rs:299-307`). Nothing checks that the response's DE 4 or DE 41 echo the request.
- A response arriving after its waiter gave up is audited as `unmatched-stan-<STAN>` for reconciliation (`host-connector/src/iso_host.rs:308-315`).

---

## 3. Response → error mapping

### 3.1 DE 39 → decision (`parse_response`, `host-connector/src/iso_host.rs:388-408`)

| Condition | Result | Ref |
| :--- | :--- | :--- |
| Unparseable, wrong response MTI (expected request MTI + 10), or no DE 39 | `HostError::Protocol` | `host-connector/src/iso_host.rs:389-394` |
| DE 39 = `"00"` | `Approved { authorization_code: DE 38 or "" }` | `host-connector/src/iso_host.rs:395-396` |
| DE 39 ∈ `soft_decline_codes` | `Declined { Soft }` | `host-connector/src/iso_host.rs:397-398` |
| **Anything else, including codes nobody has seen** | **`Declined { Hard }`** | `host-connector/src/iso_host.rs:399-400` |

Soft codes default to `19` (re-enter), `68` (response late), `91` (issuer unavailable) and `96` (system malfunction) (`host-connector/src/iso_host.rs:40-41`, `:49-54`). card-service never overrides them, so every host uses this list.

### 3.2 Decision → the spec's `Error` (`outcome`, `host-connector/src/unified.rs:84-116`)

| Input | `status` | `error_code` | `error_category` | `retryable` | Ref |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Approved, 0100 | `AUTHORIZED` | none | none | none | `host-connector/src/unified.rs:92-97` |
| Approved, 0200 / 0400 | `CAPTURED` | none | none | none | `host-connector/src/unified.rs:93` |
| Declined, DE 39 **`51`** | `FAILED` | **`INSUFFICIENT_FUNDS`** | `HARD_DECLINE` (51 isn't a soft code) | false | `host-connector/src/unified.rs:98-106` |
| Declined, any other DE 39 | `FAILED` | `ISSUER_DECLINED` | soft or hard per §3.1 | true if soft | `host-connector/src/unified.rs:99-103` |
| `HostError::Unavailable` (never sent) | `FAILED` | `INTERNAL_ERROR` | `SYSTEM_ERROR` | true | `host-connector/src/unified.rs:107-110` |
| `Timeout` / `ConnectionLost` / `Protocol` | `PENDING` | none | none | none | `host-connector/src/unified.rs:111-114` |

- `51` is the **only** response code with a specific mapping. Expired card (`54`), wrong PIN (`55`), invalid card (`14`) and do-not-honour (`05`) all become `ISSUER_DECLINED`. The raw DE 39 is kept only inside `error_message` ("response code NN") and in `HostResponse.response_code` (`host-connector/src/unified.rs:104`, `host-connector/src/lib.rs:102-103`).
- `outcome_unknown()` is true for every `HostError` except `Unavailable` (`host-connector/src/lib.rs:140-144`). This settles the question doc 03 left open: **`Protocol` counts as outcome unknown**, so the Fleet stops and card-service reverses.

### 3.3 What happens with an unknown response code

Take DE 39 = `"Q7"`, a code that isn't in any list:
1. It isn't `"00"` and isn't a soft code, so it becomes `Declined { Hard }` (`host-connector/src/iso_host.rs:399-400`).
2. It isn't `"51"`, so the result is `FAILED`, `ISSUER_DECLINED`, `HARD_DECLINE`, `retryable: false` (`host-connector/src/unified.rs:99-105`).
3. Consequences:
   - **no cascade:** the Fleet treats a decline as an answer (doc 03 §5.2), and Python only cascades on `retryable`
   - **no reversal:** the status isn't `PENDING`
   - **the idempotency key stores the failure**, so a retry replays it (doc 02 §3)

This **fails safe** against double charging: an unknown code never sends the card to a second acquirer. The trade-off is that a new transient code, which really is soft, reaches the customer as a hard decline until someone adds it to `soft_decline_codes`.

The DE 39 field itself is `FIXED 2, an` in the synthetic dialect (`iso8583/dialects/synthetic-host.json:15`). A value outside `an` fails `unpack`, which becomes `Protocol`, then `PENDING`, then a reversal.

### 3.4 What the mock acquirer sends

The amount picks the answer (`host-connector/mock_host/mock_host.py:7-17`):

| Amount | Response |
| :--- | :--- |
| `5100` | DE 39 `51` (decline) |
| `2000` | sleeps first (timeout) |
| configured soft-decline amounts | `91` |
| any other amount | `00` |

Reversals get `00` if the original is known, else `25` (`host-connector/mock_host/mock_host.py:132-157`). The mock never sends an unknown code, so the path in §3.3 is not exercised by it.

### 3.5 Reversals, connecting to doc 03

- A reversal looks up its original in **this host's in-memory** originals. If it isn't there, the call fails with `Unavailable` **without sending** (`host-connector/src/iso_host.rs:224-228`). That's what lets card-service's empty-hint reversal walk the Fleet until it reaches the one host that holds the original. This resolves doc 03 §5.3's "unverified".
- Originals live only in memory (`host-connector/src/iso_host.rs:17-18`). After a restart without the durable reversal queue, every host answers `Unavailable` and **the reversal can't be sent at all**. That's the same production risk as doc 03 #9, now confirmed at the source.
- A reversal answered `25` (original not found) counts as a decline, so card-service marks the reversal `Failed`, even though `25` usually means the host never processed the original (doc 03 §5.3; `host-connector/mock_host/mock_host.py:16-17`).

---

## 4. The runtime BDK

### 4.1 Where it's set

| Where | What | Ref |
| :--- | :--- | :--- |
| card-service reads it | `SimHsm::from_hex(&var("SIM_HSM_BDK_HEX"))`; exits if unset | `card-service/src/main.rs:142` |
| **Sandbox launcher (application package)** | `TEST_BDK_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"` passed as `SIM_HSM_BDK_HEX` | `backend/app/sandbox.py:28-29`, `:160` |
| Test helper | same constant | `backend/tests/card_sim.py:10` |
| e2e / chaos / certification / reversal tests | import it and set `SIM_HSM_BDK_HEX` | `backend/tests/e2e_stack.py:17`, `:120`, `:151`; `backend/tests/test_chaos_gate.py:35`, `:56`; `backend/tests/test_certification_harness.py:16`, `:38`; `backend/tests/test_reversal_queue.py:21`, `:42`, `:122` |
| Rust tests | same constant | `card-service/tests/flow.rs:19`, `card-service/tests/vault.rs:22`, `card-service/src/hsm.rs:403` |
| Docs | the same key in a copy-paste command | `docs/step5.md:87` |
| Production (ECS) | not in the repo: card-service secrets are injected from AWS Secrets Manager as environment variables | `infra/ecs/modules/region/main.tf:95`, `:144` |

`sandbox.py` is a standalone launcher (`python -m app.sandbox`, `backend/app/sandbox.py:1-9`). Nothing else in `backend/app/` imports it.

### 4.2 Findings

> **CRITICAL SECURITY FLAW: the BDK is hardcoded in the repository.** The 32-byte sequential key
> `000102…1e1f` is written out in **5 source files and 1 doc**, and 4 more test files import it (§4.1). One of them is `backend/app/sandbox.py:29`, which ships
> inside the production backend package. Every comment calls it a test key ("Never use it for anything real",
> `backend/app/sandbox.py:28`; "TEST KEY ONLY", `card-service/src/main.rs:6`). Nothing enforces that, though:
> **card-service accepts this key in any environment.** `SimHsm::new` checks only the length (16 or 32 bytes) and
> that it's valid hex (`card-service/src/hsm.rs:148-166`). If an operator copies `docs/step5.md:87`, or the
> Secrets Manager entry is seeded from it, every terminal envelope, every vault entry and every PAN fingerprint is
> decryptable or forgeable by anyone with the repo. Every key derives from this one BDK
> (`card-service/src/hsm.rs:168-191`).

> **CRITICAL SECURITY FLAW: the production BDK is exposed in plaintext in the process environment.** In ECS it's
> delivered as an environment variable from Secrets Manager (`infra/ecs/modules/region/main.tf:95`, `:144`) and read
> with `env::var` (`card-service/src/main.rs:50-52`, `:142`). Environment variables can be read from
> `/proc/<pid>/environ`, crash dumps, `docker inspect`, and any child process. No zeroization is possible for the
> environment copy: `SimHsm` zeroizes only its own copy (`card-service/src/hsm.rs:143`, `:156`). A real payment
> HSM never releases the BDK at all (`card-service/src/hsm.rs:3-7`).

> **PRODUCTION RISK: PIN never reaches the issuer.** DE 52 isn't built (§2.2), so online-PIN transactions are
> sent without the PIN.

> **PRODUCTION RISK: DE 3 is hardcoded `000000`** for authorizations, purchases and reversals
> (`host-connector/src/iso_host.rs:344`). Refunds, balance inquiries and cash would all need their own codes;
> today they'd go out as purchases if anyone routed them here.

> **PRODUCTION RISK: DE 12/13 send UTC as local time** (`host-connector/src/iso_host.rs:348`). For an Indian
> acquirer that's 5h30 off, which affects settlement-date cut-offs around midnight IST.
