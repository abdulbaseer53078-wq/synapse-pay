# Step 12 — the wallet adapter (tokenised flow)

Wallets differ from cards and UPI in where the money is: it already sits in the user's wallet, so a payment is a
closed-loop transfer the provider performs. That makes the tokenised flow a **direct debit** — one server-to-
server call, settled on the spot — and the redirect flow a hand-off to the provider's own UI.

This step implements the direct debit, which is what the frozen contract models.

## Why not the redirect flow yet

The brief's DoD asks `initiate()` to return a `redirect_url` to the SDK. The contract cannot express that today:

1. `WalletDetails` **requires** `wallet_token` (and `additionalProperties: false`), so a tokenless "redirect me"
   request is a schema violation, not a variation.
2. `TransactionResponse` has no field for "open this URL next". Payment intents already have the concept —
   `next_action: {type, url}` — but transactions do not.

So the redirect flow needs spec **1.7.0**: `wallet_token` optional, and `next_action` on `TransactionResponse`
with a `WALLET_REDIRECT` type, reusing the intent's existing shape rather than inventing an `action_url` beside
it. That is a deliberate decision to make, not something to smuggle in by loosening a schema.

## What shipped

| Piece | Where |
| :--- | :--- |
| Mock wallet provider (pay, debit, status, signed webhook trigger) | `mock-wallet/mock_wallet.py` |
| `WalletMethodAdapter` — tokenised direct debit | `backend/app/infrastructure/methods/wallet.py` |
| Provider client (debit, status) | same file |
| Registry wiring | `backend/app/main.py` |
| Tests | `backend/tests/test_wallet.py` (12) |

## Descriptor

The contract's `WalletCapabilities`, not the brief's: `settlement_timeline: T+0` (the brief said T+1), full
refunds only, no partial refunds, no chargebacks, `is_synchronous: false`.

`is_synchronous: false` looks odd for a debit that settles in-call — but the descriptor describes the *method*,
whose primary flow is the redirect. The token path is a fast path, not a different method.

## Wallet declines

| Provider code | Category | Retryable |
| :--- | :--- | :--- |
| `WALLET_INSUFFICIENT_BALANCE` | `SOFT_DECLINE` | yes — a top-up fixes it |
| `WALLET_BLOCKED` | `HARD_DECLINE` | no — nothing fixes KYC today |
| `WALLET_LIMIT_EXCEEDED` | `HARD_DECLINE` | no — the same amount will fail again |

Transport and 5xx raise `WalletUnavailable` → `AdapterUnavailable`: retryable, and never recorded as a decline.

## Tokens are not stored

The SDK holds the wallet token and passes it per payment. Storing wallet tokens means becoming a token vault —
encryption, rotation, breach surface — for a feature that works without it. If subscriptions need reuse later,
that is a deliberate step with its own threat model.

## Not done

- **Webhook route** (`POST /api/v1/webhooks/wallet`). The handler is provider-generic in behaviour but named for
  UPI; a second provider is exactly when to generalise it, and the route needs the 1.7.0 decision above anyway.
- **Polling fallback** for wallet payments — the same `stale_pending` machinery, with `WALLET_URL` in the job.
- **Partial refunds and auto-debit mandates**, both false in the descriptor.

## Tests

12 cases: the descriptor, token required, unknown provider and extra fields rejected, successful debit settling
immediately with the transaction id as the merchant reference, the two wallet decline mappings, transport
failure staying retryable, `status()` needing the reference, the engine routing `WALLET` and settling, and three
against the real mock provider over HTTP.
