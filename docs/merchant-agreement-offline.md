# Offline mode: draft merchant-agreement clause (for counsel)

**Status: draft for legal review. Not legal advice and not final wording.** Engineering wrote this to state the
technical facts the clause must rest on (audit finding F-06). Counsel decides the wording, and whether Indian
regulation (including RBI's framework for offline payments) limits what can be offered at all.

## What offline mode is, technically

- While a shop's internet is down, its edge node accepts sales against limits the cloud signed: per payment, and
  per terminal over a rolling 24 hours. It queues them and forwards them when the connection returns
  (store-and-forward).
- **Nobody checks the customer's funds at the moment of sale.** The issuer, PSP or wallet sees the payment only when
  it syncs, and may decline it then: an insufficient balance, a blocked card, a card already spent elsewhere offline.
- Double spending can't be prevented offline, only limited. A customer can spend at several disconnected shops at
  once; each shop's exposure is capped by its own limits.
- When a synced sale is declined, the edge node notifies the merchant's app at once (Step 24.5), and the payment
  is FAILED in the API and in webhooks.
- Tampering with the edge's queue (deleting or editing sales) is detected at sync, and the edge's offline sales are
  held for review.

## Draft clause

> **Offline Mode.** Offline Mode is a store-and-forward service. While Offline Mode is in use, SynapsePay does not
> obtain authorization from the issuer, payment service provider or wallet at the time of sale, and does not
> guarantee that any offline transaction will be authorized when it is submitted. The Merchant accepts offline
> transactions at its own risk and bears all losses from offline transactions that are declined, reversed or
> otherwise not paid when submitted, including where the same payment instrument is used at more than one location
> while offline. SynapsePay will notify the Merchant of each declined offline transaction promptly after submission.
> SynapsePay may set, change or withdraw offline limits, and may suspend Offline Mode for any edge node, at any time.

## Questions for counsel

1. Does RBI's framework for offline payments (its per-payment and total limits, and its rules on who bears the
   loss) apply to this product? If so, what limits and disclosures must the defaults follow?
2. Is shifting the loss to the merchant enforceable, and does the payment aggregator framework require any
   customer-facing disclosure?
3. Do card-scheme and NPCI rules allow store-and-forward for each rail (card, UPI, wallet), and on what terms?
4. What notice period is needed before changing or withdrawing offline limits?
