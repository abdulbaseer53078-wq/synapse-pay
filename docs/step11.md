# Step 11 — the QR adapter

QR is not a rail. A `upi://pay?...` string is a VPA in a URI; a Bharat QR carries card-network tokens. So this
adapter moves no money: it parses the string, names the rail it encodes, rewrites the request for that rail and
delegates. Refunds, status, webhooks and every error mapping stay with the real rail, unchanged.

## What shipped

| Piece | Where |
| :--- | :--- |
| `QrMethodAdapter` (parse, dispatch, descriptor) | `backend/app/infrastructure/methods/qr.py` |
| `generate_qr()` — dynamic intent string | same file |
| `qr_encoded_rail` persisted per transaction | migration `011_qr_rail.sql`, `NewTransaction`, `claim()` |
| Rail in the audit trail | `transaction.create` row carries `{"qr_encoded_rail": "UPI"}` |
| Registry wiring | `backend/app/main.py` |
| Tests | `backend/tests/test_qr.py` (18) |

## The dispatch

```python
rails = MethodRegistry([card, upi])          # what QR may route to
methods = MethodRegistry([card, upi, QrMethodAdapter(rails)])
```

`send()` parses `details["qr_data"]`, checks the amount, and calls `rails.for_method(rail).initiate(...)`. There
is no rail-specific code in the QR adapter beyond building the inner request — which is the point: adding a QR
carrying a new rail is a line in `parse_qr`, not a new adapter.

## Two things worth calling out

**The QR amount must equal the charge.** A QR generated for ₹15.00 that arrives as a ₹1.00 request is rejected
before the rail is touched (`test_the_qr_amount_must_match_the_charge`). A static QR that leaves the amount to
the payer is exactly the tampering dynamic QR prevents.

**The QR descriptor is the contract's *fallback* one.** The spec says a QR payment on a known rail follows that
rail's descriptor, and the `QR` descriptor applies only when `qr_encoded_rail` is `UNKNOWN`. So it reports
`settlement_timeline: unknown`, `supports_refund: false`, `is_synchronous: false` — the honest answer for "we
do not know what this code encodes". The brief's sample said `supports_refund: true`; that is true of a UPI QR
and false of the fallback, and conflating them would let a merchant refund a QR on an unknown rail.

## A bug this step exposed

The UPI webhook resolved a payment with `by_method_reference("UPI", reference)`. A QR payment is stored as
`payment_method = 'QR'` but carries a **UPI** PSP reference, so its own settlement webhook could never find it —
it would have been acknowledged and silently ignored. `by_method_reference` now filters on the reference alone
(`method` is an optional narrowing argument), because a network reference is unique. That is a one-line fix
that would otherwise have surfaced as "QR payments sometimes never settle".

## Not done

- **Bharat QR** raises `UnsupportedOperation`: it needs tokenised card data, which is Step 5B.
- **No endpoint for `generate_qr`.** It is a pure function; the checkout/QR-display route belongs with the
  merchant SDK work, and adding a public route means a spec change and a new auth decision.
- **Scanner is client-side by design** — the SDK extracts the string and posts `qr_data`, as the brief says.
  Nothing here decodes an image.

## Tests

18 cases, no database: parsing (rail, VPA, rupees→paise, absent amount), hostile strings (wrong scheme, missing
or malformed `pa`, non-numeric and negative `am`), Bharat QR rejected, `generate_qr` round-tripping through the
parser, the descriptor, dispatch to a fake UPI adapter, the amount-mismatch rejection, and the engine routing a
QR payment while recording `payment_method=QR` and `qr_encoded_rail=UPI`.
