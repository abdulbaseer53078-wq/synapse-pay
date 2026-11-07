# Quickstart: take a test payment in 5 minutes

You'll run the Synapse Pay sandbox on your machine, start an example shop, and pay ₹500 with a test card,
including the bank's OTP step that most Indian cards ask for.

**You need:** PostgreSQL running (user `postgres`, password `postgres`, or set `DATABASE_URL`), Python 3.12+,
Rust (`cargo`), and Node.js 18+.

## 1. Start the sandbox

```bash
cd backend
pip install -r requirements.txt
python -m app.sandbox
```

The first run builds the card service, which takes a few minutes. When it's ready it prints your **secret key**
(`sk_test_...`) and **webhook secret** (`whsec_...`). Leave it running.

## 2. Start the example shop

In a second terminal:

```bash
cd examples/node-shop
npm install
SYNAPSE_SECRET_KEY=sk_test_... SYNAPSE_WEBHOOK_SECRET=whsec_... npm start
```

(On Windows PowerShell: `$env:SYNAPSE_SECRET_KEY="sk_test_..."; $env:SYNAPSE_WEBHOOK_SECRET="whsec_..."; npm start`)

## 3. Pay

Open http://localhost:3000, enter `4111 1111 1111 1111`, any future expiry and any CVV, and press **Pay**. The
sandbox bank asks for an OTP: enter `123456`. The page says the payment went through, and the shop's terminal
prints `webhook verified: pi_... CAPTURED`.

## Test cards

| Card | What happens |
| :--- | :--- |
| `4242 4242 4242 4242` | Pays without an OTP |
| `4111 1111 1111 1111` | Asks for the OTP `123456` (a wrong OTP fails authentication) |
| `4000 0000 0000 3238` | The bank refuses to authenticate |
| any card, amount ₹51.00 | The bank declines (insufficient funds) |
| any card, amount ₹20.00 | The bank never answers; Synapse reverses it and reports `HOST_TIMEOUT` |

## What the shop did

`examples/node-shop/server.js` is the whole integration:

1. **Server:** `synapse.paymentIntents.create({ amount: 50000 })` with the secret key, so the price can't be
   changed in the browser. It sends the intent's `client_secret` to the page.
2. **Page:** `synapse.mountCard("#card")` shows Synapse's card form in an iframe, and
   `synapse.confirmCardPayment(clientSecret, card)` pays, OTP included. The card number never reaches the shop.
3. **Webhook:** `synapse.webhooks.constructEvent(rawBody, signature, secret)` proves the notification came from
   Synapse before the shop trusts it.

Next: [the web SDK](../sdks/web/README.md), [the Node SDK](../sdks/node/README.md), [Android](../sdks/android/README.md),
[how it works](step6.md).
