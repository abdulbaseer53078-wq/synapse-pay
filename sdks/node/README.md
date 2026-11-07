# @synapsepay/node

Server SDK for Synapse Pay. Runs on your server only: it holds your secret key.

```bash
npm install @synapsepay/node
```

```js
import SynapsePay from "@synapsepay/node";

const synapse = new SynapsePay(process.env.SYNAPSE_SECRET_KEY, { apiBase: "https://sandbox.synapsepay.example" });

// 1. Create the payment on your server: the amount can't be changed in the browser.
const intent = await synapse.paymentIntents.create({ amount: 50000, metadata: { order_id: "7781" } }); // ₹500.00
// 2. Send intent.client_secret to your page; @synapsepay/web takes the card.

// 3. Verify webhooks on the raw body.
app.post("/webhooks/synapse", express.raw({ type: "application/json" }), (req, res) => {
  const event = synapse.webhooks.constructEvent(req.body, req.get("x-signature"), process.env.SYNAPSE_WEBHOOK_SECRET);
  if (event.status === "CAPTURED") fulfil(event.payment_intent_id);
  res.sendStatus(200);
});
```

Pay on a physical terminal instead: `paymentIntents.create({ amount, terminal_id })`.

**Retries are automatic and safe.** Every create carries an idempotency key; network failures, 5xx answers and
"still processing" answers are retried up to 3 times with backoff, resending the same key, so a retry never
creates a second payment. Errors are `SynapsePayAuthenticationError`, `SynapsePayInvalidRequestError` (fix the
request), `SynapsePayConnectionError` and `SynapsePayApiError` (both safe to retry later), each with `code`,
`category`, `retryable` and `statusCode`.

Requires Node.js 18+. No runtime dependencies.
