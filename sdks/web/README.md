# @synapsepay/web

Take card payments on any website (plain HTML, React, Vue, Svelte...). The card form is Synapse Pay's own
page inside an iframe, so your site never sees a card number and stays out of PCI DSS scope.

```html
<div id="card"></div>
<button id="pay">Pay ₹500</button>
<script src="https://YOUR-SYNAPSE-HOST/js/synapsepay.js"></script>   <!-- or: npm install @synapsepay/web -->
<script>
  const synapse = SynapsePay({ apiBase: "https://YOUR-SYNAPSE-HOST" });
  const card = synapse.mountCard("#card", { onChange: (e) => (pay.disabled = !e.complete) });

  pay.onclick = async () => {
    const clientSecret = await fetch("/create-payment", { method: "POST" }).then((r) => r.text()); // your server
    const { paymentIntent, error } = await synapse.confirmCardPayment(clientSecret, card);
    if (error) showMessage(error);                      // see the codes below
    else if (paymentIntent.status === "SUCCEEDED") showThanks();
    else showMessage("We're confirming your payment."); // PROCESSING: wait for your webhook
  };
</script>
```

`confirmCardPayment` handles the bank's 3-D Secure step (an OTP page in a modal) when the bank asks for it, which
is most online card payments in India. Calling it again after an error is safe: an intent is never charged twice.

**In-store, on a terminal:** create the intent on your server with `terminal_id`, then:

```js
const { paymentIntent, error } = await synapse.waitForTerminalPayment(clientSecret);
```

**Error codes** (`error.code`; `error.apiCode` has Synapse's raw code):

| Code | Tell the customer |
| :--- | :--- |
| `ERR_NETWORK` | Check your internet connection and try again. |
| `ERR_CARD_INCOMPLETE` | (the card form shows what's missing) |
| `ERR_CARD_DECLINED` | Your bank declined the card. Try another card. |
| `ERR_AUTHENTICATION_FAILED` | Your bank couldn't verify this payment. Try again or use another card. |
| `ERR_CANCELED` | The payment was canceled. |
| `ERR_TIMEOUT` | (terminal only) The payment didn't finish in time. |
| `ERR_INVALID_REQUEST` | A bug in the integration: check the client secret and the intent's state. |
| `ERR_SYSTEM_ERROR` | Something went wrong. Try again in a moment. |

Builds: `dist/synapsepay.esm.js` (bundlers) and `dist/synapsepay.js` (a `<script>` tag; `window.SynapsePay`).
~5 KB minified, no dependencies.
