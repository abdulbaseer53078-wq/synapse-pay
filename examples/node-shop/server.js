// A complete merchant integration in one file: create the payment on the server, take the card in the browser,
// verify the webhook. Run the sandbox first (python -m app.sandbox in backend/), then:
//   SYNAPSE_SECRET_KEY=sk_test_... SYNAPSE_WEBHOOK_SECRET=whsec_... npm start
import { readFileSync } from "node:fs";
import { createServer } from "node:http";

import SynapsePay from "@synapsepay/node";

const API = process.env.SYNAPSE_API ?? "http://127.0.0.1:8000";
const PORT = Number(process.env.PORT ?? 3000);
const synapse = new SynapsePay(process.env.SYNAPSE_SECRET_KEY, { apiBase: API });
const page = readFileSync(new URL("./index.html", import.meta.url), "utf8").replaceAll("{{API}}", API);

const body = (req) => new Promise((resolve) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => resolve(Buffer.concat(chunks)));
});

createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(page);
    } else if (req.method === "POST" && req.url === "/create-payment") {
      // 1. The amount is decided here, on the server: ₹500.00.
      const intent = await synapse.paymentIntents.create({
        amount: 50000, description: "Order 7781", metadata: { order_id: "7781" },
        webhook_url: `http://localhost:${PORT}/webhooks`,  // https in production
      });
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ clientSecret: intent.client_secret }));
    } else if (req.method === "POST" && req.url === "/webhooks") {
      // 3. Only trust a webhook whose signature checks out, over the raw body.
      const event = synapse.webhooks.constructEvent(await body(req), req.headers["x-signature"],
                                                    process.env.SYNAPSE_WEBHOOK_SECRET);
      console.log(`webhook verified: ${event.payment_intent_id} ${event.status}`);
      res.writeHead(200).end();
    } else {
      res.writeHead(404).end();
    }
  } catch (e) {
    console.error(e.message);
    res.writeHead(e.name === "SynapsePaySignatureError" ? 400 : 500).end();
  }
}).listen(PORT, () => console.log(`Shop on http://localhost:${PORT}`));
