import { createHmac, timingSafeEqual } from "node:crypto";

import { SynapsePaySignatureError } from "./errors.js";
import type { TransactionEvent } from "./types.js";

/**
 * Verifies a webhook and returns its event. Pass the raw request body exactly as received (a string or Buffer,
 * before any JSON parsing), the X-Signature header, and your webhook secret (whsec_...).
 *
 *   app.post("/webhooks", express.raw({ type: "application/json" }), (req, res) => {
 *     const event = synapse.webhooks.constructEvent(req.body, req.get("x-signature"), process.env.SYNAPSE_WEBHOOK_SECRET);
 *     ...
 *   });
 *
 * The same event can arrive more than once (retries): handle it idempotently, by transaction_id.
 */
export function constructEvent(rawBody: string | Buffer | Uint8Array, signature: string | undefined | null,
                               secret: string): TransactionEvent {
  if (!secret) throw new SynapsePaySignatureError("Webhook secret is missing.", { code: "ERR_SIGNATURE" });
  if (typeof rawBody !== "string" && !(rawBody instanceof Uint8Array)) {
    throw new SynapsePaySignatureError("Pass the raw body (string or Buffer), not parsed JSON.", { code: "ERR_SIGNATURE" });
  }
  if (!signature || !/^[0-9a-f]{64}$/.test(signature)) {
    throw new SynapsePaySignatureError("Missing or malformed X-Signature header.", { code: "ERR_SIGNATURE" });
  }
  const body = typeof rawBody === "string" ? Buffer.from(rawBody, "utf8") : Buffer.from(rawBody);
  const expected = createHmac("sha256", secret).update(body).digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, "hex"))) {
    throw new SynapsePaySignatureError("Webhook signature doesn't match: not from Synapse Pay, or the body changed.",
                                       { code: "ERR_SIGNATURE" });
  }
  return JSON.parse(body.toString("utf8")) as TransactionEvent;
}
