import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";

import SynapsePay, {
  SynapsePayAuthenticationError, SynapsePayConnectionError, SynapsePayInvalidRequestError, SynapsePaySignatureError,
} from "../dist/index.js";

const KEY = "sk_test_abc";

/** A scripted fetch: each call takes the next response (or throws, for a network failure). */
function scripted(...steps) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, ...init, body: init.body && JSON.parse(init.body) });
    const step = steps.shift() ?? { status: 200, body: {} };
    if (step === "network") throw new TypeError("fetch failed");
    return new Response(JSON.stringify(step.body ?? {}), { status: step.status });
  };
  return { fetch, calls };
}

const client = (fetch) => new SynapsePay(KEY, { fetch, apiBase: "https://api.test", retryBaseMs: 1 });

test("refuses anything but a secret key", () => {
  assert.throws(() => new SynapsePay("pk_test_abc"), SynapsePayAuthenticationError);
});

test("create sends amount, INR by default, an idempotency key and the secret key", async () => {
  const { fetch, calls } = scripted({ status: 201, body: { id: "pi_1", client_secret: "pis_1" } });
  const intent = await client(fetch).paymentIntents.create({ amount: 50000, metadata: { order: "7781" } });
  assert.equal(intent.client_secret, "pis_1");
  assert.equal(calls[0].url, "https://api.test/api/v1/payment_intents");
  assert.equal(calls[0].headers.authorization, `Bearer ${KEY}`);
  assert.deepEqual({ ...calls[0].body, idempotency_key: "x" },
                   { amount: 50000, currency: "INR", metadata: { order: "7781" }, idempotency_key: "x" });
  assert.match(calls[0].body.idempotency_key, /^[0-9a-f-]{36}$/);
});

test("retries network failures and 5xx with the same idempotency key", async () => {
  const { fetch, calls } = scripted("network", { status: 503, body: { error_code: "INTERNAL_ERROR", retryable: true } },
                                    { status: 201, body: { id: "pi_1" } });
  const intent = await client(fetch).paymentIntents.create({ amount: 50000 });
  assert.equal(intent.id, "pi_1");
  assert.equal(calls.length, 3);
  assert.equal(new Set(calls.map((c) => c.body.idempotency_key)).size, 1, "one key across retries: never two intents");
});

test("retries a retryable 409 (the same request still running)", async () => {
  const { fetch, calls } = scripted(
    { status: 409, body: { error_code: "IDEMPOTENCY_KEY_CONFLICT", error_category: "SYSTEM_ERROR", retryable: true } },
    { status: 200, body: { id: "pi_1" } });
  assert.equal((await client(fetch).paymentIntents.create({ amount: 50000 })).id, "pi_1");
  assert.equal(calls.length, 2);
});

test("gives up after maxRetries with a connection error", async () => {
  const { fetch, calls } = scripted("network", "network", "network", "network");
  await assert.rejects(client(fetch).paymentIntents.create({ amount: 50000 }),
                       (e) => e instanceof SynapsePayConnectionError && e.code === "ERR_NETWORK" && e.retryable);
  assert.equal(calls.length, 4);
});

test("doesn't retry a bad request or a key conflict", async () => {
  const conflict = { error_code: "IDEMPOTENCY_KEY_CONFLICT", error_message: "used with a different body",
                     error_category: "VALIDATION_ERROR", retryable: false };
  const { fetch, calls } = scripted({ status: 409, body: conflict });
  await assert.rejects(client(fetch).paymentIntents.create({ amount: 50000, idempotency_key: "k" }),
                       (e) => e instanceof SynapsePayInvalidRequestError && e.code === "IDEMPOTENCY_KEY_CONFLICT"
                         && e.statusCode === 409);
  assert.equal(calls.length, 1);
});

test("authentication errors aren't retried", async () => {
  const { fetch, calls } = scripted({ status: 401, body: { error_code: "UNAUTHENTICATED", error_message: "invalid key" } });
  await assert.rejects(client(fetch).paymentIntents.retrieve("pi_1"), SynapsePayAuthenticationError);
  assert.equal(calls.length, 1);
});

test("retrieve and cancel", async () => {
  const { fetch, calls } = scripted({ status: 200, body: { id: "pi_1" } }, { status: 200, body: { status: "CANCELED" } });
  const synapse = client(fetch);
  await synapse.paymentIntents.retrieve("pi_1");
  assert.equal((await synapse.paymentIntents.cancel("pi_1")).status, "CANCELED");
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [
    ["GET", "https://api.test/api/v1/payment_intents/pi_1"],
    ["POST", "https://api.test/api/v1/payment_intents/pi_1/cancel"]]);
});

const SECRET = "whsec_test";
const sign = (body) => createHmac("sha256", SECRET).update(body).digest("hex");

test("constructEvent verifies the signature over the raw body", () => {
  const body = JSON.stringify({ transaction_id: "txn_1", status: "CAPTURED" });
  const synapse = new SynapsePay(KEY);
  assert.equal(synapse.webhooks.constructEvent(body, sign(body), SECRET).status, "CAPTURED");
  assert.equal(synapse.webhooks.constructEvent(Buffer.from(body), sign(body), SECRET).transaction_id, "txn_1");
});

test("constructEvent rejects tampered bodies, wrong secrets and parsed JSON", () => {
  const body = JSON.stringify({ status: "FAILED" });
  const synapse = new SynapsePay(KEY);
  const tampered = body.replace("FAILED", "CAPTURED");
  assert.throws(() => synapse.webhooks.constructEvent(tampered, sign(body), SECRET), SynapsePaySignatureError);
  assert.throws(() => synapse.webhooks.constructEvent(body, sign(body), "whsec_other"), SynapsePaySignatureError);
  assert.throws(() => synapse.webhooks.constructEvent(body, undefined, SECRET), SynapsePaySignatureError);
  assert.throws(() => synapse.webhooks.constructEvent(JSON.parse(body), sign(body), SECRET), SynapsePaySignatureError);
});
