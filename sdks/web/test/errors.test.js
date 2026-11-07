import assert from "node:assert/strict";
import { test } from "node:test";

import { fromApi } from "../dist/synapsepay.esm.js";

test("declines map to ERR_CARD_DECLINED, keeping the API code", () => {
  const e = fromApi({ error_code: "INSUFFICIENT_FUNDS", error_message: "declined", error_category: "HARD_DECLINE",
                      retryable: false });
  assert.deepEqual(e, { code: "ERR_CARD_DECLINED", message: "declined", retryable: false,
                        apiCode: "INSUFFICIENT_FUNDS", category: "HARD_DECLINE" });
  assert.equal(fromApi({ error_category: "SOFT_DECLINE" }).code, "ERR_CARD_DECLINED");
});

test("other categories", () => {
  assert.equal(fromApi({ error_code: "AUTHENTICATION_FAILED", error_category: "HARD_DECLINE" }).code,
               "ERR_AUTHENTICATION_FAILED");
  assert.equal(fromApi({ error_code: "PAYMENT_INTENT_NOT_FOUND", error_category: "VALIDATION_ERROR" }).code,
               "ERR_INVALID_REQUEST");
  const system = fromApi({ error_code: "INTERNAL_ERROR", error_category: "SYSTEM_ERROR", retryable: true });
  assert.equal(system.code, "ERR_SYSTEM_ERROR");
  assert.equal(system.retryable, true);
  assert.equal(fromApi({ code: "ERR_NETWORK", message: "offline" }).retryable, true);
  assert.equal(fromApi(undefined).code, "ERR_SYSTEM_ERROR");
});
