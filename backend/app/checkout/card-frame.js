// Synapse Pay card frame. Runs on Synapse's origin inside the merchant's page, so the merchant's code can't
// read what's typed here. The card number and CVV are encrypted in this frame to the HSM's public checkout key
// (sp2: ECDH P-256 + HKDF-SHA256 + AES-256-GCM) and only ciphertext leaves it.
(() => {
  "use strict";
  const hash = new URLSearchParams(location.hash.slice(1));
  const parentOrigin = hash.get("origin");
  if (!parentOrigin || !/^https?:\/\/[^/]+$/.test(parentOrigin)) {
    document.body.textContent = "This card form must be opened by the Synapse Pay SDK.";
    return;
  }
  const $ = (id) => document.getElementById(id);
  const number = $("number"), expiry = $("expiry"), cvc = $("cvc"), errorBox = $("error");
  const text = new TextEncoder();
  let checkoutKey = null;
  let busy = false;

  const post = (message) => window.parent.postMessage({ source: "synapsepay", ...message }, parentOrigin);

  const digits = (s) => s.replace(/\D/g, "");

  function brand(pan) {
    if (/^4/.test(pan)) return "VISA";
    if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(pan)) return "MASTERCARD";
    if (/^3[47]/.test(pan)) return "AMEX";
    if (/^(60|65|81|82|508|353|356)/.test(pan)) return "RUPAY";
    return null;
  }

  function luhn(pan) {
    let sum = 0;
    for (let i = 0; i < pan.length; i++) {
      let d = Number(pan[pan.length - 1 - i]);
      if (i % 2) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    return sum % 10 === 0;
  }

  function expiryParts() {
    const d = digits(expiry.value);
    return d.length === 4 ? { mm: d.slice(0, 2), yy: d.slice(2) } : null;
  }

  function problem() {
    const pan = digits(number.value);
    if (pan.length < 13 || pan.length > 19 || !luhn(pan)) return ["number", "Enter a valid card number."];
    if (!brand(pan)) return ["number", "This card type isn't accepted."];
    const exp = expiryParts();
    if (!exp || Number(exp.mm) < 1 || Number(exp.mm) > 12) return ["expiry", "Enter the expiry as MM / YY."];
    const now = new Date(), year = 2000 + Number(exp.yy), month = Number(exp.mm);
    if (year < now.getFullYear() || (year === now.getFullYear() && month < now.getMonth() + 1)) {
      return ["expiry", "This card has expired."];
    }
    const cvcLen = brand(pan) === "AMEX" ? 4 : 3;
    if (digits(cvc.value).length !== cvcLen) return ["cvc", `Enter the ${cvcLen}-digit security code.`];
    return null;
  }

  // onlyTouched: on blur, flag a field only once the customer has typed in it.
  function show(p, onlyTouched) {
    for (const el of [number, expiry, cvc]) el.removeAttribute("aria-invalid");
    errorBox.textContent = "";
    if (!p) return;
    const [field, message] = p;
    if (onlyTouched && !$(field).value) return;
    $(field).setAttribute("aria-invalid", "true");
    errorBox.textContent = message;
  }

  function changed() {
    const pan = digits(number.value);
    number.value = pan.replace(/(\d{4})(?=\d)/g, "$1 ").slice(0, 23);
    const e = digits(expiry.value).slice(0, 4);
    expiry.value = e.length > 2 ? `${e.slice(0, 2)} / ${e.slice(2)}` : e;
    cvc.value = digits(cvc.value).slice(0, 4);
    const p = problem();
    // Only brand and completeness reach the merchant's page: never digits.
    post({ type: "change", complete: !p, brand: brand(pan), empty: !pan && !e && !cvc.value });
  }
  for (const el of [number, expiry, cvc]) {
    el.addEventListener("input", changed);
    el.addEventListener("blur", () => show(problem(), true));
  }

  const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  async function loadKey() {
    const response = await fetch("/api/v1/checkout/key", { credentials: "omit" });
    if (!response.ok) throw new Error("checkout key unavailable");
    const { kty, crv, x, y } = await response.json();
    checkoutKey = await crypto.subtle.importKey("jwk", { kty, crv, x, y, ext: true },
                                                { name: "ECDH", namedCurve: "P-256" }, false, []);
  }

  async function seal(plaintext, usage) {
    const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const epk = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: checkoutKey }, ephemeral.privateKey, 256);
    const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: epk, info: text.encode(`synapsepay/checkout/v1/${usage}`) },
      hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: text.encode(usage) }, key, text.encode(plaintext)));
    const body = new Uint8Array(nonce.length + ct.length);
    body.set(nonce); body.set(ct, nonce.length);
    return `sp2.${b64url(epk)}.${b64url(body)}`;
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // Confirming twice is safe (the server returns the intent's current state), so network failures and
  // retryable answers are retried up to 3 times with backoff.
  async function send(intentId, body) {
    let last = { code: "ERR_NETWORK", message: "Couldn't reach Synapse Pay. Check your connection." };
    for (let attempt = 0; attempt < 4; attempt++) {
      if (attempt) await sleep(400 * 2 ** (attempt - 1));
      let response;
      try {
        response = await fetch(`/api/v1/payment_intents/${encodeURIComponent(intentId)}/confirm`, {
          method: "POST", credentials: "omit", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      } catch { continue; }
      const data = await response.json().catch(() => ({}));
      if (response.ok) return { intent: data };
      last = { code: data.error_code || "ERR_SYSTEM", message: data.error_message || "Payment failed.",
               category: data.error_category, retryable: !!data.retryable };
      if (!data.retryable && response.status < 500) break;
    }
    return { error: last };
  }

  async function confirm({ requestId, intentId, clientSecret }) {
    if (busy) return post({ type: "confirm-result", requestId, error: { code: "ERR_BUSY", message: "Already paying." } });
    const p = problem();
    if (p) { show(p, false); return post({ type: "confirm-result", requestId, error: { code: "ERR_CARD_INCOMPLETE", message: p[1] } }); }
    busy = true;
    for (const el of [number, expiry, cvc]) el.disabled = true;
    try {
      if (!checkoutKey) await loadKey();
      const pan = digits(number.value), exp = expiryParts();
      const card = {
        encrypted_card_data: await seal(pan, "data"),
        encrypted_cvv: await seal(digits(cvc.value), "cvv"),
        card_expiry: `${exp.mm}/${exp.yy}`,
        card_network: brand(pan),
      };
      const result = await send(intentId, { client_secret: clientSecret, payment_method: "CARD", card });
      post({ type: "confirm-result", requestId, ...result });
    } catch (e) {
      post({ type: "confirm-result", requestId, error: { code: "ERR_SYSTEM", message: "Couldn't secure the card details." } });
    } finally {
      cvc.value = "";  // never kept after an attempt
      busy = false;
      for (const el of [number, expiry, cvc]) el.disabled = false;
    }
  }

  window.addEventListener("message", (event) => {
    if (event.origin !== parentOrigin || event.source !== window.parent) return;
    const data = event.data || {};
    if (data.source !== "synapsepay-sdk") return;
    if (data.type === "confirm") confirm(data);
    if (data.type === "clear") { number.value = expiry.value = cvc.value = ""; changed(); }
    if (data.type === "focus") number.focus();
  });

  loadKey().then(() => post({ type: "ready" }), () => post({ type: "error", error: { code: "ERR_SYSTEM", message: "Card form unavailable." } }));
})();
