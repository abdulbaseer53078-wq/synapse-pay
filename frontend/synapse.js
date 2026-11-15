/**
 * Synapse Checkout SDK — vanilla JS, no dependencies.
 *
 * Card data is encrypted with RSA-OAEP (SubtleCrypto) before leaving the browser.
 * The backend receives `encrypted_card_data` (base64), never a plaintext PAN or CVV.
 * This keeps the merchant's server out of PCI scope.
 *
 * Usage:
 *   SynapseCheckout.open(checkoutUrl, publicKeyPem)
 *     checkoutUrl  — the checkout_url from POST /api/v1/checkout/sessions
 *     publicKeyPem — the terminal/session RSA public key (provided by your backend)
 */
const SynapseCheckout = (() => {
  /* ── DOM helpers ─────────────────────────────────────────────────── */

  function _css(el, styles) {
    Object.assign(el.style, styles);
  }

  function _el(tag, attrs = {}, styles = {}) {
    const el = document.createElement(tag);
    Object.assign(el, attrs);
    _css(el, styles);
    return el;
  }

  function _buildOverlay() {
    const overlay = _el("div", { id: "synapse-overlay" }, {
      position: "fixed", inset: "0", background: "rgba(0,0,0,.55)",
      display: "flex", alignItems: "center", justifyContent: "center",
      zIndex: "999999", fontFamily: "system-ui,sans-serif",
    });

    const card = _el("div", {}, {
      background: "#fff", borderRadius: "12px", padding: "32px",
      width: "min(420px, 92vw)", boxSizing: "border-box",
      boxShadow: "0 8px 40px rgba(0,0,0,.18)",
    });

    const title = _el("h2", { textContent: "Complete payment" }, {
      margin: "0 0 24px", fontSize: "18px", fontWeight: "600", color: "#111",
    });

    const closeBtn = _el("button", { textContent: "✕", title: "Cancel" }, {
      position: "absolute", top: "16px", right: "20px",
      background: "none", border: "none", fontSize: "20px",
      cursor: "pointer", color: "#666", lineHeight: "1",
    });
    _css(card, { position: "relative" });

    const form = _el("form", { id: "synapse-form" });

    function _field(labelText, inputAttrs) {
      const wrap = _el("div", {}, { marginBottom: "16px" });
      const label = _el("label", { textContent: labelText }, {
        display: "block", fontSize: "13px", fontWeight: "500",
        color: "#444", marginBottom: "6px",
      });
      const input = _el("input", inputAttrs, {
        width: "100%", padding: "10px 12px", border: "1px solid #ccc",
        borderRadius: "6px", fontSize: "15px", boxSizing: "border-box",
        outline: "none",
      });
      input.addEventListener("focus",  () => { input.style.borderColor = "#4f46e5"; });
      input.addEventListener("blur",   () => { input.style.borderColor = "#ccc"; });
      wrap.append(label, input);
      return { wrap, input };
    }

    const { wrap: panWrap, input: panInput } = _field("Card number", {
      id: "synapse-pan", type: "text", inputMode: "numeric",
      placeholder: "1234 5678 9012 3456", maxLength: "19", autocomplete: "cc-number",
      required: true,
    });

    // Format PAN with spaces as the user types; never log the value.
    panInput.addEventListener("input", () => {
      const digits = panInput.value.replace(/\D/g, "").slice(0, 16);
      panInput.value = digits.replace(/(.{4})/g, "$1 ").trimEnd();
    });

    const row = _el("div", {}, { display: "flex", gap: "12px" });

    const { wrap: expWrap, input: expInput } = _field("Expiry (MM/YY)", {
      id: "synapse-exp", type: "text", inputMode: "numeric",
      placeholder: "MM/YY", maxLength: "5", autocomplete: "cc-exp", required: true,
    });
    expInput.addEventListener("input", () => {
      let v = expInput.value.replace(/\D/g, "").slice(0, 4);
      if (v.length > 2) v = v.slice(0, 2) + "/" + v.slice(2);
      expInput.value = v;
    });
    _css(expWrap, { flex: "1" });

    const { wrap: cvvWrap, input: cvvInput } = _field("CVV", {
      id: "synapse-cvv", type: "password", inputMode: "numeric",
      placeholder: "•••", maxLength: "4", autocomplete: "cc-csc", required: true,
    });
    _css(cvvWrap, { flex: "1" });

    row.append(expWrap, cvvWrap);

    const statusEl = _el("p", {}, {
      minHeight: "20px", fontSize: "13px", margin: "0 0 12px",
      color: "#c00", display: "none",
    });

    const submitBtn = _el("button", { textContent: "Pay now", type: "submit" }, {
      width: "100%", padding: "12px", background: "#4f46e5",
      color: "#fff", border: "none", borderRadius: "8px",
      fontSize: "16px", fontWeight: "600", cursor: "pointer",
      marginTop: "8px",
    });
    submitBtn.addEventListener("mouseover", () => { submitBtn.style.background = "#4338ca"; });
    submitBtn.addEventListener("mouseout",  () => { submitBtn.style.background = "#4f46e5"; });

    form.append(panWrap, row, statusEl, submitBtn);
    card.append(closeBtn, title, form);
    overlay.append(card);

    return { overlay, form, panInput, expInput, cvvInput, statusEl, submitBtn, closeBtn };
  }

  /* ── Encryption ──────────────────────────────────────────────────── */

  async function _importPublicKey(pemOrJwk) {
    // Accepts either a JWK object/JSON string (from GET /api/v1/checkout/key)
    // or a PEM-encoded SPKI public key string.
    const jwk = (typeof pemOrJwk === "object" && pemOrJwk !== null) ? pemOrJwk
              : (() => { try { const p = JSON.parse(pemOrJwk); return (p.kty) ? p : null; } catch { return null; } })();
    if (jwk) {
      return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    }
    const b64 = pemOrJwk.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
    const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  }

  async function _encrypt(publicKey, payload) {
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    const cipher = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, bytes);
    return btoa(String.fromCharCode(...new Uint8Array(cipher)));
  }

  /* ── Core ────────────────────────────────────────────────────────── */

  /**
   * Open the payment modal.
   * @param {string} checkoutUrl   - checkout_url from POST /api/v1/checkout/sessions
   * @param {string} publicKeyPem  - RSA public key PEM (provided by your server)
   */
  async function open(checkoutUrl, publicKeyPem) {
    if (document.getElementById("synapse-overlay")) return; // already open

    let pubKey;
    try {
      pubKey = await _importPublicKey(publicKeyPem);
    } catch {
      console.error("[SynapseCheckout] Invalid public key — cannot open checkout safely.");
      return;
    }

    const { overlay, form, panInput, expInput, cvvInput, statusEl, submitBtn, closeBtn } = _buildOverlay();

    function _close() { overlay.remove(); }
    closeBtn.addEventListener("click", _close);
    overlay.addEventListener("click", e => { if (e.target === overlay) _close(); });

    function _setStatus(msg, isError = true) {
      statusEl.textContent = msg;
      statusEl.style.color = isError ? "#c00" : "#166534";
      statusEl.style.display = "block";
    }

    form.addEventListener("submit", async e => {
      e.preventDefault();
      submitBtn.disabled = true;
      submitBtn.textContent = "Processing…";
      statusEl.style.display = "none";

      const panRaw    = panInput.value.replace(/\s/g, "");
      const expParts  = expInput.value.split("/");
      const expiry    = expParts.length === 2 ? `20${expParts[1]}-${expParts[0]}` : "";

      // Card data never leaves this closure as plaintext — only the ciphertext is sent.
      let encryptedCardData;
      try {
        encryptedCardData = await _encrypt(pubKey, {
          pan:    panRaw,
          expiry: expiry,
          cvv:    cvvInput.value,
        });
      } catch {
        _setStatus("Encryption failed. Please refresh and try again.");
        submitBtn.disabled = false;
        submitBtn.textContent = "Pay now";
        return;
      }

      // Clear sensitive fields immediately after encrypting — do not let them sit in the DOM.
      panInput.value  = "";
      expInput.value  = "";
      cvvInput.value  = "";

      try {
        const res = await fetch(checkoutUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ encrypted_card_data: encryptedCardData }),
        });
        const body = await res.json();

        if (res.ok) {
          _setStatus("Payment successful! Redirecting…", false);
          setTimeout(() => {
            _close();
            if (body.success_url) window.location.href = body.success_url;
          }, 1500);
        } else {
          const msg = body.error_message || body.message || "Payment failed. Please try again.";
          _setStatus(msg);
          submitBtn.disabled = false;
          submitBtn.textContent = "Pay now";
        }
      } catch {
        _setStatus("Network error. Please check your connection and try again.");
        submitBtn.disabled = false;
        submitBtn.textContent = "Pay now";
      }
    });

    document.body.appendChild(overlay);
    panInput.focus();
  }

  return { open };
})();
