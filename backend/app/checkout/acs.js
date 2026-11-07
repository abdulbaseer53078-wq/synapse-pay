// Sandbox issuer (ACS) page for 3-D Secure challenges. Tells the opener page when the cardholder is done.
(() => {
  "use strict";
  const query = new URLSearchParams(location.search);
  const intentId = location.pathname.split("/").pop();
  const clientSecret = query.get("client_secret");
  const parentOrigin = query.get("parent_origin");
  // Mobile SDKs show this page in a WebView and watch for this URL instead of a message. Only this scheme is
  // allowed, so the page can't be used to redirect anywhere else.
  const returnUrl = query.get("return_url");
  const done = (status) => {
    if (returnUrl && returnUrl.startsWith("synapsepay-sdk://")) {
      location.href = `${returnUrl}?status=${encodeURIComponent(status)}`;
      return;
    }
    if (parentOrigin && /^https?:\/\/[^/]+$/.test(parentOrigin)) {
      window.parent.postMessage({ source: "synapsepay", type: "3ds-complete", status }, parentOrigin);
    }
  };
  document.getElementById("cancel").addEventListener("click", () => done("CANCELED_BY_CUSTOMER"));
  document.getElementById("otp-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const otp = document.getElementById("otp").value;
    document.getElementById("submit").disabled = true;
    try {
      const response = await fetch(`/sandbox/acs/${encodeURIComponent(intentId)}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_secret: clientSecret, otp }) });
      const intent = await response.json();
      done(intent.status);
    } catch {
      document.getElementById("error").textContent = "Couldn't reach the bank. Try again.";
      document.getElementById("submit").disabled = false;
    }
  });
})();
