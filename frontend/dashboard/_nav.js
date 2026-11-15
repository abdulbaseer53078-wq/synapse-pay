const BACKEND_URL = "http://localhost:8000";
const KEY_NAME = "sp_api_key";

function getKey() {
  try { return localStorage.getItem(KEY_NAME) || ""; } catch (_) { return ""; }
}
function setKey(k) {
  try { localStorage.setItem(KEY_NAME, k.trim()); } catch (_) {}
}
function clearKey() {
  try { localStorage.removeItem(KEY_NAME); } catch (_) {}
}
function requireAuth() {
  if (!getKey()) location.href = "index.html";
}
function logout() {
  clearKey();
  location.href = "index.html";
}

async function apiFetch(path, opts = {}) {
  const key = getKey();
  try {
    return await fetch(`${BACKEND_URL}${path}`, {
      ...opts,
      headers: {
        "Authorization": `Bearer ${key}`,
        "Content-Type": "application/json",
        ...(opts.headers || {}),
      },
    });
  } catch (_) {
    return null;
  }
}

function renderSidebar(active) {
  const links = [
    ["overview.html", "Overview"],
    ["settlements.html", "Settlements"],
    ["risk.html", "Risk Holds"],
    ["api_keys.html", "API Keys"],
    ["kyc.html", "KYC"],
  ].map(([href, label]) => {
    const on = active === href;
    return `<a href="${href}" class="block px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${on ? "bg-indigo-900 text-white" : "text-indigo-200 hover:bg-indigo-700 hover:text-white"}">${label}</a>`;
  }).join("\n");

  const el = document.getElementById("sidebar-mount");
  if (!el) return;
  el.innerHTML = `
    <aside class="fixed inset-y-0 left-0 w-56 bg-indigo-800 flex flex-col z-10">
      <div class="px-5 py-5 border-b border-indigo-700">
        <div class="text-white font-bold">Synapse Pay</div>
        <div class="text-indigo-300 text-xs mt-0.5">Merchant Dashboard</div>
      </div>
      <nav class="flex-1 px-3 py-4 space-y-1">${links}</nav>
      <div class="px-3 pb-4 border-t border-indigo-700 pt-4">
        <button onclick="logout()" class="w-full text-left text-indigo-300 hover:text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-colors">Log out</button>
      </div>
    </aside>`;
}

function fmt(paise, currency = "INR") {
  return new Intl.NumberFormat("en-IN", { style: "currency", currency, minimumFractionDigits: 2 })
    .format(paise / 100);
}
