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

// API strings go into innerHTML; escape them so a merchant-controlled field can't inject markup.
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const ICONS = {
  overview: '<path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/>',
  settlements: '<path d="M3 6h18M3 12h18M3 18h12"/>',
  risk: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/>',
  keys: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9m-3 3l3 3m-6 0l2 2"/>',
  kyc: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="12" r="2.5"/><path d="M14 10h4M14 14h4"/>',
};
function icon(name, cls = "h-4 w-4") {
  return `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
}

function renderSidebar(active) {
  const live = getKey().startsWith("sk_live_");
  const links = [
    ["overview.html", "Overview", "overview"],
    ["settlements.html", "Settlements", "settlements"],
    ["risk.html", "Risk holds", "risk"],
    ["api_keys.html", "API keys", "keys"],
    ["kyc.html", "Business verification", "kyc"],
  ].map(([href, label, ic]) => {
    const on = active === href;
    return `<a href="${href}" ${on ? 'aria-current="page"' : ""}
      class="flex shrink-0 items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors
             ${on ? "bg-slate-100 font-medium text-slate-900" : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"}">
      ${icon(ic)}<span>${label}</span></a>`;
  }).join("");

  const el = document.getElementById("sidebar-mount");
  if (!el) return;
  el.innerHTML = `
    <aside class="border-b border-slate-200 bg-white md:fixed md:inset-y-0 md:left-0 md:flex md:w-60 md:flex-col md:border-b-0 md:border-r">
      <div class="flex items-center justify-between px-4 py-4 md:px-5">
        <div class="flex items-center gap-2">
          <div class="flex h-7 w-7 items-center justify-center rounded-md bg-slate-900 text-xs font-semibold text-white">S</div>
          <span class="text-sm font-semibold text-slate-900">Synapse Pay</span>
        </div>
        <span class="rounded px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide
                     ${live ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"}">${live ? "Live" : "Test"}</span>
      </div>
      <nav class="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-1 md:flex-col md:pb-0">${links}</nav>
      <div class="hidden border-t border-slate-200 p-3 md:block">
        <button onclick="logout()" class="w-full rounded-md px-2.5 py-1.5 text-left text-sm text-slate-500 hover:bg-slate-50 hover:text-slate-900">Sign out</button>
      </div>
    </aside>`;
}

function emptyRow(cols, ic, title, body) {
  return `<tr><td colspan="${cols}" class="px-6 py-14 text-center">
    <div class="mx-auto flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 text-slate-400">${icon(ic, "h-5 w-5")}</div>
    <p class="mt-3 text-sm font-medium text-slate-900">${title}</p>
    <p class="mx-auto mt-1 max-w-sm text-sm text-slate-500">${body}</p>
  </td></tr>`;
}

function fmt(paise, currency = "INR") {
  return new Intl.NumberFormat("en-IN", { style: "currency", currency, minimumFractionDigits: 2 })
    .format(paise / 100);
}

function fmtDate(iso) {
  return new Date(iso).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
}
