// CyberGuard AI - Safe Browsing (background). Works in Chrome, Edge, Brave, Opera (service worker) and Firefox.
//
// What it does, only after you switch protection ON in the extension's settings:
//  1. Before a page opens, its ADDRESS is sent to YOUR CyberGuard backend on this computer (127.0.0.1) and judged
//     there by the URL models. Nothing goes to any other server.
//  2. After redirects, the final address is checked together with the addresses it came through.
//  3. Only if you also allowed "check login pages": on a page that asks for a password / card / OTP, the page's code
//     (with anything typed removed) is judged by the fake-login-page model.
// A dangerous page is replaced by a warning page; you can still continue if you are sure.
const api = globalThis.browser ?? globalThis.chrome;
const DEFAULTS = { backend: "http://127.0.0.1:8000", token: "", enabled: false, pageCheck: false, allow: [] };
const recent = new Map();          // tabId -> {url, level, score, reasons, at}
const started = new Map();         // tabId -> the address the navigation started with (to see redirects)

async function settings() {
  return { ...DEFAULTS, ...(await api.storage.local.get(Object.keys(DEFAULTS))) };
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

// Pages that are never sent anywhere: the browser's own pages, files, this computer and the home / office network.
function isPrivate(url) {
  let u;
  try { u = new URL(url); } catch { return true; }
  if (!["http:", "https:"].includes(u.protocol)) return true;
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".localhost") || h.endsWith(".lan") || h === "::1") return true;
  const m = h.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
  }
  return h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80");
}

async function allowedForNow(host) {
  const s = await settings();
  if (s.allow.includes(host)) return true;
  const store = api.storage.session;
  if (!store) return false;
  const { sessionAllow = [] } = await store.get("sessionAllow");
  return sessionAllow.includes(host);
}

async function ask(url, redirects = [], html = null) {
  const s = await settings();
  if (!s.enabled || !s.token) return null;
  try {
    const r = await fetch(`${s.backend}/api/extension/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CyberGuard-Extension": s.token },
      body: JSON.stringify({ url, redirects, html }),
    });
    if (r.status === 401) {
      await api.storage.local.set({ lastError: "CyberGuard did not accept the key. Make a new one in CyberGuard Settings." });
      return null;
    }
    if (!r.ok) return null;
    await api.storage.local.set({ lastError: "" });
    return await r.json();
  } catch {
    await api.storage.local.set({ lastError: "CyberGuard is not running on this computer (start the backend)." });
    return null;
  }
}

async function show(tabId, url, v) {
  if (!v || v.level === "skip") return;
  recent.set(tabId, { url, level: v.level, score: v.score, reasons: v.reasons || [], at: Date.now() });
  const badge = { danger: ["!", "#dc2626"], verify: ["?", "#d97706"], safe: ["", "#16a34a"] }[v.level] || ["", "#16a34a"];
  try {
    await api.action.setBadgeText({ tabId, text: badge[0] });
    await api.action.setBadgeBackgroundColor({ tabId, color: badge[1] });
  } catch { /* the tab was closed */ }
  if (v.level === "danger") {
    const q = new URLSearchParams({ u: url, s: String(v.score), r: JSON.stringify((v.reasons || []).slice(0, 4)) });
    try { await api.tabs.update(tabId, { url: api.runtime.getURL("warning.html") + "?" + q.toString() }); } catch { /* closed */ }
  }
}

async function judge(tabId, url, redirects = [], html = null) {
  if (isPrivate(url) || url.startsWith(api.runtime.getURL(""))) return;
  if (await allowedForNow(hostOf(url))) return;
  await show(tabId, url, await ask(url, redirects, html));
}

api.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId !== 0) return;
  started.set(d.tabId, d.url);
  judge(d.tabId, d.url);
});

api.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  const first = started.get(d.tabId);
  if (first && first !== d.url) judge(d.tabId, d.url, [first]);      // it was redirected: check where it ended up
});

api.webNavigation.onCompleted.addListener(async (d) => {
  if (d.frameId !== 0 || isPrivate(d.url)) return;
  const s = await settings();
  if (!s.enabled || !s.pageCheck || !s.token) return;
  const granted = await api.permissions.contains({ origins: ["<all_urls>"] });
  if (!granted || await allowedForNow(hostOf(d.url))) return;
  try {
    const [res] = await api.scripting.executeScript({ target: { tabId: d.tabId }, files: ["content.js"] });
    const page = res && res.result;
    if (page && page.hasSecretField && page.html) await show(d.tabId, d.url, await ask(d.url, [], page.html));
  } catch { /* pages the browser does not let extensions read (web store, PDF viewer ...) */ }
});

api.tabs.onRemoved.addListener((tabId) => { recent.delete(tabId); started.delete(tabId); });

api.runtime.onInstalled.addListener((info) => {
  if (info.reason === "install") api.runtime.openOptionsPage();       // explain and ask first
});

api.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg && msg.type === "continue" && typeof msg.host === "string" && api.storage.session) {
      const { sessionAllow = [] } = await api.storage.session.get("sessionAllow");
      if (!sessionAllow.includes(msg.host)) sessionAllow.push(msg.host);
      await api.storage.session.set({ sessionAllow: sessionAllow.slice(-200) });
      reply({ ok: true });
    } else if (msg && msg.type === "verdict") {
      reply(recent.get(msg.tabId) || null);
    } else if (msg && msg.type === "ping") {
      const s = await settings();
      try {
        const r = await fetch(`${s.backend}/api/extension/ping`, { headers: { "X-CyberGuard-Extension": s.token } });
        reply({ ok: r.ok, status: r.status });
      } catch { reply({ ok: false, status: 0 }); }
    } else reply(null);
  })();
  return true;      // answer asynchronously
});
