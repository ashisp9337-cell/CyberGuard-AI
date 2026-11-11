const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const ALL = { origins: ["<all_urls>"] };

function cleanBackend(v) {
  let u;
  try { u = new URL(v.trim()); } catch { return null; }
  if (!["http:", "https:"].includes(u.protocol) || !["127.0.0.1", "localhost"].includes(u.hostname)) return null;
  return u.origin;                                   // only CyberGuard on this computer
}

async function load() {
  const s = await api.storage.local.get(["backend", "token", "enabled", "pageCheck", "feeds", "allow"]);
  $("backend").value = s.backend || "http://127.0.0.1:8000";
  $("token").value = s.token || "";
  $("enabled").checked = Boolean(s.enabled);
  $("pageCheck").checked = Boolean(s.pageCheck) && await api.permissions.contains(ALL);
  $("allow").value = (s.allow || []).join("\n");
  $("feeds").checked = Boolean(s.feeds);
}

$("connect").addEventListener("click", async () => {
  const backend = cleanBackend($("backend").value);
  const token = $("token").value.trim();
  if (!backend) { $("conn").textContent = "The address must be CyberGuard on this computer (http://127.0.0.1:8000)."; return; }
  if (!/^cgx_[A-Za-z0-9_-]{20,}$/.test(token)) { $("conn").textContent = "That does not look like a CyberGuard key (cgx_...)."; return; }
  if (!["http://127.0.0.1:8000", "http://localhost:8000"].includes(backend)) {
    const ok = await api.permissions.request({ origins: [backend + "/*"] });
    if (!ok) { $("conn").textContent = "The browser did not allow that address."; return; }
  }
  await api.storage.local.set({ backend, token });
  const r = await api.runtime.sendMessage({ type: "ping" });
  $("conn").textContent = r && r.ok ? "Connected to your CyberGuard." :
    r && r.status === 401 ? "CyberGuard did not accept this key." : "CyberGuard is not reachable - is the backend running?";
});

$("enabled").addEventListener("change", async (e) => {
  await api.storage.local.set({ enabled: e.target.checked });
  $("perm").textContent = e.target.checked ? "Protection is ON." : "Protection is OFF.";
});

$("feeds").addEventListener("change", async (e) => {
  await api.storage.local.set({ feeds: e.target.checked });
  $("perm").textContent = e.target.checked ? "Site names will be looked up on VirusTotal, URLhaus and AbuseIPDB."
    : "Threat lists are not asked any more.";
});

$("pageCheck").addEventListener("change", async (e) => {
  if (e.target.checked) {
    const ok = await api.permissions.request(ALL);        // the browser's own permission prompt
    e.target.checked = ok;
    $("perm").textContent = ok ? "Login pages will be checked." : "Permission not given - login pages are not checked.";
  } else {
    await api.permissions.remove(ALL);
    $("perm").textContent = "Login pages are not checked any more.";
  }
  await api.storage.local.set({ pageCheck: e.target.checked });
});

$("off").addEventListener("click", async () => {
  await api.storage.local.set({ enabled: false, pageCheck: false, feeds: false });
  try { await api.permissions.remove(ALL); } catch { /* not granted */ }
  await load();
  $("perm").textContent = "Everything is off. Nothing is sent.";
});

$("saveAllow").addEventListener("click", async () => {
  const allow = [...new Set($("allow").value.split(/\s+/).map((h) => h.trim().toLowerCase())
    .filter((h) => /^[a-z0-9.-]{3,253}$/.test(h)))].slice(0, 500);
  await api.storage.local.set({ allow });
  $("allow").value = allow.join("\n");
  $("allowMsg").textContent = `Saved ${allow.length} website(s).`;
});

load();
