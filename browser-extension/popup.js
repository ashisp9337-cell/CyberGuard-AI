const api = globalThis.browser ?? globalThis.chrome;
(async () => {
  const s = await api.storage.local.get(["enabled", "token", "lastError"]);
  const state = document.getElementById("state");
  if (!s.token) { state.textContent = "Not connected"; state.className = "pill warn"; }
  else if (!s.enabled) { state.textContent = "Protection off"; state.className = "pill off"; }
  else { state.textContent = "Protecting"; state.className = "pill ok"; }
  document.getElementById("err").textContent = s.lastError || "";
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const v = tab ? await api.runtime.sendMessage({ type: "verdict", tabId: tab.id }) : null;
  const page = document.getElementById("page");
  if (v) {
    const names = { danger: ["Dangerous", "bad"], verify: ["Be careful", "warn"], safe: ["No warning signs", "ok"] };
    const [label, cls] = names[v.level] || ["Checked", "off"];
    page.textContent = "";
    const pill = document.createElement("span"); pill.className = `pill ${cls}`; pill.textContent = `${label} - ${v.score}/100`;
    page.appendChild(pill);
    if (v.reasons && v.reasons.length) {
      const ul = document.createElement("ul");
      for (const r of v.reasons.slice(0, 3)) { const li = document.createElement("li"); li.textContent = r; ul.appendChild(li); }
      page.appendChild(ul);
    }
  }
  document.getElementById("opts").addEventListener("click", () => api.runtime.openOptionsPage());
})();
