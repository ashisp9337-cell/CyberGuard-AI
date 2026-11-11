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
    // (11 Nov) threat lists (only when switched on in the settings)
    const rep = v.rep;
    const box = document.getElementById("feeds");
    const line = (name, text, cls) => {
      const p = document.createElement("div"); p.className = "small"; p.style.margin = "3px 0";
      const b = document.createElement("strong"); b.textContent = name + ": "; b.style.color = cls === "bad" ? "#fca5a5" : cls === "warn" ? "#fde68a" : "#e2e8f0";
      p.appendChild(b); p.appendChild(document.createTextNode(text)); box.appendChild(p);
    };
    if (rep && rep.trusted) line("Threat lists", "well-known official site - not looked up", "ok");
    else if (rep) {
      const vt = rep.virustotal || {}, uh = rep.urlhaus || {}, ab = rep.abuseipdb || {};
      if (vt.status === "ok") {
        const votes = (vt.malicious || 0) + (vt.suspicious || 0);
        line("VirusTotal", vt.known === false ? `${rep.site} not in VirusTotal yet` : `${votes} of ${vt.total} vendors flag ${rep.site}`, votes >= 3 ? "bad" : votes ? "warn" : "ok");
      } else line("VirusTotal", vt.status === "unavailable" ? "no key set in CyberGuard" : (vt.reason || "not checked"), "off");
      if (uh.status === "ok") line("URLhaus", uh.listed ? `listed (${uh.urlCount} link(s), ${uh.online} online)` : "not on the malware list", uh.listed ? (uh.online ? "bad" : "warn") : "ok");
      else line("URLhaus", uh.status === "unavailable" ? "no key set in CyberGuard" : "not checked", "off");
      if (ab.status === "ok") line("AbuseIPDB", ab.isWhitelisted ? `${ab.ip}: well-known provider` : `${ab.ip}: ${ab.abuseScore}% abuse score (${ab.totalReports} reports)`, ab.abuseScore >= 75 && !ab.isWhitelisted ? "warn" : "ok");
      else line("AbuseIPDB", ab.status === "unavailable" ? "no key set in CyberGuard" : "not checked", "off");
    } else {
      const { feeds } = await api.storage.local.get("feeds");
      line("Threat lists", feeds ? "checking... (open this popup again in a moment)" : "off - switch on in Settings", "off");
    }
  }
  document.getElementById("opts").addEventListener("click", () => api.runtime.openOptionsPage());
})();
