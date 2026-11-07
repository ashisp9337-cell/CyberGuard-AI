const api = globalThis.browser ?? globalThis.chrome;
const q = new URLSearchParams(location.search);
const url = q.get("u") || "";
let host = "";
try { host = new URL(url).hostname; } catch { /* not a web address */ }
document.getElementById("score").textContent = q.get("s") || "?";
document.getElementById("site").textContent = url.slice(0, 300);
let reasons = [];
try { reasons = JSON.parse(q.get("r") || "[]"); } catch { reasons = []; }
const list = document.getElementById("reasons");
for (const r of (Array.isArray(reasons) ? reasons : []).slice(0, 4)) {
  const li = document.createElement("li");
  li.textContent = String(r).slice(0, 200);          // text only: never HTML from the website
  list.appendChild(li);
}
if (!list.children.length) { const li = document.createElement("li"); li.textContent = "Several warning signs together."; list.appendChild(li); }
document.getElementById("back").addEventListener("click", () => {
  if (history.length > 2) history.go(-2); else location.replace("about:blank");
});
document.getElementById("go").addEventListener("click", async () => {
  if (!/^https?:\/\//i.test(url) || !host) return;
  await api.runtime.sendMessage({ type: "continue", host });
  location.replace(url);
});
