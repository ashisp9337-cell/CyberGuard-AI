"""
Watcher 6 (6 Nov) -- every website name this PC looks up, from ANY program (Module 5: malicious URL / website).

Why this one: a browser extension only protects the browsers it is installed in. Windows keeps a list of the website
names that ANY program recently looked up (its DNS cache: every browser, WhatsApp / Telegram desktop, games, and
malware calling home). Reading that list needs no installation and no administrator rights.

ASKS FIRST: it starts OFF and runs only after the owner switches it on in Settings (that switch is the permission).

Every minute it reads the list (PowerShell Get-DnsClientCache, read-only), and judges each NEW name with the same URL
engine as a manual scan, in its no-network mode: the name is only judged by the models and rules, CyberGuard never
opens or contacts the website. A name scoring REPORT_SCORE or more becomes an automatic finding (+ the usual alert
limits). Each name is judged once a week at most.

What it can NOT see: the full link (only the website name), and names a browser looks up itself through "secure DNS"
(DNS over HTTPS) - the browser extension covers those.
"""
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from app.automation.engine import Watcher, get_state, save_and_alert, update_state

# Measured 6 Nov on real names, judged by name only (the code below):
#   normal  - 1,325 names real Windows PCs looked up (WRCCDC 2018 dns.log): 0.08% reach 86
#           - 10,000 everyday domains (OpenDNS random list): 0.22% reach 86 (about half of them are typo traps such as
#             hpotmail.com, pinterrest.com, googleanalutics.ru - a warning is fair there); 0.38% reach 71
#           - 10,000 most popular domains (OpenDNS top list): 0.40% reach 86 (companies' own extra domains such as
#             facebookmail.com, comodoca2.com - real false alarms)
#   phishing - 9,842 live phishing domains (Phishing.Database ACTIVE): 2.7% reach 86, 5.7% reach 71 - a name alone
#             gives little away (most phishing sits on random names or hosting platforms); look-alikes of brands are
#             what it catches. Full links and pages are the browser extension's job.
# Rejected with data: skipping old domains (40% of the name-flagged real phishing domains were > 1 year old) and
# skipping popular sites (no measurable change). 86 = the level automatic findings must reach to alert anyway.
REPORT_SCORE = 86
IS_WINDOWS = sys.platform == "win32"
RECHECK_DAYS = 7
MAX_PER_ROUND = 400
_LOCAL_ENDINGS = (".local", ".lan", ".home", ".internal", ".arpa", ".localdomain", ".corp", ".intranet", ".test",
                  ".invalid", ".example", ".localhost", ".home.arpa")
_PS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
       "Get-DnsClientCache | Select-Object -Property Entry,Type,Status | ConvertTo-Json -Compress"]


def read_dns_cache() -> list[str]:
    """Names in Windows' DNS cache (read-only). Raises on other systems or when PowerShell is not usable."""
    if not IS_WINDOWS:
        raise RuntimeError("Reading the list of looked-up website names works on Windows only.")
    out = subprocess.run(_PS, capture_output=True, text=True, timeout=25,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if out.returncode != 0:
        raise RuntimeError(f"PowerShell could not read the DNS cache: {(out.stderr or '').strip()[:200]}")
    return parse_cache_json(out.stdout)


def parse_cache_json(text: str) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    rows = data if isinstance(data, list) else [data]
    names = []
    for r in rows:
        name = str((r or {}).get("Entry") or "").strip().rstrip(".").lower()
        if name:
            names.append(name)
    return list(dict.fromkeys(names))


def worth_checking(name: str) -> bool:
    """Real internet names only: not local / single-label / IP addresses / reverse lookups."""
    if not name or "." not in name or len(name) > 253 or name.endswith(_LOCAL_ENDINGS):
        return False
    if name.replace(".", "").isdigit() or ":" in name:
        return False
    return all(c.isalnum() or c in "-._" for c in name)


def judge(name: str) -> dict:
    """The URL engine's verdict on a website NAME, without contacting it (models + rules only)."""
    from app.detectors import malicious_url
    return malicious_url.analyze_url(f"https://{name}/", "Website name looked up by this PC",
                                     subtopic_id="malicious-url", network=False)


class DnsWatcher(Watcher):
    name = "dns"
    title = "Websites this PC looks up (all browsers and apps)"
    what = ("Every minute: the website names any program on this PC looked up (Windows DNS cache), each new name "
            "judged by the URL models without opening the site. Covers every browser and app, even without the "
            "browser extension.")
    modules = ["url-security", "phishing"]
    technology = "Windows DNS cache (Get-DnsClientCache, read-only) + CyberGuard URL engine (no-network mode)"
    interval_seconds = 60
    default_enabled = False
    permission = ("Read the list of website NAMES that programs on this computer looked up (no full links, no page "
                  "contents) and judge them on this computer. Dangerous names are saved as findings; the rest is "
                  "only remembered for a week so it is not checked twice.")

    def configured(self) -> tuple[bool, str]:
        if not IS_WINDOWS:
            return False, "Works on Windows only (it reads Windows' list of looked-up website names)."
        return True, ""

    def check(self) -> dict:
        names = [n for n in read_dns_cache() if worth_checking(n)]
        now = datetime.now(timezone.utc)
        seen = get_state(self.name).get("seen", {})
        fresh = [n for n in names if not (seen.get(n) and now - datetime.fromisoformat(seen[n]) < timedelta(days=RECHECK_DAYS))]
        fresh = fresh[:MAX_PER_ROUND]
        threats, finding = 0, None
        for n in fresh:
            seen[n] = now.isoformat()
            result = judge(n)
            if result["riskScore"] < REPORT_SCORE:
                continue
            self.record(n, result["riskScore"], result["classification"])
            result["explanation"] = (f"A program on this computer looked up the website name {n}. "
                                     + result["explanation"])
            scan_id = save_and_alert(module_id="url-security", subtopic_id="malicious-url",
                                     subtopic_title="Automatic check of looked-up websites", result=result,
                                     target=n, target_type="url", source="dns", metadata={"name": n},
                                     min_score=REPORT_SCORE)
            if scan_id:
                threats += 1
                finding = f"{n} (score {result['riskScore']})"
        cutoff = now - timedelta(days=RECHECK_DAYS)
        seen = {k: v for k, v in seen.items() if datetime.fromisoformat(v) >= cutoff}
        if len(seen) > 20000:
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-20000:])
        update_state(self.name, seen=seen)
        return {"checked": len(fresh), "threats": threats, "finding": finding,
                "note": f"{len(names)} website name(s) in the list, {len(fresh)} new one(s) judged"}
