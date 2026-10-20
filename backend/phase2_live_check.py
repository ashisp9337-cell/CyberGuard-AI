"""
CyberGuard Phase 2 - live check of every EXTERNAL service + online URL checks, from YOUR PC. READ-ONLY.

Run from backend/ with the venv active (a second terminal is fine; it does not disturb other running jobs):
    python phase2_live_check.py

What it does (and does NOT do):
  * prints which keys are set in backend/.env -- NAMES only, never the values
  * DNS, WHOIS, registry (RDAP) and SSL lookups for well-known real sites
  * VirusTotal / AbuseIPDB / URLhaus: one lookup each if a key is set (else "needs API key")
  * Gemini: one tiny question if GEMINI_API_KEY is set
  * Telegram: getMe only (checks the bot token; NO message is sent)
  * SMTP: connect + login + quit (NO email is sent);  IMAP: login + open INBOX read-only + logout
  * urlscan.io: reads your quota only (no search is used up);  OpenPhish: downloads the public feed text
  * the online URL checks (DNS + WHOIS + registry) for the 30 Phase-2 test URLs. Phishing sites are NEVER
    contacted: for them only DNS / WHOIS / registry servers are asked, page fetching and SSL are switched off.
  * the CyberGuard database: connection + migration version
Nothing is written to the database and nothing is changed. Output also saved to phase2_live_check.txt.
"""
import imaplib
import json
import os
import smtplib
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
OUT = []


def say(line=""):
    print(line, flush=True)
    OUT.append(line)


def timed(fn):
    t = time.perf_counter()
    try:
        res = fn()
        return res, round((time.perf_counter() - t) * 1000), None
    except Exception as e:  # noqa: BLE001
        return None, round((time.perf_counter() - t) * 1000), f"{type(e).__name__}: {str(e)[:160]}"


def row(name, status, ms, note=""):
    say(f"  {name:34s} {status:16s} {str(ms) + ' ms' if ms is not None else '':>9s}  {note}")


from app.core.config import get_settings  # noqa: E402

s = get_settings()
say("=" * 100)
say("CyberGuard Phase 2 live check  -  " + time.strftime("%Y-%m-%d %H:%M:%S"))
say("=" * 100)
say("\n1. Keys set in backend/.env (names only)")
keys = ["DATABASE_URL", "JWT_SECRET", "GEMINI_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "URLHAUS_API_KEY",
        "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_USER", "SMTP_PASSWORD", "IMAP_USER", "IMAP_PASSWORD",
        "GOOGLE_CLIENT_ID", "TURNSTILE_SECRET_KEY", "URLSCAN_API_KEY", "CALLMEBOT_APIKEY", "TWILIO_ACCOUNT_SID"]
env = {}
envfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(envfile):
    for line in open(envfile, encoding="utf-8", errors="ignore"):
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.split("#")[0].strip().strip('"').strip("'")
for k in keys:
    val = getattr(s, k, None) if hasattr(s, k) else env.get(k, "")
    say(f"  {k:24s} {'set' if val else 'EMPTY'}")

say("\n2. Database")
from sqlalchemy import text  # noqa: E402
from app.db.database import engine  # noqa: E402


def db():
    with engine.connect() as c:
        v = c.execute(text("select version_num from alembic_version")).scalar()
        n = c.execute(text("select count(*) from scans")).scalar()
        return v, n


r, ms, err = timed(db)
row("PostgreSQL", "works" if r else "FAILS", ms, f"migration {r[0]}, {r[1]} scans" if r else err)

say("\n3. Network intelligence (well-known real sites)")
from app.services import network_intel, threat_intelligence  # noqa: E402
from app.detectors import domain_facts  # noqa: E402
for name, fn in [("DNS  (www.google.com)", lambda: network_intel.resolve_domain("www.google.com")),
                 ("WHOIS (google.com)", lambda: network_intel.get_domain_age("google.com")),
                 ("SSL  (www.google.com)", lambda: network_intel.get_ssl_info("www.google.com")),
                 ("RDAP registry (google.com)", lambda: domain_facts.lookup("google.com", use_cache=False))]:
    r, ms, err = timed(fn)
    ok = bool(r) and (r.get("status") in ("ok", "resolved") or r.get("ok") is True)
    row(name, "works" if ok else "FAILS", ms, err or json.dumps(r, default=str)[:90])

say("\n4. Threat-intelligence APIs")
for name, key, fn in [("VirusTotal", s.VIRUSTOTAL_API_KEY, lambda: threat_intelligence.check_virustotal_url_sync("https://www.google.com/")),
                      ("URLhaus", s.URLHAUS_API_KEY, lambda: threat_intelligence.check_urlhaus_sync("https://www.google.com/"))]:
    if not key:
        row(name, "needs API key", None, f"add {name.upper()}_API_KEY to backend/.env to enable")
        continue
    r, ms, err = timed(fn)
    row(name, "works" if r and r.get("status") not in ("error", "unavailable") else "FAILS", ms, err or json.dumps(r)[:90])
if not s.ABUSEIPDB_API_KEY:
    row("AbuseIPDB", "needs API key", None, "add ABUSEIPDB_API_KEY to backend/.env to enable")
else:
    import asyncio
    fn = getattr(threat_intelligence, "check_abuseipdb", None)
    if fn:
        r, ms, err = timed(lambda: asyncio.run(fn("8.8.8.8")))
        row("AbuseIPDB", "works" if r and r.get("status") != "error" else "FAILS", ms, err or json.dumps(r)[:90])

say("\n5. Other external services")
if s.GEMINI_API_KEY:
    def gem():
        from google import genai
        return genai.Client(api_key=s.GEMINI_API_KEY).models.generate_content(model=s.GEMINI_MODEL, contents="Reply with the word OK").text
    r, ms, err = timed(gem)
    row("Gemini (chat assistant)", "works" if r else "FAILS", ms, err or (r or "")[:40])
else:
    row("Gemini (chat assistant)", "needs API key", None)
if s.TELEGRAM_BOT_TOKEN:
    import requests
    r, ms, err = timed(lambda: requests.get(f"https://api.telegram.org/bot{s.TELEGRAM_BOT_TOKEN}/getMe", timeout=10).json())
    row("Telegram bot (getMe, no message)", "works" if r and r.get("ok") else "FAILS", ms, err or ("bot @" + str((r or {}).get("result", {}).get("username"))))
else:
    row("Telegram bot", "not configured", None)
if s.SMTP_HOST and s.SMTP_USER:
    def smtp():
        pw = s.SMTP_PASSWORD.replace(" ", "")
        if int(s.SMTP_PORT) == 465:
            c = smtplib.SMTP_SSL(s.SMTP_HOST, 465, timeout=15, context=ssl.create_default_context())
        else:
            c = smtplib.SMTP(s.SMTP_HOST, int(s.SMTP_PORT), timeout=15); c.starttls(context=ssl.create_default_context())
        c.login(s.SMTP_USER, pw); c.quit(); return True
    r, ms, err = timed(smtp)
    row("SMTP email alerts (login only)", "works" if r else "FAILS", ms, err or "login ok, nothing sent")
else:
    row("SMTP email alerts", "not configured", None)
if (s.IMAP_USER or s.SMTP_USER) and (s.IMAP_PASSWORD or s.SMTP_PASSWORD):
    def imap():
        c = imaplib.IMAP4_SSL(s.IMAP_HOST, 993, timeout=20)
        c.login((s.IMAP_USER or s.SMTP_USER).strip(), (s.IMAP_PASSWORD or s.SMTP_PASSWORD).replace(" ", ""))
        typ, data = c.select('"INBOX"', readonly=True); c.logout(); return typ
    r, ms, err = timed(imap)
    row("Gmail IMAP (read-only)", "works" if r == "OK" else "FAILS", ms, err or "INBOX opened read-only")
else:
    row("Gmail IMAP", "not configured", None)
ukey = env.get("URLSCAN_API_KEY", "")
if ukey:
    import requests
    r, ms, err = timed(lambda: requests.get("https://urlscan.io/api/v1/quotas/", headers={"API-Key": ukey}, timeout=15))
    row("urlscan.io (quota only)", "works" if r is not None and r.status_code == 200 else "FAILS", ms, err or f"HTTP {r.status_code}")
else:
    row("urlscan.io", "needs API key", None)
import requests  # noqa: E402
r, ms, err = timed(lambda: requests.get("https://openphish.com/feed.txt", timeout=20))
row("OpenPhish feed", "works" if r is not None and r.status_code == 200 else "FAILS", ms,
    err or f"{len(r.text.split())} links in the feed")
row("Google sign-in", "configured" if s.GOOGLE_CLIENT_ID else "not configured", None)
row("Cloudflare Turnstile captcha", "configured" if s.TURNSTILE_SECRET_KEY else "not configured", None)

say("\n6. Online URL checks for the 30 Phase-2 URLs (DNS + WHOIS + registry only; phishing sites never contacted)")
from app.detectors import malicious_url  # noqa: E402
s.LIVE_PAGE_CHECKS = False                                       # never fetch pages
network_intel.get_ssl_info = lambda d: {"status": "skipped"}     # never connect to the sites themselves
TESTS = {
    "malicious-url": (["https://tvlicensing-en.cek123.co/?_tk=354", "https://maxis-org.shop/max", "http://support-paypul.top/",
                       "http://find-mylphone.top/", "https://imtouken.com/"],
                      ["https://www.onlinesbi.sbi/", "https://accounts.google.com/signin", "https://www.amazon.in/gp/your-account",
                       "https://www.irctc.co.in/nget/train-search", "https://github.com/login"]),
    "ssl-domain-analysis": (["http://cerropai.click/", "http://webuluxp.com/", "http://tiktokvip.cyou/", "http://vdann.web.id/",
                             "http://tokemix-cdn07-hk07.club/"],
                            ["https://www.sbi.co.in/", "https://www.icicibank.com/", "https://www.google.com/",
                             "https://www.microsoft.com/", "https://www.bput.ac.in/"]),
    "fake-login-page": (["https://tvlicensing-en.cek123.co/?_tk=354", "http://frinvoiceadsmanager.vercel.app/",
                         "https://sbi-netbanking-login.top/retail/login", "https://microsoft365-login-verify.cyou/owa",
                         "https://instagram-help-center.click/login"],
                        ["https://accounts.google.com/signin", "https://login.microsoftonline.com/",
                         "https://www.instagram.com/accounts/login/", "https://retail.onlinesbi.sbi/retail/login.htm",
                         "https://github.com/login"]),
}
for sub, (bad, good) in TESTS.items():
    caught = ok = 0
    times = []
    for label, urls in (("phishing", bad), ("real", good)):
        for u in urls:
            r, ms, err = timed(lambda: malicious_url.analyze_url(u, sub, subtopic_id=sub))
            times.append(ms)
            score = r["riskScore"] if r else None
            hit = score is not None and score >= 51
            caught += label == "phishing" and hit
            ok += label == "real" and not hit
            age = next((i["description"] for i in (r or {}).get("indicators", []) if "registr" in i["label"].lower()), "")
            say(f"    {sub:20s} {label:8s} score {score!s:>4}  {ms:5d} ms  {u[:48]:48s} {age[:60]}")
    say(f"  -> {sub}: phishing caught {caught}/5, real sites correct {ok}/5, median {sorted(times)[len(times) // 2]} ms")

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase2_live_check.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(OUT))
say("\nSaved to backend\\phase2_live_check.txt  -  send me that file or a screenshot.")
