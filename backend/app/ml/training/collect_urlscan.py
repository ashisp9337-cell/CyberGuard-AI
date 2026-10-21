"""
Collect training data for FAKE LOGIN PAGE and REDIRECT ANALYSIS from urlscan.io. Run on your PC (needs internet).

What it collects (urlscan.io already visited these pages in its own sandbox - YOUR PC NEVER OPENS THEM):
  * phishing  : recent scans of links that public phishing FEEDS reported (urlscan imports OpenPhish / PhishTank),
                scans tagged "phishing", and scans of the fresh OpenPhish domains collect_domain_facts found
                (works on the FREE plan - searching urlscan's own "malicious" verdict needs a paid plan)
  * genuine   : scans of real login pages (Google, Microsoft, PayPal, SBI, HDFC, ...) and of popular real sites
For every scan: the first URL, the final URL after redirects, the redirect type, TLS certificate facts
(issuer, validity, age), country/hosting  -> data/urlscan/scans.jsonl
For phishing + real login pages also the page HTML (urlscan's stored copy, compressed) -> data/urlscan/dom/

Needs a FREE urlscan.io API key in backend/.env:   URLSCAN_API_KEY=xxxxxxxx   (never share it)
The free key has daily limits. The script checks them, waits between requests, and stops cleanly when the
day's limit is reached - run it again the next day and it continues where it stopped.

Run from backend/:
    python -m app.ml.training.collect_urlscan --test        # 1-2 minutes: checks key + query syntax, saves a few
    python -m app.ml.training.collect_urlscan               # full run (1-3 hours, maybe over 2 days)
"""
import argparse
import gzip
import json
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OUT = os.path.join(HERE, "data", "urlscan")
API = "https://urlscan.io/api/v1"
UA = "CyberGuard-training-collector/1.0"
MAX_DOM_BYTES = 800_000

# Real login / account pages of brands that phishing copies most (and Indian banks / services)
GENUINE_LOGIN_HOSTS = [
    "accounts.google.com", "login.microsoftonline.com", "login.live.com", "outlook.live.com", "www.office.com",
    "www.paypal.com", "www.amazon.com", "www.amazon.in", "signin.aws.amazon.com", "appleid.apple.com",
    "idmsa.apple.com", "www.icloud.com", "www.facebook.com", "www.instagram.com", "www.linkedin.com", "github.com",
    "login.yahoo.com", "www.netflix.com", "www.dropbox.com", "www.docusign.net", "account.docusign.com",
    "login.salesforce.com", "auth.services.adobe.com", "zoom.us", "slack.com", "discord.com", "x.com",
    "steamcommunity.com", "store.steampowered.com", "signin.ebay.com", "www.ebay.com", "www.walmart.com",
    "www.dhl.com", "www.fedex.com", "www.ups.com", "www.usps.com", "secure.chase.com", "www.chase.com",
    "connect.secure.wellsfargo.com", "www.wellsfargo.com", "secure.bankofamerica.com", "www.bankofamerica.com",
    "www.coinbase.com", "accounts.binance.com", "www.binance.com", "www.flipkart.com", "paytm.com",
    "www.phonepe.com", "www.irctc.co.in", "eportal.incometax.gov.in", "www.onlinesbi.sbi", "retail.onlinesbi.sbi",
    "netbanking.hdfcbank.com", "now.hdfcbank.com", "infinity.icicibank.com", "www.icicibank.com",
    "omni.axisbank.co.in", "www.axisbank.com", "www.kotak.com", "netbanking.kotak.com", "www.mail.com",
    "mail.zoho.com", "accounts.zoho.com", "www.wetransfer.com", "online.citi.com", "www.hsbc.co.uk",
    "www.santander.co.uk", "www.lloydsbank.com", "www.natwest.com", "www.barclays.co.uk", "my.roblox.com",
    "www.roblox.com", "login.aol.com", "mail.yahoo.com", "www.office365.com", "portal.office.com",
]


def api_key():
    key = os.environ.get("URLSCAN_API_KEY", "").strip()
    env = os.path.join(BACKEND, ".env")
    if not key and os.path.exists(env):
        for line in open(env, encoding="utf-8", errors="ignore"):
            if line.strip().startswith("URLSCAN_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not key:
        raise SystemExit("No URLSCAN_API_KEY found. Add a line  URLSCAN_API_KEY=your_key  to backend/.env")
    return key


class Limited(Exception):
    pass


class Refused(Exception):
    """urlscan refused one search (e.g. a field the free plan cannot search) - skip that search, keep going."""


class Client:
    def __init__(self, key, delay):
        self.key, self.delay, self.last = key, delay, 0.0

    def get(self, url, raw=False):
        wait = self.delay - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.last = time.time()
        req = urllib.request.Request(url, headers={"API-Key": self.key, "User-Agent": UA})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=40) as r:
                    data = r.read(MAX_DOM_BYTES if raw else 30_000_000)
                    return data if raw else json.loads(data.decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    reset = e.headers.get("X-Rate-Limit-Reset-After") or e.headers.get("Retry-After") or "?"
                    raise Limited(f"urlscan rate limit reached (reset after {reset} s)")
                if e.code in (404, 410):
                    return None
                if e.code == 401:
                    raise SystemExit("urlscan says the API key is wrong (HTTP 401). Check URLSCAN_API_KEY in backend/.env")
                if e.code in (400, 403):
                    body = e.read(500).decode("utf-8", errors="replace")
                    try:
                        body = json.loads(body).get("message") or body
                    except ValueError:
                        pass
                    raise Refused(f"HTTP {e.code}: {body}")
                time.sleep(5 * (attempt + 1))
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                time.sleep(5 * (attempt + 1))
        return None

    def search(self, q, size=100, search_after=None):
        params = {"q": q, "size": size}
        if search_after:
            params["search_after"] = search_after
        return self.get(f"{API}/search/?{urllib.parse.urlencode(params)}")


BLOCK_TITLES = ("suspected phishing", "suspected malware", "attention required", "just a moment", "access denied",
                "403 forbidden", "404 not found", "page not found", "account suspended", "this site can")
PER_SITE = 3          # at most this many scans of one site (so one phishing kit or one host cannot dominate)


def usable(s):
    """Only pages that really loaded: not error pages, not Cloudflare / host warning or block pages."""
    title = (s.get("title") or "").strip().lower()
    return (str(s.get("status")) == "200" and not any(title.startswith(t) for t in BLOCK_TITLES)
            and not title.startswith(("404", "403", "500", "502", "503")) and "not found" not in title)


def site_of(host):
    from app.detectors import domain_model
    try:
        return domain_model.site_parts(host or "")["site"] or (host or "")
    except Exception:
        return host or ""


def compact(item, label, group, how=""):
    task, page = item.get("task") or {}, item.get("page") or {}
    return {"uuid": item.get("_id") or task.get("uuid"), "label": label, "group": group,
            "time": task.get("time"), "task_url": task.get("url"), "task_domain": task.get("domain"),
            "page_url": page.get("url"), "page_domain": page.get("domain"), "apex": page.get("apexDomain"),
            "redirected": page.get("redirected"), "status": page.get("status"), "mime": page.get("mimeType"),
            "title": page.get("title"), "tls_issuer": page.get("tlsIssuer"), "tls_valid_days": page.get("tlsValidDays"),
            "tls_age_days": page.get("tlsAgeDays"), "country": page.get("country"), "asnname": page.get("asnname"),
            "server": page.get("server"), "ip": page.get("ip"),
            "source": task.get("source"), "tags": task.get("tags"), "found_by": how,
            "verdict_malicious": (item.get("verdicts") or {}).get("malicious")}


def add_flags(s):
    """cloaked      : a reported phishing link whose final page is a REAL trusted site (kit hides from scanners) -
                      useful for redirect analysis, never used as a 'fake page' example.
       came_from_other_site: a real login page that was reached from a different site (maybe a phishing redirect) -
                      fine as a real login page, not used as a 'safe redirect' example."""
    from app.detectors import trusted_domains
    final_trusted = bool(s["page_url"]) and trusted_domains.is_trusted(s["page_url"])
    s["final_trusted"] = final_trusted
    s["cloaked"] = s["label"] == 1 and final_trusted
    s["came_from_other_site"] = site_of(s.get("task_domain")) != site_of(s.get("page_domain"))
    return s


def tranco_sample(n, seed=7):
    import zipfile
    data = os.path.join(HERE, "data")
    z = [f for f in os.listdir(data) if f.startswith("tranco") and f.endswith(".zip")]
    if not z:
        return []
    with zipfile.ZipFile(os.path.join(data, z[0])) as zf:
        rows = [ln.decode().strip().split(",") for ln in zf.open(zf.namelist()[0])]
    doms = [d for r, d in rows if d and int(r) <= 50_000]
    return random.Random(seed).sample(doms, min(n, len(doms)))


# Phishing searches the FREE plan allows. The label comes from the feed that reported the link, not from urlscan.
PHISH_SEARCHES = [
    ("OpenPhish feed", "task.source:openphish AND date:>now-120d"),
    ("PhishTank feed", "task.source:phishtank AND date:>now-120d"),
    ("tagged phishing", "task.tags:phishing AND date:>now-120d"),
]


def fresh_phish_domains():
    """Fresh phishing domains that collect_domain_facts --openphish found (registered < 1 year ago, not taken down)."""
    path = os.path.join(HERE, "data", "domain_facts.jsonl")
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        st = " ".join(r.get("status") or [])
        if ("OpenPhish" in (r.get("source") or "") and r.get("ok") and r.get("domain") not in out
                and not any(t in st for t in ("hold", "redemption", "pending delete"))):
            out.append(r["domain"])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true", help="tiny run to check the key and queries")
    ap.add_argument("--phish", type=int, default=3000)
    ap.add_argument("--login-per-host", type=int, default=40)
    ap.add_argument("--web", type=int, default=2000)
    ap.add_argument("--delay", type=float, default=2.5, help="seconds between requests")
    ap.add_argument("--no-dom", action="store_true")
    ap.add_argument("--dom-only", action="store_true", help="no new searches: only download missing page copies")
    ap.add_argument("--web-dom", type=int, default=0,
                    help="also download page copies of this many ordinary real websites (Fake Login model negatives)")
    a = ap.parse_args()
    if a.dom_only:
        a.phish = 0                            # no phishing searches either
    if a.test:
        a.login_per_host, a.web = 2, 5
    os.makedirs(os.path.join(OUT, "dom"), exist_ok=True)
    scans_path = os.path.join(OUT, "scans.jsonl")
    seen = {}
    if os.path.exists(scans_path):
        old_rows = 0
        for line in open(scans_path, encoding="utf-8"):
            try:
                s = json.loads(line)
            except ValueError:
                continue
            if "cloaked" not in s:            # saved by the first version (no quality filter) - collect again
                old_rows += 1
                continue
            seen[s["uuid"]] = s
        if old_rows:
            with open(scans_path, "w", encoding="utf-8") as f:
                for s in seen.values():
                    f.write(json.dumps(s) + "\n")
            print(f"removed {old_rows} scans saved before the quality filter (they will be collected again, checked)")
    c = Client(api_key(), a.delay)
    q = c.get(f"{API}/quotas/")
    if q:
        lim = (q.get("limits") or {})
        print("Your urlscan limits:", json.dumps({k: lim.get(k) for k in ("search", "retrieve") if k in lim})[:600])
    counts = {g: sum(1 for s in seen.values() if s["group"] == g) for g in ("phish", "genuine-login", "genuine-web")}
    print("already collected:", counts)
    out = open(scans_path, "a", encoding="utf-8")

    per_site = {}
    for old in seen.values():
        k = (old["group"], site_of(old.get("page_domain")))
        per_site[k] = per_site.get(k, 0) + 1
    skipped = {"not loaded / warning page": 0, "same site already 3 times": 0}

    def keep(item, label, group, how=""):
        s = compact(item, label, group, how)
        if not s["uuid"] or s["uuid"] in seen or not s["page_url"]:
            return False
        if not usable(s):
            skipped["not loaded / warning page"] += 1
            return False
        k = (group, site_of(s.get("page_domain")))
        if group != "genuine-login" and per_site.get(k, 0) >= PER_SITE:
            skipped["same site already 3 times"] += 1
            return False
        per_site[k] = per_site.get(k, 0) + 1
        add_flags(s)
        seen[s["uuid"]] = s
        out.write(json.dumps(s) + "\n")
        out.flush()
        counts[group] += 1
        return True

    try:
        # 1. phishing scans (reported by public phishing feeds / fresh OpenPhish domains)
        for name, query in PHISH_SEARCHES:
            after, tries = None, 0
            cap = counts["phish"] + 3 if a.test else a.phish          # --test: try every search, keep 3 of each
            while counts["phish"] < cap and tries < 60:
                tries += 1
                try:
                    r = c.search(query, size=100, search_after=after)
                except Refused as e:
                    print(f"  {name}: not available on your plan ({e}) - skipped")
                    break
                res = (r or {}).get("results") or []
                if tries == 1:
                    print(f"  {name}: urlscan has {(r or {}).get('total', 0)} scans")
                if not res:
                    break
                for it in res:
                    if counts["phish"] < cap:
                        keep(it, 1, "phish", name)
                after = ",".join(str(x) for x in (res[-1].get("sort") or [])) or None
                print(f"  phishing scans: {counts['phish']}", flush=True)
                if a.test or not after or not r.get("has_more", True):
                    break
        doms = fresh_phish_domains()
        cap = counts["phish"] + 3 if a.test else a.phish
        if a.test:
            doms = doms[:40]
        for i in range(0, len(doms), 40):
            if counts["phish"] >= cap:
                break
            batch = " OR ".join(f'"{d}"' for d in doms[i:i + 40])
            try:
                r = c.search(f"page.apexDomain:({batch}) AND date:>now-60d", size=100)
            except Refused as e:
                print(f"  fresh OpenPhish domains: refused ({e}) - skipped")
                break
            if i == 0:
                print(f"  fresh OpenPhish domains: urlscan has {(r or {}).get('total', 0)} scans of the first {len(doms[:40])}")
            for it in (r or {}).get("results") or []:
                if counts["phish"] < cap:
                    keep(it, 1, "phish", "fresh OpenPhish domain")
            print(f"  phishing scans: {counts['phish']}  (fresh OpenPhish domains {min(i + 40, len(doms))}/{len(doms)})",
                  flush=True)
        # 2. real login / account pages
        for host in ([] if a.dom_only else GENUINE_LOGIN_HOSTS):
            try:
                r = c.search(f'page.domain:"{host}"', size=a.login_per_host)
            except Refused as e:
                print(f"  real login pages: refused ({e}) - skipped")
                break
            for it in (r or {}).get("results") or []:
                keep(it, 0, "genuine-login", host)
            print(f"  real login pages: {counts['genuine-login']}  ({host})", flush=True)
            if a.test and counts["genuine-login"] >= 4:
                break
        # 3. ordinary real websites (popular sites, batches of 40 per search)
        doms = [] if a.dom_only else tranco_sample(max(a.web, 40))
        for i in range(0, len(doms), 20):
            if counts["genuine-web"] >= a.web:
                break
            batch = " OR ".join(f'"{d}" OR "www.{d}"' for d in doms[i:i + 20])
            try:
                r = c.search(f"page.domain:({batch})", size=100)
            except Refused as e:
                print(f"  real websites: refused ({e}) - skipped")
                break
            for it in (r or {}).get("results") or []:
                if counts["genuine-web"] < a.web:
                    keep(it, 0, "genuine-web", "Tranco top 50k homepage")
            print(f"  real websites: {counts['genuine-web']}", flush=True)
        # 4. page HTML (urlscan's stored copy) for phishing + real login pages
        if not a.no_dom:
            def missing(s):
                return (not os.path.exists(os.path.join(OUT, "dom", s["uuid"] + ".html.gz"))
                        and not os.path.exists(os.path.join(OUT, "dom", s["uuid"] + ".none")))
            need = [s for s in seen.values() if s["group"] in ("phish", "genuine-login") and not s.get("cloaked") and missing(s)]
            if a.web_dom:                     # ordinary websites: a fixed random pick, so a re-run continues the same pick
                import random
                web = sorted((s for s in seen.values() if s["group"] == "genuine-web"), key=lambda s: s["uuid"])
                pick = random.Random(7).sample(web, min(a.web_dom, len(web)))
                need += [s for s in pick if missing(s)]
            print(f"downloading stored page HTML for {len(need)} scans ...")
            for i, s in enumerate(need, 1):
                try:
                    html = c.get(f"https://urlscan.io/dom/{s['uuid']}/", raw=True)
                except Refused as e:
                    print(f"  page HTML: refused ({e}) - stopping HTML downloads")
                    break
                path = os.path.join(OUT, "dom", s["uuid"])
                if html and html[:2] == b"\x1f\x8b":            # urlscan sends it compressed: store plain HTML
                    try:
                        import zlib
                        html = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(html)
                    except Exception:
                        pass
                if html:
                    with gzip.open(path + ".html.gz", "wb") as f:
                        f.write(html)
                else:
                    open(path + ".none", "w").close()
                if i % 50 == 0 or a.test:
                    print(f"  page HTML {i}/{len(need)}", flush=True)
    except Limited as e:
        print(f"\n{e}. Everything so far is saved - run the same command again later (or tomorrow) to continue.")
    except KeyboardInterrupt:
        print("\nStopped. Everything so far is saved; run the same command to continue.")
    out.close()
    doms = len([f for f in os.listdir(os.path.join(OUT, "dom")) if f.endswith(".html.gz")])
    print(f"Skipped (not saved): {skipped}")
    print(f"Collected: {counts}, page HTML files: {doms}.  Folder: {OUT}")


if __name__ == "__main__":
    main()
