"""
CyberGuard - live check of the Fake Login Page model on REAL websites only, from YOUR PC.

Why: phase2_live_check.py never fetches pages (so it never contacts phishing sites) - which also means the Fake Login
model, which judges a page's HTML, never runs there. This check fetches ONLY well-known real websites (read-only, the
same safe fetcher a scan uses: no JavaScript, no forms submitted, no cookies) and shows what the model says about
them. Most are NOT on CyberGuard's official-site list, so nothing caps their score: these are the pages where a false
alarm would show in a demo. No phishing site is contacted. Nothing is saved to the database. No alert is sent.

Run from backend/ with the venv active:
    python fake_login_check.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
OUT = []

REAL_SITES = [
    # not on the official-site list (the model's verdict counts here)
    "https://kiit.ac.in/", "https://www.cet.edu.in/", "https://accounts.zoho.com/signin", "https://discord.com/login",
    "https://store.steampowered.com/login/", "https://www.bookmyshow.com/", "https://www.olx.in/",
    "https://timesofindia.indiatimes.com/", "https://www.ndtv.com/", "https://leetcode.com/accounts/login/",
    "https://www.hackerrank.com/auth/login", "https://www.canva.com/login", "https://www.yatra.com/",
    "https://www.nykaa.com/", "https://www.meesho.com/", "https://www.ajio.com/", "https://unacademy.com/",
    "https://byjus.com/",
    # on the official-site list (score is capped low anyway; shown for comparison)
    "https://www.bput.ac.in/", "https://github.com/login", "https://www.naukri.com/nlogin/login",
    "https://www.flipkart.com/account/login", "https://www.netflix.com/in/login",
]


def say(s=""):
    print(s, flush=True)
    OUT.append(s)


def main():
    import math
    from app.detectors import fake_login, malicious_url, trusted_domains
    from app.detectors import login_page_features as LF
    from app.services import safe_fetch

    b = fake_login.load()
    say("=" * 110)
    say(f"CyberGuard Fake Login model - real websites check  -  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    say("=" * 110)
    if b is None:
        say("app/ml/models/fake_login.joblib is missing - train it first: python -m app.ml.training.train_fake_login")
        return
    say(f"model trained {b.get('trained_at')}, alert >= {b['thr_alert']:.3f}, verify >= {b['thr_verify']:.3f}, "
        f"alert rule {'on' if b.get('alert_needs_ask') else 'off'}\n")
    say(f"  {'site':42s} {'official?':9s} {'model':>6s}  {'level':7s} {'scan':>5s}  page (html KB / text chars / "
        f"inputs / password / links / scripts)  clues")
    counts = {"untrusted": 0, "untrusted_alert": 0, "untrusted_verify": 0, "flagged": 0, "no_page": 0, "shell": 0}
    for url in REAL_SITES:
        trusted = trusted_domains.is_trusted(url)
        try:
            res = safe_fetch.fetch(url)
        except Exception as e:                                  # a site problem is reported, never hidden
            res = {"status": "error", "html": "", "final_url": url, "reason": f"{type(e).__name__}: {e}"}
        a = fake_login.assess(res.get("html"), res.get("final_url") or url)
        try:
            score = malicious_url.analyze_url(url, "Fake Login Page", subtopic_id="fake-login-page")["riskScore"]
        except Exception as e:
            score = f"ERR {type(e).__name__}"
        page = ""
        if res.get("html"):
            v = LF.extract(res["html"], res.get("final_url") or url)
            page = (f"{len(res['html']) / 1024:.0f}/{math.expm1(v['log_text_chars']):.0f}/{v['n_inputs']:.0f}/"
                    f"{v['n_password']:.0f}/{v['n_links']:.0f}/{v['n_scripts']:.0f}")
            if a is None and fake_login.load() is not None and len(res["html"]) >= 200:
                counts["shell"] += 1
                say(f"  {url[:42]:42s} {'yes' if trusted else 'no':9s} {'-':>6s}  {'no verd':7s} {score!s:>5s}  "
                    f"{page:22s} page shows nothing to judge without JavaScript")
                continue
        if a is None:
            counts["no_page"] += 1
            say(f"  {url[:42]:42s} {'yes' if trusted else 'no':9s} {'-':>6s}  {'no page':7s} {score!s:>5s}  "
                f"({res.get('status')}: {str(res.get('reason') or '')[:50]})")
            continue
        if not trusted:
            counts["untrusted"] += 1
            counts["untrusted_alert"] += a["level"] == "high"
            counts["untrusted_verify"] += a["level"] in ("high", "medium")
        counts["flagged"] += isinstance(score, int) and score >= 51
        why = "; ".join(fake_login.reasons(a["facts"])[:2])
        say(f"  {url[:42]:42s} {'yes' if trusted else 'no':9s} {a['probability'] * 100:5.1f}%  {a['level']:7s} "
            f"{score!s:>5s}  {page:22s} {why[:60]}")
    n = counts["untrusted"]
    say(f"\nRESULT: real sites NOT on the official list with a page: {n};  model at alert: {counts['untrusted_alert']},  "
        f"at verify or alert: {counts['untrusted_verify']}")
    say(f"        full scan score >= 51 (shown as risky) on any real site: {counts['flagged']} of "
        f"{len(REAL_SITES) - counts['no_page']}   (no page fetched: {counts['no_page']}, "
        f"empty app shell - no verdict: {counts['shell']})")


if __name__ == "__main__":
    try:
        main()
    finally:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_login_check.txt"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(OUT) + "\n")
        print("\nSaved to backend\\fake_login_check.txt  -  send me that file or a screenshot.")
