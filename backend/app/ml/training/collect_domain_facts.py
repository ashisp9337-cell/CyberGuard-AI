"""
Collect domain REGISTRATION facts (RDAP) for the SSL & Domain Analysis model. Run on your PC (needs internet).

Input : app/ml/training/data/domain_age_sample.csv   (4,000 phishing domains + 2,500 genuine Tranco domains, generic TLDs)
Output: app/ml/training/data/domain_facts.jsonl       (one line per domain, appended as it goes)

SAFE: it only asks the public registries (via rdap.org) about each NAME. It never opens or contacts the
phishing websites. It waits between lookups (default 1 s) so no service is overloaded or blocks you.
It can be stopped at any time with Ctrl+C and started again: domains already done are skipped.

Run from backend/ (about 2.5-3 hours, you can keep using the PC):
    python -m app.ml.training.collect_domain_facts            # all 6,500
    python -m app.ml.training.collect_domain_facts --test 10  # quick check first: 10 domains

FRESH phishing domains (the most valuable data - run once or twice a day for a few days, ~5-10 minutes each):
    python -m app.ml.training.collect_domain_facts --openphish
It downloads OpenPhish's free public feed (a TEXT LIST of phishing links reported in the last hours - the
links are never opened), keeps each link's domain and looks it up in the registry right away, while the
phishing is still live. That gives the real age of phishing domains at the time people receive them.
"""
import argparse
import csv
import json
import os
import random
import time

from app.detectors import domain_facts

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


OPENPHISH_FEED = "https://openphish.com/feed.txt"


def openphish_rows():
    """OpenPhish community feed -> one row per registrable domain (shared hosting such as *.web.app and big
    sites that only host the phishing page - e.g. docs.google.com - are skipped: their age says nothing)."""
    import urllib.request
    from datetime import date

    from app.detectors import domain_model, trusted_domains
    req = urllib.request.Request(OPENPHISH_FEED, headers={"User-Agent": domain_facts.USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        links = r.read(5_000_000).decode("utf-8", errors="replace").split()
    rows, seen = [], set()
    for link in links:
        host = link.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
        parts = domain_model.site_parts(host)
        site = parts["site"]
        if (not site or parts["ip"] or parts["platform"] or site in seen or site in trusted_domains.USER_CONTENT_DOMAINS
                or trusted_domains.is_trusted("https://" + site)):
            continue
        seen.add(site)
        rows.append({"domain": site, "label": "1", "source": f"OpenPhish feed {date.today().isoformat()} (live)"})
    print(f"OpenPhish feed: {len(links)} links -> {len(rows)} new phishing domains to look up")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=os.path.join(DATA, "domain_age_sample.csv"))
    ap.add_argument("--out", default=os.path.join(DATA, "domain_facts.jsonl"))
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between lookups")
    ap.add_argument("--test", type=int, default=0, help="only this many domains (to check it works)")
    ap.add_argument("--openphish", action="store_true", help="look up the domains of OpenPhish's live feed")
    a = ap.parse_args()

    if a.openphish:
        rows = openphish_rows()
    else:
        with open(a.input, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    random.Random(1).shuffle(rows)                     # mix phishing and genuine, so a partial run is balanced
    done = set()
    if os.path.exists(a.out):
        with open(a.out, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["domain"])
                except (ValueError, KeyError):
                    pass
    todo = [r for r in rows if r["domain"] not in done]
    if a.test:
        todo = todo[: a.test]
    print(f"{len(done)} already collected, {len(todo)} to go (about {len(todo) * (a.delay + 0.6) / 60:.0f} minutes). "
          f"Ctrl+C stops safely; run again to continue.")
    ok = fail = 0
    t0 = time.time()
    try:
        with open(a.out, "a", encoding="utf-8") as out:
            for i, r in enumerate(todo, 1):
                facts = domain_facts.lookup(r["domain"], use_cache=False)
                facts.update(label=int(r["label"]), source=r["source"])
                out.write(json.dumps(facts) + "\n")
                out.flush()
                ok += facts["ok"]
                fail += not facts["ok"]
                if a.test or i % 50 == 0:
                    print(f"  {i}/{len(todo)}  found {ok}  not found/failed {fail}  "
                          f"{(time.time() - t0) / 60:.1f} min" + (f"   {r['domain']}: created {facts.get('created')} "
                                                                  f"{facts.get('error', '')}" if a.test else ""), flush=True)
                time.sleep(a.delay)
    except KeyboardInterrupt:
        print("\nStopped. Everything collected so far is saved; run the same command to continue.")
    print(f"Done this run: {ok} found, {fail} not found/failed. File: {a.out}")


if __name__ == "__main__":
    main()
