r"""Insider-risk training, step 2: turn the CERT r4.2 archive into one small table (one row per user per day).

Reads data\insider\r4.2.tar.bz2 and answers.tar.bz2 as a STREAM (nothing is unpacked to disk; nothing in them is run)
and writes, in the same git-ignored folder:
  * insider_userdays.csv.gz  - per user and day: logons (after hours / weekend / first-last time / PCs used), USB
                               connects, file copies (by type), e-mails (external / personal webmail / attachments /
                               size), web visits to job, file-sharing, leak and spyware sites (the rules live in
                               app\detectors\insider_signals.py and are shared with the live detector)
  * insider_users.csv        - each user's role / department / team (from the LDAP files)
  * insider_labels.csv       - the answer key: the 70 r4.2 insiders, their scenario and the exact malicious days
  * insider_domains.csv.gz   - every web domain and how many users / visits (to check the site categories)
  * insider_rareweb.csv.gz   - visits (user, day, domain) to RARE sites - used by at most 10% of the staff
  * insider_summary.txt      - what was read (files, columns, rows)
Left out on purpose: the total number of web requests (a known flaw of this simulator gives the insiders away) and all
page / e-mail TEXT. Memory stays small: lines are read one at a time. Run from the backend folder (35-60 minutes):
    python -I app\ml\training\prepare_insider_data.py
"""
import bz2
import csv
import gzip
import io
import os
import re
import sys
import tarfile
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))   # the backend folder (python -I ignores cwd)
from app.detectors import insider_signals as S
DIR = os.path.join(HERE, "data", "insider")
ARCHIVE = os.path.join(DIR, "r4.2.tar.bz2")
ANSWERS = os.path.join(DIR, "answers.tar.bz2")
DATASET = "4.2"

FEATURES = S.FEATURES
RARE_CAP = 100          # a domain stops being "rare" once more than this many users visited it (10% of 1,000)


def stream_members(path):
    """(member name, text line iterator) for each CSV in a .tar.bz2, read sequentially (no unpacking)."""
    # bz2.open, not tarfile's "r|bz2": CERT's archives are multi-stream bzip2 (parallel-compressed), and tarfile's
    # streaming reader stops after the first stream ("End of stream already reached"); BZ2File reads them all.
    with bz2.open(path, "rb") as zf, tarfile.open(fileobj=zf, mode="r|") as tar:
        for m in tar:
            if not m.isfile() or not m.name.lower().endswith(".csv"):
                continue
            f = tar.extractfile(m)
            raw = io.BufferedReader(_Sequential(f), 1 << 20)
            yield m.name, io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")


class _Sequential(io.RawIOBase):
    """Forward-only view of a streamed tar member (TextIOWrapper asks 'seekable?', which the stream can't answer)."""

    def __init__(self, f):
        self.f = f

    def readable(self):
        return True

    def seekable(self):
        return False

    def readinto(self, b):
        data = self.f.read(len(b))
        b[:len(data)] = data
        return len(data)


def main():
    for p in (ARCHIVE, ANSWERS):
        if not os.path.exists(p):
            sys.exit(f"{p} is missing - run download_insider_data.py first.")
    t0 = time.time()
    day = defaultdict(S.new_day)                             # (user, date) -> feature -> value
    pcs = defaultdict(set)                                   # (user, date) -> PCs used
    users, domains, dom_users = {}, Counter(), defaultdict(set)
    sender_domains = Counter()
    rcpt_domains = defaultdict(Counter)                     # (user, date) -> recipient domain -> count (small)
    rare = defaultdict(Counter)                             # domain -> (user, date) -> visits, while still rare
    summary = []

    for name, lines in stream_members(ARCHIVE):
        base = os.path.basename(name).lower()
        ts = time.time()
        if "/ldap/" in name.lower().replace("\\", "/"):
            r = csv.DictReader(lines)
            for row in r:
                uid = (row.get("user_id") or "").strip()
                if uid:
                    users[uid] = {k: (row.get(k) or "").strip() for k in ("role", "business_unit", "functional_unit",
                                                                            "department", "team")}
            continue
        if base == "psychometric.csv":
            summary.append(f"{name}: skipped (personality scores are not activity logs)")
            continue
        header = next(csv.reader([lines.readline()]), [])
        n = 0
        if base == "logon.csv":                              # id,date,user,pc,activity
            for row in csv.reader(lines):
                if len(row) < 5:
                    continue
                t = S.parse_time(row[1])
                if t is None:
                    continue
                key = (row[2], t.date().isoformat())
                pcs[key].add(row[3])
                S.add_logon(day[key], t, row[4])
                n += 1
        elif base == "device.csv":                           # id,date,user,pc,activity (Connect/Disconnect)
            for row in csv.reader(lines):
                if len(row) < 5:
                    continue
                t = S.parse_time(row[1])
                if t is None:
                    continue
                key = (row[2], t.date().isoformat())
                if S.add_usb(day[key], t, row[4]):
                    pcs[key].add(row[3])
                    n += 1
        elif base == "file.csv":                             # id,date,user,pc,filename,content
            for line in lines:
                parts = line.split(",", 5)
                if len(parts) < 5:
                    continue
                t = S.parse_time(parts[1])
                if t is None:
                    continue
                key = (parts[2], t.date().isoformat())
                S.add_file(day[key], t, parts[4])
                n += 1
        elif base == "email.csv":                            # id,date,user,pc,to,cc,bcc,from,size,attachments,content
            idx = {h.strip().lower(): i for i, h in enumerate(header)}
            need = [idx.get(k) for k in ("date", "user", "to", "cc", "bcc", "from", "size", "attachments")]
            if None in need:
                summary.append(f"{name}: unexpected columns {header} - skipped")
                continue
            di, ui, toi, cci, bcci, fri, szi, ati = need
            for row in csv.reader(lines):
                if len(row) <= max(need):
                    continue
                t = S.parse_time(row[di])
                if t is None:
                    continue
                key = (row[ui], t.date().isoformat())
                rcpt = S.split_recipients(row[toi], row[cci], row[bcci])
                sender = row[fri].strip().lower()
                if "@" in sender:
                    sender_domains[sender.rsplit("@", 1)[1]] += 1
                rcpt_domains[key].update(r.rsplit("@", 1)[1] for r in rcpt)
                S.add_email(day[key], t, rcpt, row[szi], row[ati])
                n += 1
        elif base == "http.csv":                             # id,date,user,pc,url,content (content can be very long)
            for line in lines:
                parts = line.split(",", 5)
                if len(parts) < 5:
                    continue
                t = S.parse_time(parts[1])
                if t is None:
                    continue
                dom = S.domain_of(parts[4])
                domains[dom] += 1
                if len(dom_users[dom]) <= RARE_CAP:
                    dom_users[dom].add(parts[2])
                key = (parts[2], t.date().isoformat())
                if len(dom_users[dom]) <= RARE_CAP:
                    rare[dom][key] += 1
                elif dom in rare:
                    del rare[dom]                            # popular now - stop keeping its visits
                S.add_web(day[key], t, dom)
                n += 1
                if n % 5_000_000 == 0:
                    print(f"  {name}: {n:,} lines ({time.time() - t0:.0f}s)", flush=True)
        else:
            summary.append(f"{name}: not used")
            continue
        summary.append(f"{name}: {n:,} rows, columns {header}")
        print(f"{name}: {n:,} rows ({time.time() - ts:.0f}s, total {time.time() - t0:.0f}s)", flush=True)

    company = sender_domains.most_common(1)[0][0] if sender_domains else ""
    for key, rc in rcpt_domains.items():                    # recipients outside the company's own e-mail domain
        day[key]["email_ext"] = float(sum(c for dom, c in rc.items() if dom != company))

    # answer key: insiders.csv (dataset, scenario, details, user, start, end) + one detail file per insider
    labels, malicious = {}, defaultdict(set)
    detail_files = {}
    for name, lines in stream_members(ANSWERS):
        base = os.path.basename(name)
        if base.lower() == "insiders.csv":
            for row in csv.DictReader(lines):
                if str(row.get("dataset", "")).strip() in (DATASET, "4.20"):
                    labels[row["user"].strip()] = {"scenario": row.get("scenario", "").strip(),
                                                   "start": row.get("start", "").strip(), "end": row.get("end", "").strip(),
                                                   "details": row.get("details", "").strip()}
        elif "r4.2" in name:
            detail_files[base] = [ln for ln in lines]
    for user, lab in labels.items():
        rows = detail_files.get(lab["details"]) or []
        for ln in rows:
            t = S.parse_time((re.search(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}", ln) or [""])[0])
            if t and user in ln:
                malicious[user].add(t.date().isoformat())
    if not labels:
        sys.exit("No r4.2 insiders found in answers.tar.bz2 - tell Claude what insider_summary.txt shows.")

    os.makedirs(DIR, exist_ok=True)
    with gzip.open(os.path.join(DIR, "insider_userdays.csv.gz"), "wt", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["user", "date", "pcs"] + FEATURES)
        for (u, dt) in sorted(day):
            d = day[(u, dt)]
            w.writerow([u, dt, ";".join(sorted(pcs.get((u, dt), ())))] + [round(d.get(k, 0.0), 2) for k in FEATURES])
    with open(os.path.join(DIR, "insider_users.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["user", "role", "business_unit", "functional_unit", "department", "team"])
        for u, info in sorted(users.items()):
            w.writerow([u] + [info[k] for k in ("role", "business_unit", "functional_unit", "department", "team")])
    with open(os.path.join(DIR, "insider_labels.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["user", "scenario", "start", "end", "malicious_days"])
        for u, lab in sorted(labels.items()):
            w.writerow([u, lab["scenario"], lab["start"], lab["end"], ";".join(sorted(malicious[u]))])
    with gzip.open(os.path.join(DIR, "insider_domains.csv.gz"), "wt", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "visits", "users", "category"])
        for dom, c in domains.most_common():
            users_n = len(dom_users[dom])
            w.writerow([dom, c, users_n if users_n <= RARE_CAP else f">{RARE_CAP}", S.site_category(dom)])
    cap = max(1, int(0.10 * max(len(users), 1)))           # rare = used by at most 10% of the staff
    n_rare = 0
    with gzip.open(os.path.join(DIR, "insider_rareweb.csv.gz"), "wt", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["user", "date", "domain", "visits"])
        for dom in sorted(rare):
            if len(dom_users[dom]) <= cap:
                n_rare += 1
                for (u, dt), c in sorted(rare[dom].items()):
                    w.writerow([u, dt, dom, c])
    lines = summary + [f"company e-mail domain: {company}", f"users with LDAP info: {len(users)}",
                       f"user-days: {len(day):,}", (f"insiders (r4.2): {len(labels)}, with malicious days: "
                                                    f"{sum(1 for u in labels if malicious[u])}"),
                       "scenarios: " + str(Counter(l['scenario'] for l in labels.values())),
                       f"domains: {len(domains):,}; categorised: "
                       + str(Counter(c for c in map(S.site_category, domains) if c)),
                       f"rare domains (used by at most {cap} users): {n_rare}"]
    with open(os.path.join(DIR, "insider_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    for fn in ("insider_userdays.csv.gz", "insider_users.csv", "insider_labels.csv", "insider_domains.csv.gz",
               "insider_rareweb.csv.gz"):
        print(f"wrote {fn} ({os.path.getsize(os.path.join(DIR, fn)) / 1e6:.1f} MB)")
    print(f"done in {(time.time() - t0) / 60:.0f} min")


if __name__ == "__main__":
    main()
