r"""Insider-risk demo files: REAL CERT r4.2 activity, written as the activity-log format the app reads.

Run once after prepare_insider_data.py (it reads the archive again: about 35-45 minutes):
    python -I app\ml\training\make_insider_demo.py
Writes into data\insider\demo\ (git-ignored):
  * insider_demo_leak.csv      - a scenario-1 insider (night-time USB + leak site) and 19 colleagues with the same role
  * insider_demo_jobtheft.csv  - a scenario-2 insider (job hunting, then data theft) and 19 colleagues
  * insider_demo_spyware.csv   - a scenario-3 insider (keylogger, other people's PCs) and 19 colleagues
  * insider_demo_normal.csv    - 20 people with no insider at all (the control: it should stay quiet)
  * insider_demo_answers.txt   - who the insider is in each file and on which days (do not show it before the scan)
Each file covers 35 days before the insider's first malicious day to 3 days after the last one. People are chosen
by a fixed rule (first by user id), never by how the detector scores them. Web page text and e-mail text are left out
(the detector never reads them).
Columns: date,user,pc,activity,details,to,cc,bcc,from,size,attachments  (activity = logon / logoff / usb_connect /
usb_disconnect / file_copy / email / web)
"""
import csv
import os
import sys
from datetime import date, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))   # the backend folder (python -I ignores cwd)
sys.path.insert(0, HERE)

import prepare_insider_data as P  # noqa: E402

from app.detectors import insider_signals as S  # noqa: E402

DIR = P.DIR
OUT = os.path.join(DIR, "demo")
PEOPLE = 20
BEFORE, AFTER = 35, 3
HEADER = ["date", "user", "pc", "activity", "details", "to", "cc", "bcc", "from", "size", "attachments"]


def cases():
    """{name: (insider or None, set of users, first day, last day)} chosen by a fixed rule from the prepared files."""
    labels, roles = {}, {}
    with open(os.path.join(DIR, "insider_labels.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            labels[r["user"]] = (r["scenario"], sorted(r["malicious_days"].split(";")))
    with open(os.path.join(DIR, "insider_users.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            roles[r["user"]] = r["role"]
    out = {}
    for name, sc in (("leak", "1"), ("jobtheft", "2"), ("spyware", "3")):
        for u in sorted(u for u, (s, _) in labels.items() if s == sc):
            peers = sorted(p for p in roles if roles[p] == roles.get(u) and p != u and p not in labels)
            if len(peers) >= PEOPLE - 1:
                days = labels[u][1]
                first = date.fromisoformat(days[0]) - timedelta(days=BEFORE)
                last = date.fromisoformat(days[-1]) + timedelta(days=AFTER)
                out[name] = (u, {u, *peers[:PEOPLE - 1]}, first, last, sc, days)
                break
    leak = out.get("leak")
    if leak:                                    # control: same period, 20 people of one role, nobody an insider
        by_role = {}
        for p, r in sorted(roles.items()):
            if p not in labels:
                by_role.setdefault(r, []).append(p)
        role = next((r for r, ps in sorted(by_role.items(), key=lambda kv: -len(kv[1])) if len(ps) >= PEOPLE), None)
        if role is not None:
            out["normal"] = (None, set(by_role[role][:PEOPLE]), leak[2], leak[3], "-", [])
    return out


def main():
    for f in ("insider_labels.csv", "insider_users.csv"):
        if not os.path.exists(os.path.join(DIR, f)):
            sys.exit(f"{f} is missing - run prepare_insider_data.py first.")
    if not os.path.exists(P.ARCHIVE):
        sys.exit(f"{P.ARCHIVE} is missing - run download_insider_data.py first.")
    cs = cases()
    os.makedirs(OUT, exist_ok=True)
    files = {n: open(os.path.join(OUT, f"insider_demo_{n}.csv"), "w", newline="", encoding="utf-8") for n in cs}
    writers = {n: csv.writer(f) for n, f in files.items()}
    for w in writers.values():
        w.writerow(HEADER)
    wanted = {}                                  # user -> [(case, first, last)]
    for n, (_, users, first, last, _, _) in cs.items():
        for u in users:
            wanted.setdefault(u, []).append((n, first, last))
    counts = {n: 0 for n in cs}

    def emit(user, t, row):
        for n, first, last in wanted.get(user, ()):
            if first <= t.date() <= last:
                writers[n].writerow(row)
                counts[n] += 1

    try:
        for name, lines in P.stream_members(P.ARCHIVE):
            base = os.path.basename(name).lower()
            if base not in ("logon.csv", "device.csv", "file.csv", "email.csv", "http.csv"):
                continue
            header = next(csv.reader([lines.readline()]), [])
            idx = {h.strip().lower(): i for i, h in enumerate(header)}
            n_read = 0
            for line in lines:
                n_read += 1
                if n_read % 5_000_000 == 0:
                    print(f"  {name}: {n_read:,} lines", flush=True)
                quick = line.split(",", 4)               # id,date,user,pc,... - skip unwanted people cheaply
                if len(quick) < 5 or quick[2] not in wanted:
                    continue
                if base in ("file.csv", "http.csv"):
                    parts = line.rstrip("\r\n").split(",", 5)
                else:
                    parts = next(csv.reader([line]), [])
                if len(parts) < 5:
                    continue
                t = S.parse_time(parts[1])
                if t is None:
                    continue
                when = t.strftime("%Y-%m-%d %H:%M:%S")
                user, pc = parts[2], parts[3]
                if base == "logon.csv":
                    emit(user, t, [when, user, pc, parts[4].strip().lower(), "", "", "", "", "", "", ""])
                elif base == "device.csv":
                    act = "usb_connect" if parts[4].strip().lower() == "connect" else "usb_disconnect"
                    emit(user, t, [when, user, pc, act, "", "", "", "", "", "", ""])
                elif base == "file.csv":
                    emit(user, t, [when, user, pc, "file_copy", parts[4].strip().strip('"'), "", "", "", "", "", ""])
                elif base == "http.csv":
                    emit(user, t, [when, user, pc, "web", parts[4].strip().strip('"'), "", "", "", "", "", ""])
                else:
                    g = lambda k: parts[idx[k]] if k in idx and idx[k] < len(parts) else ""  # noqa: E731
                    emit(user, t, [when, user, pc, "email", "", g("to"), g("cc"), g("bcc"), g("from"), g("size"),
                                   g("attachments")])
            print(f"{name}: done", flush=True)
    finally:
        for f in files.values():
            f.close()
    with open(os.path.join(OUT, "insider_demo_answers.txt"), "w", encoding="utf-8") as f:
        for n, (u, users, first, last, sc, days) in cs.items():
            line = (f"insider_demo_{n}.csv: {len(users)} people, {first} to {last}, {counts[n]:,} events; "
                    + (f"insider {u} (CERT scenario {sc}), malicious days {', '.join(days)}" if u else
                       "no insider (control file)"))
            f.write(line + "\n")
            print(line)
    for n in cs:
        p = os.path.join(OUT, f"insider_demo_{n}.csv")
        print(f"wrote {p} ({os.path.getsize(p) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
