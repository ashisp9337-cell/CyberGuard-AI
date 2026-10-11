"""
Look inside the RBA dataset before (re)designing the account-takeover model.
Run from backend/:
    python -m app.ml.training.explore_rba --rows 3000000

Writes (in app/ml/training/data/):
    rba_explore_report.txt     -- what separates attack logins from normal ones
    rba_sample.csv             -- the first --sample-rows logins, small enough to experiment with
Reads only; changes nothing else.
"""
import argparse
import os
import sys
from collections import Counter, defaultdict

import pandas as pd

from app.ml.training.train_ato_login import DATA_DIR, find_dataset, map_columns, truthy

out_lines = []


def say(*a):
    line = " ".join(str(x) for x in a)
    print(line)
    out_lines.append(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None)
    ap.add_argument("--rows", type=int, default=3_000_000)
    ap.add_argument("--sample-rows", type=int, default=400_000)
    args = ap.parse_args()
    path = find_dataset(args.data)
    cols = map_columns(list(pd.read_csv(path, nrows=0).columns))
    rtt_col = next((c for c in pd.read_csv(path, nrows=0).columns if "round-trip" in c.lower() or "rtt" in c.lower()), None)

    sample_path = os.path.join(DATA_DIR, "rba_sample.csv")
    wrote_header, written = False, 0
    n = n_att = n_ato = n_ok = n_att_ok = 0
    ip_users, ip_att, ip_n = defaultdict(set), {}, Counter()
    user_n, att_users_per_ip = Counter(), Counter()
    cat = {k: (Counter(), Counter()) for k in ("country", "asn", "device_type", "browser", "os") if k in cols}
    ua_att, ua_all = Counter(), Counter()
    hours_att, hours_all = Counter(), Counter()
    rtt_att, rtt_norm = [], []
    first_ts = last_ts = None
    for chunk in pd.read_csv(path, dtype=str, chunksize=500_000, keep_default_na=False):
        if written < args.sample_rows:
            part = chunk.iloc[: args.sample_rows - written]
            part.to_csv(sample_path, mode="a" if wrote_header else "w", header=not wrote_header, index=False)
            wrote_header, written = True, written + len(part)
        att, ato, ok = truthy(chunk[cols["attack_ip"]]), truthy(chunk[cols["ato"]]), truthy(chunk[cols["success"]])
        ts = pd.to_datetime(chunk[cols["ts"]], errors="coerce", utc=True)
        first_ts = first_ts or ts.min()
        last_ts = ts.max()
        n += len(chunk); n_att += int(att.sum()); n_ato += int(ato.sum()); n_ok += int(ok.sum()); n_att_ok += int((att & ok).sum())
        for ip, u, a in zip(chunk[cols["ip"]], chunk[cols["user"]], att):
            ip_n[ip] += 1
            if len(ip_users[ip]) < 1000:
                ip_users[ip].add(u)
            if a:
                ip_att[ip] = True
            user_n[u] += 1
        for k, (c_att, c_all) in cat.items():
            vals = chunk[cols[k]]
            c_all.update(vals)
            c_att.update(vals[att])
        if "ua" in cols:
            fam = chunk[cols["ua"]].str.extract(r"^([A-Za-z\-]+)", expand=False).fillna("")
            ua_all.update(fam); ua_att.update(fam[att])
        hours_all.update(ts.dt.hour.dropna().astype(int)); hours_att.update(ts[att].dt.hour.dropna().astype(int))
        if rtt_col:
            r = pd.to_numeric(chunk[rtt_col], errors="coerce")
            rtt_att.extend(r[att].dropna().tolist()[:20000]); rtt_norm.extend(r[~att].dropna().tolist()[:20000])
        print(f"  {n:,} rows read", flush=True)
        if n >= args.rows:
            break

    say(f"Rows read: {n:,}   time span: {first_ts} -> {last_ts}")
    say(f"Attack-IP rows: {n_att:,} ({n_att / n:.2%})   account-takeover rows: {n_ato}")
    say(f"Login success rate: normal {(n_ok - n_att_ok) / max(n - n_att, 1):.1%}   attack {n_att_ok / max(n_att, 1):.1%}")
    att_ips = [ip for ip in ip_att]
    say(f"\nIPs: {len(ip_n):,} total, {len(att_ips):,} attack IPs")
    def stats(ips):
        users = sorted(len(ip_users[i]) for i in ips)
        logins = sorted(ip_n[i] for i in ips)
        q = lambda v, p: v[min(len(v) - 1, int(p * len(v)))] if v else 0
        return f"accounts per IP median {q(users, .5)}, p90 {q(users, .9)}, max {q(users, 1)} | logins per IP median {q(logins, .5)}, p90 {q(logins, .9)}, max {q(logins, 1)}"
    say("  attack IPs :", stats(att_ips))
    normal_ips = [i for i in ip_n if i not in ip_att]
    say("  normal IPs :", stats(normal_ips[:200000]))
    say(f"Users: {len(user_n):,}; logins per user median {sorted(user_n.values())[len(user_n) // 2]}")

    for k, (c_att, c_all) in cat.items():
        say(f"\nTop {k} among ATTACK logins (share of attacks | attack rate for that value):")
        for v, c in c_att.most_common(8):
            say(f"   {v[:40]:40s} {c / max(n_att, 1):6.1%} | {c / c_all[v]:6.1%}")
    say("\nUser-agent family among attacks (share | attack rate):")
    for v, c in ua_att.most_common(8):
        say(f"   {v[:30]:30s} {c / max(n_att, 1):6.1%} | {c / ua_all[v]:6.1%}")
    say("\nHour of day (UTC): attack share vs normal share")
    for h in range(24):
        say(f"   {h:02d}h  attack {hours_att[h] / max(n_att, 1):5.1%}   all {hours_all[h] / n:5.1%}")
    if rtt_col and rtt_att:
        s1, s2 = pd.Series(rtt_att), pd.Series(rtt_norm)
        say(f"\nRTT ms  attack median {s1.median():.0f} (n={len(s1)})   normal median {s2.median():.0f} (n={len(s2)})")
    with open(os.path.join(DATA_DIR, "rba_explore_report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
    print(f"\nReport -> {os.path.join(DATA_DIR, 'rba_explore_report.txt')}\nSample -> {sample_path} ({written:,} rows)")


if __name__ == "__main__":
    sys.exit(main())
