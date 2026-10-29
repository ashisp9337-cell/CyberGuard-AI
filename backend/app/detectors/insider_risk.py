"""Insider Risk (UEBA) - ONE engine behind three SOC lenses: Data Exfiltration, Abnormal Activity, Insider Threat.

Input is a table of user-days (one row per person per day, counts from insider_signals.py). For every user-day it adds:
  * own-baseline deviations - how far today is from the same person's previous 30 active days (past only)
  * peer deviations         - how far today is from colleagues with the same role on the same day
  * novelty flags           - first-ever USB use, logon on a PC never used before, first visit to a site that almost
                              nobody in the organisation uses (rare = at most 1% of the staff)
The same function is used by training (train_insider_risk.py) and by the live scan, so the numbers are identical.
"""
import csv
import json
import os
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

from app.detectors import insider_signals as S

WINDOW = 30            # own baseline: the previous 30 active days
MIN_HISTORY = 5        # fewer past days than this -> own-baseline deviations are 0 (not enough history)
RARE_SHARE = 0.01      # a site is "rare" when at most 1% of the staff visit it (at least 1 person)

# counts compared with the person's own past and with their peers
KEY = ["logon_n", "logon_after", "usb_n", "usb_after", "file_n", "file_after", "file_exe", "file_doc", "file_zip",
       "email_n", "email_ext", "email_personal_attach", "email_attach", "email_kb", "web_job", "web_cloud"]


def _own_deviation(g):
    """Per user (rows sorted by date): (today - mean of previous WINDOW days) / (std + 1); 0 with too little history."""
    past = g[KEY].shift(1).rolling(WINDOW, min_periods=MIN_HISTORY)
    mu, sd = past.mean(), past.std()
    z = (g[KEY] - mu) / (sd.fillna(0) + 1.0)
    out = z.fillna(0.0).add_prefix("own_")
    fm = g["first_min"].shift(1).rolling(WINDOW, min_periods=MIN_HISTORY)
    lm = g["last_min"].shift(1).rolling(WINDOW, min_periods=MIN_HISTORY)
    out["own_earlier_min"] = (fm.mean() - g["first_min"]).fillna(0.0).clip(lower=0) / 60.0   # hours earlier than usual
    out["own_later_min"] = (g["last_min"] - lm.mean()).fillna(0.0).clip(lower=0) / 60.0      # hours later than usual
    out["history_days"] = np.minimum(np.arange(len(g)), WINDOW)
    return out


def add_features(ud, roles=None, rare_visits=None, rare_reference=None):
    """ud: DataFrame with user, date (YYYY-MM-DD), pcs ('A;B') and S.FEATURES. roles: {user: role}.
    rare_visits: DataFrame user, date, domain, visits (visits to candidate rare sites).
    rare_reference: {domain: number of distinct users} defining rarity (default: counted from rare_visits itself),
    and the staff size is the number of distinct users in ud.
    Returns ud sorted by user/date with the extra feature columns (see feature_columns())."""
    ud = ud.copy()
    for c in S.FEATURES:
        if c not in ud.columns:
            ud[c] = 0.0
    ud = ud.sort_values(["user", "date"]).reset_index(drop=True)
    ud[S.FEATURES] = ud[S.FEATURES].astype(float)

    # own baseline
    # only the columns _own_deviation reads (not "user"): pandas will stop passing the grouping column to apply()
    dev = ud.groupby("user", group_keys=False, sort=False)[KEY + ["first_min", "last_min"]].apply(_own_deviation)
    ud = pd.concat([ud, dev.loc[ud.index]], axis=1)

    # novelty: first-ever USB use, PC never used before (both past-only)
    usb_before = ud.groupby("user")["usb_n"].transform(lambda s: s.shift(1).fillna(0).cumsum())
    ud["usb_first"] = ((ud["usb_n"] > 0) & (usb_before == 0) & (ud["history_days"] >= MIN_HISTORY)).astype(float)
    new_pc, n_pcs = [], []
    seen = defaultdict(set)
    for u, pcs, h in zip(ud["user"], ud["pcs"].fillna(""), ud["history_days"]):
        s = {p for p in str(pcs).split(";") if p}
        n_pcs.append(len(s))
        new_pc.append(float(len(s - seen[u])) if h >= MIN_HISTORY else 0.0)
        seen[u] |= s
    ud["new_pc"], ud["n_pcs"] = new_pc, n_pcs

    # peers: same role, same day (everyone that day when roles are unknown)
    role = ud["user"].map(roles or {}).fillna("(all)")
    grp = ud.groupby([role, ud["date"]])[KEY]
    mu, sd = grp.transform("mean"), grp.transform("std").fillna(0)
    peer = ((ud[KEY] - mu) / (sd + 1.0)).add_prefix("peer_")
    ud = pd.concat([ud, peer], axis=1)

    # rare sites: first visit by this person to a site at most RARE_SHARE of the staff use
    ud["web_rare_new"] = 0.0
    if rare_visits is not None and len(rare_visits):
        rv = rare_visits.sort_values(["date"])
        staff = max(ud["user"].nunique(), 1)
        ref = rare_reference if rare_reference is not None else rv.groupby("domain")["user"].nunique().to_dict()
        limit = max(1, int(RARE_SHARE * staff))
        rare_doms = {d for d, n in ref.items() if n <= limit}
        rv = rv[rv["domain"].map(lambda d: d in rare_doms or d not in ref)]
        rv = rv.drop_duplicates(["user", "domain"], keep="first")          # first visit only
        cnt = rv.groupby(["user", "date"]).size()
        idx = pd.MultiIndex.from_frame(ud[["user", "date"]])
        ud["web_rare_new"] = cnt.reindex(idx).fillna(0).to_numpy(dtype=float)
    return ud


def baseline_score(d, with_web=True):
    """The 'unlike themselves' score: no labels involved. Sum of positive own/peer deviations (each capped at 6) plus
    fixed points for novelties. Weights were set once by hand, before any evaluation, and are not tuned."""
    z = sum(d[c].clip(0, 6) for c in feature_columns(with_web) if c.startswith(("own_", "peer_")))
    s = z + 3 * d["usb_first"] + 2 * d["new_pc"]
    if with_web:
        s = s + 5 * (d["web_leak"] > 0) + 5 * (d["web_spyware"] > 0) + 3 * d["web_rare_new"]
    return np.asarray(s, dtype=float)


def to_percentile(values, quantiles):
    """Where each value sits among NORMAL training user-days (0-100); quantiles = 1001 cut points."""
    q = np.asarray(quantiles, dtype=float)
    return np.interp(np.asarray(values, dtype=float), q, np.linspace(0, 100, len(q)), left=0.0, right=100.0)


def combined_risk(model_p, base_s, cfg):
    """0-100: the higher of 'matches a known insider playbook' (model) and 'unlike themselves' (baseline), each as a
    percentile of normal user-days. 99 = riskier than 99% of ordinary working days."""
    return np.maximum(to_percentile(model_p, cfg["model_quantiles"]), to_percentile(base_s, cfg["baseline_quantiles"]))


def feature_columns(with_web=True):
    cols = (S.FEATURES + ["own_" + k for k in KEY] + ["own_earlier_min", "own_later_min", "usb_first", "new_pc", "n_pcs"]
            + ["peer_" + k for k in KEY] + ["web_rare_new"])
    if not with_web:
        cols = [c for c in cols if not (c.startswith("web_") or c in ("own_web_job", "own_web_cloud", "peer_web_job",
                                                                       "peer_web_cloud"))]
    return cols


# =====================================================================================================================
# Live scan: an uploaded / pasted ACTIVITY LOG -> user-days -> risk -> SOC triage queue with three lenses
# =====================================================================================================================
HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "insider_risk.joblib")
CONFIG_PATH = os.path.join(HERE, "..", "ml", "models", "insider_risk.json")
MAX_EVENTS = 400_000          # events read from one upload
MIN_STAFF_FOR_RARITY = 20     # "a site almost nobody uses" needs a real organisation to compare with
QUEUE_SIZE = 15

_COLS = {
    "time": ("date", "timestamp", "time", "datetime", "_time", "eventtime", "event_time", "time_generated",
             "timegenerated", "@timestamp"),
    "user": ("user", "username", "user_name", "userid", "user_id", "account", "accountname", "src_user", "actor",
             "employee"),
    "pc": ("pc", "host", "hostname", "computer", "computername", "device", "workstation", "machine"),
    "activity": ("activity", "event", "event_type", "eventtype", "action", "type", "category", "operation"),
    "detail": ("details", "detail", "target", "object", "resource"),
    "url": ("url", "uri", "website", "site", "domain"),
    "file": ("filename", "file", "file_name", "filepath", "path"),
    "to": ("to", "recipient", "recipients"),
    "cc": ("cc",), "bcc": ("bcc",), "from": ("from", "sender"),
    "size": ("size", "bytes", "size_bytes"),
    "attachments": ("attachments", "attachment_count", "attachment"),
    "role": ("role", "job_title", "title", "department"),
}
_KIND = [  # unified "activity" values -> event kind
    ("logon", ("logon", "login", "log on", "sign-in", "signin", "sign in", "4624", "logged on")),
    ("logoff", ("logoff", "logout", "log off", "sign-out", "signout", "4634", "4647")),
    ("usb", ("connect", "usb", "usb_connect", "usb connect", "device connect", "removable", "mount", "insert")),
    ("usb_off", ("disconnect", "usb_disconnect", "eject", "unmount", "remove")),
    ("file", ("file", "file_copy", "file copy", "copy", "file_write", "write", "copied")),
    ("email", ("email", "e-mail", "mail", "send", "email_send", "sent")),
    ("web", ("http", "web", "url", "visit", "browse", "upload", "download", "proxy")),
]
MITRE = {"usb": "T1052.001", "cloud": "T1567.002", "leak": "T1567", "email": "T1048", "spyware": "T1056.001",
         "account": "T1078"}

_CACHE = {"stamp": None, "model": None, "cfg": None}


def _stamp(path):
    st = os.stat(path)
    return st.st_mtime_ns, st.st_size


def load_trained():
    """(model bundle, config) or (None, None) when train_insider_risk.py has not been run / files are broken."""
    try:
        stamp = (_stamp(MODEL_PATH), _stamp(CONFIG_PATH))
    except OSError:
        return None, None
    if _CACHE["stamp"] != stamp:
        try:
            import joblib
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
            _CACHE["model"], _CACHE["cfg"] = joblib.load(MODEL_PATH), cfg
        except Exception:                     # noqa: BLE001 - a broken model file never breaks a scan
            _CACHE["model"], _CACHE["cfg"] = None, None
        _CACHE["stamp"] = stamp
    return _CACHE["model"], _CACHE["cfg"]


def _kind_of(value):
    v = (value or "").strip().lower()
    for kind, words in _KIND:
        if v in words:
            return kind
    for kind, words in _KIND:                 # "USB Connect", "File Copy to E:" ...
        if any(w in v for w in words if len(w) > 3):
            return kind
    return ""


def _header(line):
    cols = [c.strip().strip('"').strip().lower() for c in next(csv.reader([line]), [])]
    idx = {}
    for key, names in _COLS.items():
        for i, c in enumerate(cols):
            if c in names and key not in idx:
                idx[key] = i
    return cols, idx


def _table_kind(idx, cols):
    """Which activity table this is: 'unified' or one of CERT's logon / device / file / email / http."""
    if "time" not in idx or "user" not in idx:
        return ""
    if "url" in idx and "activity" not in idx:
        return "http"
    if "file" in idx and "activity" not in idx:
        return "file"
    if "to" in idx and ("size" in idx or "attachments" in idx) and "activity" not in idx:
        return "email"
    if "activity" in idx:
        return "unified"
    return ""


FORMATS = {"unified": "user activity log - one event per row", "http": "web proxy log - CERT http.csv layout",
           "file": "file-copy log - CERT file.csv layout", "email": "e-mail log - CERT email.csv layout"}


def activity_log_kind(text):
    """The activity-log layout of this text, judged from its header row only ('' when it is not one)."""
    head = next((ln for ln in (text or "").lstrip("\ufeff")[:4096].splitlines() if ln.strip()), "")
    if "," not in head:
        return ""
    cols, idx = _header(head)
    return _table_kind(idx, cols)


def parse_activity(text):
    """Read an activity log (CSV with a header row). Returns None when the text is not one."""
    text = (text or "").lstrip("\ufeff")
    if not activity_log_kind(text):                   # decided from the header alone, before reading everything
        return None
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip())
    cols, idx = _header(lines[start])
    table = _table_kind(idx, cols)
    day = defaultdict(S.new_day)
    pcs = defaultdict(set)
    web = Counter()                                    # (user, date, domain) -> visits
    roles, senders, rcpt_domains = {}, Counter(), defaultdict(Counter)
    stats = Counter()
    first = last = None

    def col(row, key):
        i = idx.get(key)
        return row[i].strip() if i is not None and i < len(row) else ""

    for row in csv.reader(lines[start + 1:]):
        if not row or not any(c.strip() for c in row):
            continue
        if stats["events"] >= MAX_EVENTS:
            stats["truncated"] = 1
            break
        t = S.parse_time(col(row, "time"))
        user = col(row, "user")
        if t is None or not user:
            stats["unreadable"] += 1
            continue
        if "@" in user and table == "unified" and not col(row, "from"):
            senders[user.lower().rsplit("@", 1)[1]] += 1
        user = user.split("\\")[-1]                        # DOMAIN\user -> user
        key = (user, t.date().isoformat())
        if col(row, "role"):
            roles[user] = col(row, "role")
        if table == "unified":
            act = col(row, "activity")
            kind = _kind_of(act)
            detail = col(row, "detail")
        else:
            kind = {"http": "web", "file": "file", "email": "email"}.get(table, "")
            act, detail = "", ""
        pc = col(row, "pc")
        d = day[key]
        if kind in ("logon", "logoff"):
            S.add_logon(d, t, "logon" if kind == "logon" else "logoff")
        elif kind in ("usb", "usb_off"):
            if kind == "usb":
                S.add_usb(d, t, "connect")
        elif kind == "file":
            S.add_file(d, t, col(row, "file") or detail)
        elif kind == "email":
            rcpt = S.split_recipients(col(row, "to") or detail, col(row, "cc"), col(row, "bcc"))
            sender = col(row, "from").lower()
            if "@" in sender:
                senders[sender.rsplit("@", 1)[1]] += 1
            rcpt_domains[key].update(r.rsplit("@", 1)[1] for r in rcpt)
            S.add_email(d, t, rcpt, col(row, "size") or "0", col(row, "attachments"))
        elif kind == "web":
            dom = S.domain_of(col(row, "url") or detail)
            if dom:
                S.add_web(d, t, dom)
                web[(user, key[1], dom)] += 1
        elif table == "unified" and act.lower() in ("logon", "logoff"):
            pass
        else:
            stats["other"] += 1
            if not kind:
                continue
        if pc and kind in ("logon", "logoff", "usb"):        # same as training: PCs come from logons / USB connects
            pcs[key].add(pc)
        stats["events"] += 1
        stats[kind or "other"] += 1
        first = t if first is None or t < first else first
        last = t if last is None or t > last else last
    if stats["events"] < 2:
        return None
    if not rcpt_domains:
        company = ""
    else:
        company = senders.most_common(1)[0][0] if senders else Counter(
            dm for rc in rcpt_domains.values() for dm in rc.elements()).most_common(1)[0][0]
    for key, rc in rcpt_domains.items():
        day[key]["email_ext"] = float(sum(c for dm, c in rc.items() if dm != company))
    rows = [{"user": u, "date": dt, "pcs": ";".join(sorted(pcs.get((u, dt), ()))),
             **{k: float(day[(u, dt)].get(k, 0.0)) for k in S.FEATURES}} for (u, dt) in sorted(day)]
    ud = pd.DataFrame(rows)                             # (first_min / last_min stay 0 on days without logon or USB,
                                                        #  exactly as in training)
    rv = pd.DataFrame([{"user": u, "date": dt, "domain": dm, "visits": c} for (u, dt, dm), c in web.items()],
                      columns=["user", "date", "domain", "visits"])
    fmt = FORMATS[table]
    return {"ud": ud, "rare_visits": rv, "roles": roles, "format": fmt, "company": company,
            "events": int(stats["events"]), "skipped": int(stats["unreadable"] + stats["other"]),
            "truncated": bool(stats["truncated"]), "kinds": {k: int(v) for k, v in stats.items()
                                                          if k in ("logon", "logoff", "usb", "file", "email", "web")},
            "timeRange": [first.isoformat(sep=" "), last.isoformat(sep=" ")] if first else None}


def _reasons(r):
    """Plain-language reasons for one scored user-day, per lens. Each: (text, mitre or None)."""
    ex, ab = [], []
    if r["usb_first"] > 0:
        ex.append(("first USB storage use ever seen for this person", MITRE["usb"]))
    if r["usb_after"] > 0:
        ex.append((f"USB drive connected outside office hours ({int(r['usb_after'])}x)", MITRE["usb"]))
    elif r["own_usb_n"] >= 3:
        ex.append((f"USB drive used {int(r['usb_n'])}x - far more than usual for them", MITRE["usb"]))
    if r["file_n"] > 0 and (r["own_file_n"] >= 3 or r["peer_file_n"] >= 3):
        ex.append((f"{int(r['file_n'])} files copied to removable media - far above their usual / their colleagues",
                   MITRE["usb"]))
    if r["file_after"] > 0:
        ex.append((f"{int(r['file_after'])} files copied outside office hours", MITRE["usb"]))
    if r["email_personal_attach"] > 0:
        ex.append((f"{int(r['email_personal_attach'])} e-mail(s) carrying files sent to personal webmail addresses",
                   MITRE["email"]))
    if r["web_leak"] > 0:
        ex.append(("visited a public leak site (WikiLeaks-type)", MITRE["leak"]))
    if r["web_cloud"] > 0 and r["own_web_cloud"] >= 2:
        ex.append((f"{int(r['web_cloud'])} visits to file-sharing / upload sites - far above usual", MITRE["cloud"]))
    if r["own_email_kb"] >= 3:
        ex.append((f"sent {r['email_kb'] / 1024:.1f} MB of e-mail - far above usual", MITRE["email"]))
    if r["logon_after"] > 0 and (r["own_logon_after"] >= 2 or r["peer_logon_after"] >= 3):
        ab.append((f"logged on outside office hours ({int(r['logon_after'])}x) - unusual for them", None))
    if r["own_earlier_min"] >= 2:
        ab.append((f"started work {r['own_earlier_min']:.1f} h earlier than usual", None))
    if r["own_later_min"] >= 2:
        ab.append((f"still active {r['own_later_min']:.1f} h later than usual", None))
    if r["new_pc"] > 0:
        ab.append((f"used {int(r['new_pc'])} computer(s) they had never used before", MITRE["account"]))
    if r["own_logon_n"] >= 3 or r["peer_logon_n"] >= 3:
        ab.append((f"{int(r['logon_n'])} logons - far more than usual / than colleagues", None))
    if r["web_rare_new"] > 0:
        ab.append((f"first visit to {int(r['web_rare_new'])} site(s) almost nobody in the organisation uses", None))
    if r["web_spyware"] > 0:
        ab.append(("visited a keylogger / spyware vendor site", MITRE["spyware"]))
    return ex, ab


def _pattern(r, ex, ab, job_trend):
    """Insider-threat lens: which known insider pattern the day fits (rules; see the README for the evidence)."""
    if r["web_spyware"] > 0 or (r["file_exe"] > 0 and r["new_pc"] > 0):
        return ("Spying / sabotage with monitoring tools", "high",
                "keylogger or spyware sites, program files copied, other people's computers used", MITRE["spyware"])
    if r["web_leak"] > 0 or (r["usb_first"] > 0 and r["usb_after"] > 0):
        return ("Data leak to outsiders", "high", "new after-hours USB use and / or leak-site visits", MITRE["leak"])
    if ex and job_trend:
        return ("Data theft before leaving", "high", "job-site visits rising while data is being copied", MITRE["usb"])
    if r["new_pc"] > 0 and r["logon_after"] > 0 and not ex:
        return ("Possible misuse of someone else's account or computer", "medium",
                "after-hours logons on computers this person never used", MITRE["account"])
    if r["email_personal_attach"] > 0 and len(ex) == 1 and not ab:
        return ("Possible careless handling (negligent insider)", "low",
                "work files e-mailed to a personal address - rule only, no accuracy measured", MITRE["email"])
    if ex:
        return ("Unusual data handling", "medium", "data moved in an unusual way", ex[0][1])
    if ab:
        return ("Behaviour change", "low", "activity unlike this person's normal pattern", ab[0][1])
    return None


def to_score(risk, review, alert):
    """Combined percentile -> the app's 0-100 scale: alert level 71-100, review level 51-70, below that 0-50."""
    if risk >= alert:
        return int(min(100, round(71 + 29 * (risk - alert) / max(100 - alert, 1e-6))))
    if risk >= review:
        return int(round(51 + 19 * (risk - review) / max(alert - review, 1e-6)))
    return int(round(50 * min(risk, review) / max(review, 1e-6)))


def analyze_text(text):
    """Activity log -> SOC summary (None when the text is not an activity log)."""
    parsed = parse_activity(text)
    if not parsed:
        return None
    ud = parsed["ud"]
    staff = ud["user"].nunique()
    rv = parsed["rare_visits"] if staff >= MIN_STAFF_FOR_RARITY else None
    X = add_features(ud, parsed["roles"], rv)
    bundle, cfg = load_trained()
    notes = []
    if staff < MIN_STAFF_FOR_RARITY:
        notes.append(f"Only {staff} person(s) in this log: 'sites almost nobody uses' needs at least "
                     f"{MIN_STAFF_FOR_RARITY} people, and colleague comparisons are weak.")
    if (X["history_days"] < MIN_HISTORY).all():
        notes.append(f"Every person has fewer than {MIN_HISTORY} earlier days in this log, so nobody's own normal "
                     "behaviour could be learned - upload a few weeks of activity for a real baseline.")
    trained = bool(bundle and cfg)
    if trained:
        cols = bundle["columns"]
        p = bundle["model"].predict_proba(X[cols])[:, 1]
        X["risk"] = combined_risk(p, baseline_score(X, with_web="web_leak" in cols), cfg)
        review, alert = float(cfg.get("review_level", 99.0)), float(cfg.get("alert_level", 99.9))
    else:
        X["risk"] = 0.0
        review, alert = 99.0, 99.9
        notes.append("The insider-risk model is not trained yet (run app\\ml\\training\\train_insider_risk.py): only "
                     "the rule findings below are shown, without a risk level.")
    X["job_hot"] = (X["own_web_job"] >= 2).astype(int)
    X["job_trend"] = X.groupby("user")["job_hot"].transform(lambda s: s.rolling(14, min_periods=1).sum()) >= 3

    queue, lens_users = [], {"exfiltration": set(), "abnormal": set(), "insider": set()}
    for user, g in X.groupby("user", sort=False):
        days = []
        for _, r in g.iterrows():
            ex, ab = _reasons(r)
            pat = _pattern(r, ex, ab, bool(r["job_trend"]))
            level = "alert" if r["risk"] >= alert else "review" if r["risk"] >= review else ""
            if not trained and pat and pat[1] == "high":
                level = "review"
            days.append((r, ex, ab, pat, level))
        flagged = [d for d in days if d[4]]
        if not flagged:
            continue
        best = max(flagged, key=lambda d: (d[4] == "alert", d[0]["risk"]))
        r, ex, ab, pat, level = best
        if ex:
            lens_users["exfiltration"].add(user)
        if ab:
            lens_users["abnormal"].add(user)
        if pat and pat[1] in ("high", "medium"):
            lens_users["insider"].add(user)
        queue.append({
            "user": user, "level": level, "risk": round(float(r["risk"]), 2),
            "score": to_score(float(r["risk"]), review, alert) if trained else 51,
            "date": r["date"], "flaggedDays": len(flagged), "alertDays": sum(d[4] == "alert" for d in days),
            "historyDays": int(r["history_days"]),
            "exfiltration": [t for t, _ in ex], "abnormal": [t for t, _ in ab],
            "pattern": {"name": pat[0], "strength": pat[1], "why": pat[2]} if pat else None,
            "mitre": sorted({m for _, m in ex + ab if m} | ({pat[3]} if pat and pat[3] else set())),
            "timeline": [{"date": d[0]["date"], "risk": round(float(d[0]["risk"]), 1), "level": d[4]}
                         for d in days[-30:]],
        })
    queue.sort(key=lambda q: (q["level"] == "alert", q["risk"], q["alertDays"]), reverse=True)
    res = (cfg or {}).get("results", {}).get("time_split", {})
    return {"format": parsed["format"], "events": parsed["events"], "skipped": parsed["skipped"],
            "truncated": parsed["truncated"], "kinds": parsed["kinds"], "timeRange": parsed["timeRange"],
            "people": int(staff), "userDays": int(len(X)), "trained": trained,
            "reviewLevel": review, "alertLevel": alert,
            "alerts": sum(q["level"] == "alert" for q in queue), "reviews": sum(q["level"] == "review" for q in queue),
            "lenses": {k: len(v) for k, v in lens_users.items()}, "queue": queue[:QUEUE_SIZE],
            "falseAlertsPerDay": res.get("false_alert_per_day"), "testCaught": res.get("caught"),
            "testOf": res.get("of"), "notes": notes}
