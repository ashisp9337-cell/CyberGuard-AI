"""
Credential theft / account-takeover (ATO) engine.

Two ways to use it:
  1. Structured fields   -> analyze_event({"failedAttempts": 20, "newDevice": "true", ...})
  2. A pasted log / description -> analyze_event({}, text="...auth log lines...")

The text is parsed by parse_log() into the same fields, so both paths score
identically. Explicit fields always win/add to what the parser finds.
"""
import math
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from app.detectors.base import build_result
from app.detectors import rba_risk

# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
FAIL_RE = re.compile(
    r"(failed password|authentication fail|auth(?:entication)? failure|invalid (?:user|password|credentials)|"
    r"login failed|failed login|failed to log ?in|logon failure|access denied|bad password|wrong password|"
    r"event ?id[:= ]*4625|\b4625\b|status[=: ]*(?:401|403)\b|\b401 unauthorized|incorrect password|"
    r"sign-?in (?:failed|error)|mfa (?:failed|denied|rejected)|account locked|locked out)", re.I)
OK_RE = re.compile(
    r"(accepted (?:password|publickey)|login success|successful login|logged in|logon success|"
    r"event ?id[:= ]*4624|\b4624\b|authentication success|sign-?in success|status[=: ]*200 .*login|session opened)", re.I)
USER_RES = [
    re.compile(r"invalid user (\S+)", re.I),
    re.compile(r"failed password for (?:invalid user )?(\S+)", re.I),
    re.compile(r"(?:user(?:name)?|account(?: name)?|login|upn)\s*[=:]\s*\"?([^\s\",;]+)", re.I),
    re.compile(r"for user (\S+)", re.I),
]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TS_RES = [
    (re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)"), "%Y-%m-%d %H:%M:%S"),
    (re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"), None),  # syslog: Oct  7 03:12:01
]
NEW_DEVICE_RE = re.compile(r"(new device|unrecogni[sz]ed device|unknown device|unfamiliar device|new browser|"
                           r"device (?:not|never) (?:seen|recognized|trusted)|untrusted device|device fingerprint (?:mismatch|changed))", re.I)
ANON_RE = re.compile(r"\b(tor exit|tor node|tor network|vpn|proxy|anonymi[sz]|residential proxy|datacenter ip)\b", re.I)
MFA_RE = re.compile(r"(mfa|2fa|two[- ]factor|multi[- ]factor|authenticator)[^.\n]{0,40}(changed|reset|disabled|removed|added|modified|new|enrolled|bypass)|"
                    r"(changed|reset|disabled|removed|added|modified|enrolled)[^.\n]{0,40}(mfa|2fa|two[- ]factor|multi[- ]factor|authenticator)", re.I)
PWRESET_RE = re.compile(r"(password (?:was )?(?:reset|changed|updated)|reset (?:the |your )?password|change[d]? password|passwd changed|forgot password)", re.I)
RECOVERY_RE = re.compile(r"(recovery (?:email|phone|number|address|option)|backup (?:email|phone)|security question)[^.\n]{0,40}(changed|updated|added|removed|modified)", re.I)
PRIV_RE = re.compile(r"(privilege escalation|added to (?:the )?(?:admin|administrators|domain admins|sudoers|root)|"
                     r"role (?:changed|assigned|elevated)[^.\n]{0,30}(?:admin|owner|root)|granted (?:admin|owner|root)|sudo su|made admin|"
                     r"event ?id[:= ]*(?:4728|4732|4672)|\b4672\b|\b4732\b)", re.I)
FORWARD_RE = re.compile(r"(forwarding (?:rule|address)|inbox rule|mail ?flow rule|auto-?forward|forward(?:ed)? (?:all )?(?:mail|email)s? to|redirect(?:ed)? (?:mail|email))", re.I)
TOKEN_RE = re.compile(r"(new api (?:key|token)|api (?:key|token) (?:created|generated)|oauth (?:app|consent|grant)|app password (?:created|generated)|"
                      r"personal access token|new ssh key|authorized_keys)", re.I)
EXFIL_RE = re.compile(r"(bulk download|mass download|exported? (?:all|\d{3,})|downloaded \d{3,}|data export|download(?:ed)? [0-9.]+ ?(?:gb|mb)|"
                      r"\d{3,} files (?:downloaded|accessed|copied)|archive created)", re.I)
UNUSUAL_HOUR_RE = re.compile(r"(unusual (?:hour|time)|odd hour|outside (?:normal|business|working) hours|off[- ]hours|at night|middle of the night)", re.I)
TRAVEL_WORD_RE = re.compile(r"(impossible travel|atypical travel|unlikely travel|travell?ed [0-9,]+ ?(?:km|miles) in)", re.I)
# Note: Windows 4625 always prints "Unknown user name or bad password" -- that does NOT mean the account is
# missing (only sub-status 0xC0000064 does), so that phrase is excluded.
INVALID_USER_RE = re.compile(r"(invalid user|user unknown|unknown user(?! name or bad password)|no such user|user (?:does not|doesn't) exist|"
                             r"account (?:does not|doesn't) exist|0xc0000064|user not found)", re.I)
UNUSUAL_LOC_RE = re.compile(r"(unusual (?:location|country|region)|new (?:location|country)|first time (?:from|in) |unfamiliar location|login from (?:an? )?(?:new|unknown) (?:location|country))", re.I)

# Small city/country table so "Mumbai ... London" works without a GeoIP service.
GEO = {
    "mumbai": (19.07, 72.88), "delhi": (28.61, 77.21), "new delhi": (28.61, 77.21), "bhubaneswar": (20.30, 85.82),
    "bengaluru": (12.97, 77.59), "bangalore": (12.97, 77.59), "kolkata": (22.57, 88.36), "chennai": (13.08, 80.27),
    "hyderabad": (17.38, 78.48), "pune": (18.52, 73.86), "india": (22.0, 79.0),
    "london": (51.51, -0.13), "uk": (54.0, -2.0), "united kingdom": (54.0, -2.0), "paris": (48.86, 2.35),
    "berlin": (52.52, 13.40), "germany": (51.0, 10.0), "moscow": (55.75, 37.62), "russia": (61.5, 105.0),
    "kyiv": (50.45, 30.52), "ukraine": (49.0, 32.0), "lagos": (6.52, 3.38), "nigeria": (9.0, 8.0),
    "new york": (40.71, -74.01), "usa": (39.0, -98.0), "united states": (39.0, -98.0), "california": (37.0, -120.0),
    "san francisco": (37.77, -122.42), "toronto": (43.65, -79.38), "canada": (56.0, -106.0),
    "singapore": (1.35, 103.82), "tokyo": (35.68, 139.69), "japan": (36.0, 138.0), "beijing": (39.90, 116.40),
    "china": (35.0, 103.0), "hong kong": (22.32, 114.17), "dubai": (25.20, 55.27), "uae": (24.0, 54.0),
    "sydney": (-33.87, 151.21), "australia": (-25.0, 134.0), "sao paulo": (-23.55, -46.63), "brazil": (-10.0, -55.0),
    "pakistan": (30.0, 70.0), "karachi": (24.86, 67.01), "dhaka": (23.81, 90.41), "bangladesh": (24.0, 90.0),
    "pyongyang": (39.04, 125.76), "north korea": (40.0, 127.0), "tehran": (35.69, 51.39), "iran": (32.0, 53.0),
}
_GEO_RE = re.compile(r"(?<![a-z])(" + "|".join(sorted((re.escape(k) for k in GEO), key=len, reverse=True)) + r")(?![a-z])", re.I)
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_ts(line: str):
    m = TS_RES[0][0].search(line)
    if m:
        t = m.group(2)
        t = t if t.count(":") == 2 else t + ":00"
        try:
            return datetime.strptime(f"{m.group(1)} {t}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    m = TS_RES[1][0].search(line)
    if m and m.group(1) in _MONTHS:
        try:
            return datetime(2000, _MONTHS[m.group(1)], int(m.group(2)),
                            *[int(x) for x in m.group(3).split(":")])
        except ValueError:
            return None
    return None


def _km(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (*a, *b))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def parse_log(text: str) -> dict:
    """Turn pasted logs / a description into signal fields plus evidence strings."""
    out = {"failedAttempts": 0, "successAfterFailures": False, "distinctFailedUsers": 0, "sources": 0,
           "impossibleTravel": False, "newDevice": False, "anonymizingNetwork": False,
           "passwordResetRecent": False, "mfaChanged": False, "privilegeEscalation": False,
           "unusualHour": False, "unusualLocation": False, "recoveryChanged": False,
           "forwardingRule": False, "newCredentialCreated": False, "massDownload": False,
           "invalidUserAttempts": 0, "evidence": {}}
    if not text or not text.strip():
        return out
    ev = out["evidence"]
    lines = [ln for ln in re.split(r"[\r\n]+", text) if ln.strip()]

    fails, users, srcs, invalid = 0, defaultdict(set), set(), 0
    invalid_users = defaultdict(set)    # source -> usernames that do not exist on the system
    seq = []      # "F" / "S" in order
    logins = []   # (timestamp, (lat, lon), place)
    odd_hour = False
    for ln in lines:
        is_fail = bool(FAIL_RE.search(ln))
        is_ok = bool(OK_RE.search(ln)) and not is_fail
        ips = IP_RE.findall(ln)
        if is_fail:
            fails += 1
            seq.append("F")
            invalid += bool(INVALID_USER_RE.search(ln))
            for rx in USER_RES:
                m = rx.search(ln)
                if m:
                    u = m.group(1).strip("'\"[]()").lower()
                    src = ips[0] if ips else "?"
                    users[src].add(u)
                    if INVALID_USER_RE.search(ln):
                        invalid_users[src].add(u)
                    break
            srcs.update(ips[:1])
        elif is_ok:
            seq.append("S")
        ts = _parse_ts(ln)
        if (is_ok or "login" in ln.lower() or "sign" in ln.lower()) and ts is not None:
            if ts.hour < 5 and (is_ok or not is_fail):
                odd_hour = True
        gm = _GEO_RE.search(ln)
        if gm and ts is not None and (is_ok or not is_fail):
            logins.append((ts, GEO[gm.group(1).lower()], gm.group(1).title()))

    prose = re.search(r"(\d{1,5})\s+(?:failed|unsuccessful|invalid|bad)\s+(?:login|logon|sign-?in|password|attempt|authentication)", text, re.I)
    if prose:
        fails = max(fails, int(prose.group(1)))
        ev["failedAttempts"] = f"\"{prose.group(0)}\""
    out["failedAttempts"] = fails
    if fails and "failedAttempts" not in ev:
        ev["failedAttempts"] = f"{fails} failed-login line(s)"

    s = "".join(seq)
    m = re.search(r"F{3,}S", s)
    out["successAfterFailures"] = bool(m)
    if m:
        ev["successAfterFailures"] = "a successful login followed repeated failures"
    elif re.search(r"(then|after)[^.\n]{0,40}(success|logged in|accepted)", text, re.I) and fails >= 3:
        out["successAfterFailures"] = True
        ev["successAfterFailures"] = "text describes a success after failures"

    # Password spraying (T1110.003) = one source trying REAL accounts. If (almost) every username it tried does
    # not exist, it is a bot guessing default names (oracle, test, pi...) -- password guessing, not spraying.
    best = max((len(v) for src, v in users.items() if len(v - invalid_users[src]) >= 2), default=0)
    out["distinctFailedUsers"] = best
    if best >= 5:
        real = max(len(v - invalid_users[src]) for src, v in users.items() if len(v) == best)
        ev["distinctFailedUsers"] = f"{best} different usernames failed from one source ({real} of them real accounts)"
    out["sources"] = len(srcs)
    out["invalidUserAttempts"] = invalid
    if invalid:
        ev["invalidUserAttempts"] = f"{invalid} attempt(s) on accounts that do not exist"

    logins.sort(key=lambda x: x[0])
    for (t1, g1, p1), (t2, g2, p2) in zip(logins, logins[1:]):
        if p1 == p2:
            continue
        hours = abs((t2 - t1).total_seconds()) / 3600
        dist = _km(g1, g2)
        if dist > 500 and dist / max(hours, 0.01) > 900:   # faster than a plane
            out["impossibleTravel"] = True
            ev["impossibleTravel"] = f"{p1} -> {p2} ({dist:,.0f} km in {hours:.1f} h)"
            break
    if not out["impossibleTravel"] and TRAVEL_WORD_RE.search(text):
        out["impossibleTravel"] = True
        ev["impossibleTravel"] = f"\"{TRAVEL_WORD_RE.search(text).group(0)}\""

    for key, rx in [("newDevice", NEW_DEVICE_RE), ("anonymizingNetwork", ANON_RE), ("passwordResetRecent", PWRESET_RE),
                    ("mfaChanged", MFA_RE), ("privilegeEscalation", PRIV_RE), ("recoveryChanged", RECOVERY_RE),
                    ("forwardingRule", FORWARD_RE), ("newCredentialCreated", TOKEN_RE), ("massDownload", EXFIL_RE),
                    ("unusualLocation", UNUSUAL_LOC_RE)]:
        m = rx.search(text)
        if m:
            out[key] = True
            ev[key] = f"\"{m.group(0).strip()[:60]}\""
    if odd_hour or UNUSUAL_HOUR_RE.search(text):
        out["unusualHour"] = True
        ev["unusualHour"] = "login time between 00:00 and 05:00" if odd_hour else "text says off-hours"
    return out


# ---------------------------------------------------------------------------
# Trained risk model (RBA login dataset) -- optional; rules work without it
# ---------------------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "ato_rba_model.joblib")
_model_cache: dict = {}
UA_RE = re.compile(r"(Mozilla/\S+(?: \([^)]*\))?(?: [A-Za-z]+/[\w.]+)*|python-requests/\S+|curl/\S+|okhttp/\S+|Go-http-client/\S+|"
                   r"(?:user[-_ ]?agent|device|browser)\s*[=:]\s*\"?[^\",;]+)", re.I)
COUNTRY_RE = re.compile(r"\bcountry(?:[ _]?code)?\s*[=:]\s*\"?([A-Za-z]{2})\b", re.I)
ASN_RE = re.compile(r"\b(?:asn\s*[=:]\s*\"?(?:AS)?|AS)(\d{2,7})\b", re.I)
# country for the places the log parser knows, so "Mumbai ... London" also counts as a country change
PLACE_COUNTRY = {
    "mumbai": "IN", "delhi": "IN", "new delhi": "IN", "bhubaneswar": "IN", "bengaluru": "IN", "bangalore": "IN",
    "kolkata": "IN", "chennai": "IN", "hyderabad": "IN", "pune": "IN", "india": "IN", "london": "GB", "uk": "GB",
    "united kingdom": "GB", "paris": "FR", "berlin": "DE", "germany": "DE", "moscow": "RU", "russia": "RU",
    "kyiv": "UA", "ukraine": "UA", "lagos": "NG", "nigeria": "NG", "new york": "US", "usa": "US",
    "united states": "US", "california": "US", "san francisco": "US", "toronto": "CA", "canada": "CA",
    "singapore": "SG", "tokyo": "JP", "japan": "JP", "beijing": "CN", "china": "CN", "hong kong": "HK",
    "dubai": "AE", "uae": "AE", "sydney": "AU", "australia": "AU", "sao paulo": "BR", "brazil": "BR",
    "pakistan": "PK", "karachi": "PK", "dhaka": "BD", "bangladesh": "BD", "pyongyang": "KP", "north korea": "KP",
    "tehran": "IR", "iran": "IR",
}
_SSH_USER_RE = re.compile(r"(?:accepted|failed)\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)", re.I)


def _load_model():
    """Load the trained RBA risk model, reloading if the file changes. None if missing, old or broken."""
    if not os.path.exists(MODEL_PATH):
        _model_cache.clear()
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _model_cache.get("mtime") != mtime:
        try:
            import joblib
            model = rba_risk.RBAModel(joblib.load(MODEL_PATH))
        except Exception:
            model = None    # not an RBA bundle (e.g. an old model file) -- refuse rather than mis-score
        _model_cache.update(mtime=mtime, model=model)
    return _model_cache.get("model")


def events_from_log(text: str) -> list[rba_risk.LoginEvent]:
    """Turn pasted log lines into login events (time, account, IP, success, country, ASN, device)."""
    events, fallback = [], 1_000_000_000.0
    for ln in re.split(r"[\r\n]+", text or ""):
        is_fail = bool(FAIL_RE.search(ln))
        is_ok = bool(OK_RE.search(ln)) and not is_fail
        if not (is_fail or is_ok):
            continue
        ts = _parse_ts(ln)
        t = ts.replace(tzinfo=timezone.utc).timestamp() if ts else fallback
        fallback = t + 1
        user = None
        for rx in (_SSH_USER_RE,) + tuple(USER_RES):
            m = rx.search(ln)
            if m:
                user = m.group(1).strip("'\"[]()").lower()
                break
        ips = IP_RE.findall(ln)
        gm, cm, am, um = _GEO_RE.search(ln), COUNTRY_RE.search(ln), ASN_RE.search(ln), UA_RE.search(ln)
        country = cm.group(1).upper() if cm else (PLACE_COUNTRY.get(gm.group(1).lower()) if gm else None)
        events.append(rba_risk.LoginEvent(
            ts=t, user=user or "unknown-user", ip=ips[0] if ips else None, success=is_ok,
            country=country, city=gm.group(1).title() if gm else None, asn=am.group(1) if am else None,
            ua=um.group(0).strip()[:200] if um else None, user_unknown=bool(INVALID_USER_RE.search(ln))))
    events.sort(key=lambda e: e.ts)
    return events


def model_assessment(text: str):
    """Score each login in the pasted log with the RBA risk model; return the riskiest one."""
    model = _load_model()
    if model is None:
        return None
    events = events_from_log(text)
    if not events:
        return None
    scored = model.assess(events)
    top = max(r["percentile"] for r in scored)
    # the latest login within 0.5 points of the top: it has the most history behind it, so clearer reasons
    best = [r for r in scored if r["percentile"] >= top - 0.5][-1]
    return {**best, "alert": model.alert, "medium": model.medium, "events": len(scored),
            "flagged": sum(r["flagged"] for r in scored), "elevatedCount": sum(r["elevated"] for r in scored),
            "level": "high" if best["flagged"] else "medium" if best["elevated"] else "low",
            "withHistory": sum(r["historyPercentile"] is not None for r in scored)}


# ---------------------------------------------------------------------------
# Per-subtopic trained models (one model per credential subtopic, see
# app/ml/training/train_credential_subtopics.py). Same features as training: credential_features.py
# ---------------------------------------------------------------------------
SUBTOPIC_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models")
_sub_cache: dict = {}
SUBTOPIC_INFO = {
    # subtopic: (short name used in the result, MITRE technique)
    "failed-logins": ("Brute-force model", "T1110.001"),
    "password-spraying": ("Password-spraying model", "T1110.003"),
    "unusual-location": ("Unusual-location model", "T1078"),
    "unknown-device": ("Unknown-device model", "T1078"),
    "session-activity": ("Session-hijack model", "T1078"),
    "behavior-changes": ("Behaviour-change model", "T1078"),
}


def _load_subtopic_model(subtopic: str):
    path = os.path.join(SUBTOPIC_MODEL_DIR, f"cred_{subtopic}.joblib")
    if subtopic not in SUBTOPIC_INFO or not os.path.exists(path):
        _sub_cache.pop(subtopic, None)
        return None
    mtime = os.path.getmtime(path)
    cached = _sub_cache.get(subtopic)
    if not cached or cached[0] != mtime:
        try:
            import joblib
            b = joblib.load(path)
            ok = isinstance(b, dict) and b.get("kind") == "cyberguard-credential-subtopic" and b.get("subtopic") == subtopic
            from app.detectors import credential_features as CF
            ok = ok and list(b["features"]) == list(CF.SUBTOPICS[subtopic][0])   # features must match this code
            b = {**b, "tables_obj": CF.Tables(b["tables"])} if ok else None
        except Exception:
            b = None
        _sub_cache[subtopic] = (mtime, b)
    return _sub_cache[subtopic][1]


def _fmt_h(hours: float) -> str:
    return f"{hours * 60:.0f} min" if hours < 1 else f"{hours:.1f} h" if hours < 48 else f"{hours / 24:.0f} days"


def _subtopic_reasons(subtopic: str, e, f: dict) -> list[str]:
    """Plain-language reasons from the features the model looked at (only the ones that point to an attack)."""
    r = []
    who = f"'{e.user}'" if e.user and e.user != "unknown-user" else "the account"
    if subtopic == "failed-logins":
        if f["fail_1h"] >= 2:
            r.append(f"{int(f['fail_1h'])} failed attempts on {who} within one hour")
        if f["consec_fail"] >= 3:
            r.append(f"{int(f['consec_fail'])} failures in a row")
        if f["success_after_fails"] >= 1:
            r.append(f"a successful login right after {int(f['success_after_fails'])} failure(s)")
        if f["ips_1h"] >= 2:
            r.append(f"attempts came from {int(f['ips_1h'])} different IP addresses")
        if f["att_1h"] >= 3 and f["min_gap_1h"] < 5:
            r.append("attempts only seconds apart (an automated tool)")
        if f["ip_new"] == 1:
            r.append(f"IP {e.ip} was never used for a successful login on this account")
    elif subtopic == "password-spraying":
        if f["users_24h"] >= 2:
            r.append(f"{int(f['users_24h'])} different accounts tried from {e.ip or 'one source'}")
        if f["users_only_failed_24h"] >= 2:
            r.append(f"{int(f['users_only_failed_24h'])} of them only failed")
        if f["unknown_user_24h"] >= 1:
            r.append(f"{int(f['unknown_user_24h'])} attempt(s) on accounts that do not exist")
        if f["users_24h"] >= 3 and f["att_per_user_24h"] <= 2:
            r.append("only 1-2 tries per account (low-and-slow, to avoid lockouts)")
        if f["bot_ua"] == 1:
            r.append("an automated tool's user agent")
    elif subtopic == "unusual-location":
        if f["country_new"] == 1:
            r.append(f"country {e.country} never used by {who} before")
        if f["asn_new"] == 1:
            r.append(f"network AS{e.asn} never used before")
        if f["ip16_new"] == 1:
            r.append(f"IP range of {e.ip} never used before")
        elif f["ip_new"] == 1:
            r.append(f"IP {e.ip} never used before")
        if f["fast_country_change"] == 1:
            r.append(f"country changed within {_fmt_h(math.expm1(f['hours_since_last']))} of the previous login")
    elif subtopic == "unknown-device":
        from app.detectors.credential_features import parse_ua
        b, bv, o, ov, d, bot = parse_ua(e.ua)
        if f["is_bot"] == 1:
            r.append("the user agent belongs to an automated tool, not a person's browser")
        if f["ofam_new"] == 1 and o != "other":
            r.append(f"operating system {o} never used by {who} before")
        elif f["over_new"] == 1 and ov != "other":
            r.append(f"{ov} never used before")
        if f["bfam_new"] == 1 and b != "other":
            r.append(f"browser {b} never used before")
        elif f["ua_new"] == 1:
            r.append("this exact browser/device was never seen before")
        if f["dtype_new"] == 1:
            r.append(f"device type '{d}' never used before")
    elif subtopic == "session-activity":
        if f["minutes_since_prev"] != -1:
            r.append(f"a second login {math.expm1(f['minutes_since_prev']):.0f} min after the previous one")
        if f["same_ip_prev"] == 0:
            r.append("from a different IP address")
        if f["same_country_prev"] == 0:
            r.append(f"from a different country ({e.country})")
        if f["same_ua_prev"] == 0:
            r.append("with a different browser/device")
        if f["ips_2h"] >= 3:
            r.append(f"{int(f['ips_2h'])} IP addresses used within 2 hours")
    elif subtopic == "behavior-changes":
        if f["hour_dev"] >= 4:
            r.append(f"login time is {f['hour_dev']:.0f} h away from this account's usual hours")
        if f["weekday_seen"] == 0:
            r.append("a weekday this account never logs in on")
        if f["n_changed"] >= 2:
            r.append(f"{int(f['n_changed'])} things changed at once (country, network, device...)")
        if f["rate_ratio_24h"] >= 1.5:
            r.append("far more logins in the last day than usual")
        if f["fail_rate_change"] >= 0.3:
            r.append("many more failed attempts than usual")
    return r


def subtopic_assessment(subtopic: str, text: str):
    """Score a pasted log with the trained model of ONE credential subtopic; return its riskiest login."""
    b = _load_subtopic_model(subtopic)
    if b is None:
        return None
    from app.detectors import credential_features as CF
    events = events_from_log(text)
    if not events:
        return None
    rows = list(CF.score_events(subtopic, events, b["tables_obj"]))
    if not rows:
        return None
    import numpy as np
    probs = b["model"].predict_proba(np.array([x for _, x in rows], dtype=float))[:, 1]
    top = float(probs.max())
    i = max(j for j, p in enumerate(probs) if p >= top - 1e-9)       # the latest of the riskiest logins
    e, x = rows[i]
    feats = dict(zip(b["features"], x))
    level = "high" if top >= b["thr_alert"] else "medium" if top >= b["thr_verify"] else "low"
    return {"subtopic": subtopic, "probability": top, "level": level, "event": e, "features": feats,
            "reasons": _subtopic_reasons(subtopic, e, feats), "scored": len(rows),
            "flagged": int((probs >= b["thr_alert"]).sum()), "thrAlert": b["thr_alert"], "thrVerify": b["thr_verify"],
            "trainedAt": b.get("trained_at")}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
# Attack chains: a chain fires when ALL `needs` signals are present, and sets a minimum score.
_CHAINS = [
    ("Brute force succeeded", ["failedAttempts>=5", "successAfterFailures"], 90,
     "Many failed logins were followed by a successful one -- the attacker most likely guessed the password."),
    ("Account taken over: login anomaly + credential change", ["anomalousLogin", "credentialChange"], 85,
     "A suspicious sign-in was followed by an MFA / password / recovery change -- classic account takeover."),
    ("Persistence set up after suspicious login", ["anomalousLogin", "persistence"], 85,
     "Mail forwarding, a new API token / OAuth app, or admin rights appeared after an anomalous login."),
    ("Impossible travel with new device", ["impossibleTravel", "newDevice"], 75,
     "The same account signed in from two distant places, and one device was never seen before."),
    ("Impossible travel + MFA change", ["impossibleTravel", "mfaChanged"], 90,
     "Impossible travel with an MFA change is almost always a takeover."),
    ("Password spraying", ["spraying"], 75,
     "One source tried failures against many different accounts -- a spraying attack."),
    ("Data theft after login", ["anomalousLogin", "massDownload"], 80,
     "A bulk download followed an anomalous login -- data is probably being stolen."),
]


def analyze_event(fields: dict, subtopic_title: str = "Credential Theft & Account Takeover", text: str = "",
                  subtopic_id: str | None = None) -> dict:
    fields = fields or {}
    parsed = parse_log(text or "")
    ev = parsed["evidence"]

    def gi(key):
        try:
            return int(float(fields.get(key, 0) or 0))
        except (ValueError, TypeError):
            return 0

    def gb(key):
        return str(fields.get(key, "")).strip().lower() in ("1", "true", "yes", "y")

    failed = max(gi("failedAttempts"), parsed["failedAttempts"])
    keys = ["impossibleTravel", "newDevice", "anonymizingNetwork", "passwordResetRecent", "mfaChanged",
            "privilegeEscalation", "unusualHour", "unusualLocation", "recoveryChanged", "forwardingRule",
            "newCredentialCreated", "massDownload", "successAfterFailures"]
    s = {k: gb(k) or parsed[k] for k in keys}
    spraying = parsed["distinctFailedUsers"] >= 5 or gb("passwordSpraying")
    brute = failed >= 15 and not spraying

    indicators = []

    def add(triggered, label, desc, severity, weight, mitre, key=None):
        if triggered and key and key in ev:
            desc += f" Evidence: {ev[key]}."
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                           "triggered": bool(triggered), "mitre": mitre, "id": f"IND_{uuid.uuid4().hex[:12]}"})

    add(failed >= 5, "Multiple failed login attempts",
        f"{failed} failed authentication attempt(s) recorded.", "high", 20, "T1110", "failedAttempts")
    add(brute, "Brute-force pattern", "Failed-attempt volume fits an automated brute-force attack on one account.",
        "critical", 25, "T1110.001")
    add(spraying, "Password spraying",
        f"{parsed['distinctFailedUsers']} different usernames failed from one source -- low-and-slow spraying across accounts.",
        "critical", 40, "T1110.003", "distinctFailedUsers")
    add(s["successAfterFailures"], "Successful login after repeated failures",
        "A login succeeded right after a run of failures -- the attacker may have found the password.",
        "critical", 40, "T1110", "successAfterFailures")
    add(s["impossibleTravel"], "Impossible travel", "Logins from places too far apart for the elapsed time.",
        "critical", 40, "T1078", "impossibleTravel")
    add(s["unusualLocation"] and not s["impossibleTravel"], "Login from unusual location",
        "Sign-in from a place this account does not normally use.", "high", 18, "T1078", "unusualLocation")
    add(s["newDevice"], "Unrecognized device", "Device does not match any previously trusted device.",
        "high", 22, "T1078", "newDevice")
    add(s["anonymizingNetwork"], "Anonymizing network", "Connection comes from a VPN / proxy / Tor exit.",
        "medium", 14, "T1090", "anonymizingNetwork")
    add(s["passwordResetRecent"], "Password reset / change", "Password was reset or changed around this event.",
        "high", 25, "T1098", "passwordResetRecent")
    add(s["mfaChanged"], "MFA settings changed",
        "Multi-factor settings were modified -- attackers do this to lock the owner out.", "critical", 38, "T1556", "mfaChanged")
    add(s["recoveryChanged"], "Recovery email/phone changed",
        "Recovery details changed -- lets an attacker take permanent control.", "critical", 32, "T1098", "recoveryChanged")
    add(s["privilegeEscalation"], "Privilege escalation", "Account permissions were raised.", "critical", 38, "T1078.003", "privilegeEscalation")
    add(s["forwardingRule"], "Mail forwarding / inbox rule", "Mail is being silently copied elsewhere.", "critical", 38, "T1114.003", "forwardingRule")
    add(s["newCredentialCreated"], "New API key / token / OAuth app", "A new way to access the account without a password was created.",
        "high", 28, "T1098.001", "newCredentialCreated")
    add(s["massDownload"], "Bulk data download", "Large download/export of data in the session.", "critical", 32, "T1530", "massDownload")
    add(parsed["invalidUserAttempts"] >= 3, "Logins to accounts that do not exist",
        f"{parsed['invalidUserAttempts']} attempts used usernames that do not exist -- an automated tool guessing "
        "common/default account names (password guessing). In the RBA dataset (31M real-world logins) such attempts "
        "came from attacker IPs 1.5x as often as attempts on real accounts.", "medium", 25, "T1110.001", "invalidUserAttempts")
    add(s["unusualHour"], "Unusual login hour", "Login outside the account's normal hours.", "low", 10, "T1078", "unusualHour")

    score = sum(i["weight"] for i in indicators if i["triggered"])
    triggered = [i for i in indicators if i["triggered"]]

    anomalous = s["impossibleTravel"] or s["newDevice"] or s["unusualLocation"] or s["anonymizingNetwork"] or s["successAfterFailures"]
    cred_change = s["mfaChanged"] or s["passwordResetRecent"] or s["recoveryChanged"]
    persistence = s["forwardingRule"] or s["newCredentialCreated"] or s["privilegeEscalation"]
    state = {"failedAttempts>=5": failed >= 5, "successAfterFailures": s["successAfterFailures"],
             "anomalousLogin": anomalous, "credentialChange": cred_change, "persistence": persistence,
             "impossibleTravel": s["impossibleTravel"], "newDevice": s["newDevice"], "mfaChanged": s["mfaChanged"],
             "spraying": spraying, "massDownload": s["massDownload"]}
    chains, floor = [], 0
    for name, needs, fl, desc in _CHAINS:
        if all(state[n] for n in needs):
            chains.append((name, desc))
            floor = max(floor, fl)
    for name, desc in chains:
        indicators.append({"label": f"Attack chain: {name}", "description": desc, "severity": "critical", "weight": 0,
                           "triggered": True, "mitre": "", "id": f"IND_{uuid.uuid4().hex[:12]}"})
    score = max(min(100, score), floor)

    # Trained RBA risk model: can RAISE the risk (it compares each login with the account's own earlier
    # logins and with known attacker sources); it never lowers what the rules found.
    sub = subtopic_assessment(subtopic_id, text) if (text and subtopic_id in SUBTOPIC_INFO) else None
    ml = None if sub else (model_assessment(text) if text else None)
    if sub:
        name, technique = SUBTOPIC_INFO[subtopic_id]
        e, p = sub["event"], sub["probability"]
        who = f"login{' attempt' if not e.success else ''} for '{e.user}'" + (f" from {e.ip}" if e.ip else "")
        level = sub["level"]
        reasons = "; ".join(sub["reasons"]) or "the combination of signals in the log"
        indicators.append({
            "label": {"high": f"{name}: attack pattern detected", "medium": f"{name}: unusual - verify the user",
                      "low": f"{name}: looks normal"}[level],
            "severity": "critical" if level == "high" and p >= 0.9 else {"high": "high", "medium": "medium", "low": "low"}[level],
            "description": (f"The trained {name.lower()} (gradient-boosted trees, trained on the 31M-login RBA dataset) "
                            f"rates the riskiest {who} at {p * 100:.0f}% attack likelihood "
                            f"(alert level {sub['thrAlert'] * 100:.0f}%, which only 1% of normal logins reach). "
                            f"{sub['flagged']} of {sub['scored']} scored event(s) are above the alert level. "
                            f"Main reasons: {reasons}."),
            "weight": 0, "triggered": level != "low", "mitre": technique, "id": f"IND_{uuid.uuid4().hex[:12]}"})
        if level == "high":
            span = max(1 - sub["thrAlert"], 1e-6)
            score = max(score, min(100, 71 + round(29 * (p - sub["thrAlert"]) / span)))
        elif level == "medium":
            span = max(sub["thrAlert"] - sub["thrVerify"], 1e-6)
            score = max(score, min(70, 51 + round(19 * (p - sub["thrVerify"]) / span)))
        triggered = [i for i in indicators if i["triggered"]]
    if ml:
        e, pct = ml["event"], ml["percentile"]
        reasons = "; ".join(ml["reasons"]) or "its combination of location, network and device"
        who = f"login for '{e.user}'" + (f" from {e.ip}" if e.ip else "")
        sides = []
        if ml["historyPercentile"] is not None:
            sides.append(f"vs this account's history: riskier than {ml['historyPercentile']:.1f}% of normal logins")
        if ml["reputationPercentile"] is not None:
            sides.append(f"vs known attacker sources: riskier than {ml['reputationPercentile']:.1f}%")
        level = ml["level"]
        indicators.append({
            "label": {"high": "Risk-based authentication model: high-risk login",
                      "medium": "Risk-based authentication model: unusual login - verify the user (e.g. OTP)",
                      "low": "Risk-based authentication model"}[level],
            "severity": "critical" if pct >= 99.9 else {"high": "high", "medium": "medium", "low": "low"}[level],
            "description": (f"The RBA risk model (trained on the 31M-login RBA dataset) rates the {who} as riskier than "
                            f"{pct:.1f}% of normal logins ({'; '.join(sides) or 'no history or location/device data in the log'}). "
                            f"{ml['flagged']} of {ml['events']} logins are above the alert level ({ml['alert']:g}th percentile), "
                            f"{ml['elevatedCount']} above the verify level ({ml['medium']:g}th). "
                            + ("The account has little history yet, so the model asks for verification rather than "
                               "raising an alert. " if level == "medium" else "") +
                            f"Main reasons: {reasons}."),
            "weight": 0, "triggered": level != "low", "mitre": "T1078", "id": f"IND_{uuid.uuid4().hex[:12]}"})
        if level == "high":
            score = max(score, round(0.6 * pct + 0.4 * min(score, 100)))
        elif level == "medium":    # 95th -> 40, 99th -> 55 ("low risk / suspicious": step-up verification)
            score = max(score, round(40 + (pct - ml["medium"]) * 15 / max(ml["alert"] - ml["medium"], 1)))
        triggered = [i for i in indicators if i["triggered"]]

    if not triggered:
        explanation = ("No account-security signals were found. Paste login/session log lines (or describe what "
                       "happened) or fill in the signal fields for a meaningful assessment.")
        confidence = 20 if not (text or fields) else 60
    else:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        explanation = f"Flagged {len(triggered)} signal(s), most notably: {names}."
        if chains:
            explanation += f" Attack chain detected: {chains[0][0]}."
        confidence = 55 + min(len(triggered) * 6, 30) + (10 if chains else 0)

    result = build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Account Takeover Engine — Log Parser + Attack-Chain Rules"
                    + (f" + {SUBTOPIC_INFO[subtopic_id][0]} (RBA-dataset trained)" if sub else "")
                    + (" + RBA Risk Model (RBA-dataset trained)" if ml else ""),
        threat_type=subtopic_title, explanation=explanation,
    )
    result["parsedSignals"] = {k: v for k, v in parsed.items() if k != "evidence" and v}
    if sub:
        result["subtopicModel"] = {"subtopic": subtopic_id, "model": SUBTOPIC_INFO[subtopic_id][0],
                                   "probability": round(sub["probability"], 4), "level": sub["level"],
                                   "alertThreshold": round(sub["thrAlert"], 4), "verifyThreshold": round(sub["thrVerify"], 4),
                                   "eventsScored": sub["scored"], "eventsFlagged": sub["flagged"],
                                   "reasons": sub["reasons"], "trainedAt": sub["trainedAt"]}
    if ml:
        result["modelAssessment"] = {"percentile": round(ml["percentile"], 1), "level": ml["level"],
                                     "verifyPercentile": ml["medium"],
                                     "historyPercentile": None if ml["historyPercentile"] is None else round(ml["historyPercentile"], 1),
                                     "reputationPercentile": None if ml["reputationPercentile"] is None else round(ml["reputationPercentile"], 1),
                                     "alertPercentile": ml["alert"], "loginsScored": ml["events"],
                                     "loginsFlagged": ml["flagged"], "loginsWithHistory": ml["withHistory"],
                                     "reasons": ml["reasons"]}
    return result