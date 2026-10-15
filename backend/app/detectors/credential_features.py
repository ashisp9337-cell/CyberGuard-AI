"""
Features for the six Credential Theft & Account Takeover subtopic models.

The SAME code turns login events into numbers in two places:
  * training  (app/ml/training/train_credential_subtopics.py) -- events come from the RBA login dataset
  * scanning  (app/detectors/account_takeover.py)              -- events come from the log the user pastes
so a model always sees exactly the kind of numbers it was trained on.

A login event is an object with: ts (unix seconds), user, ip, success, country, region, city, asn,
ua (user-agent string), user_unknown (login to an account that does not exist).
Any field may be missing (None); "unknown" is then encoded as -1 so the model can tell
"not new" (0) from "we don't know" (-1).

Subtopic        unit that is scored               what the features describe
---------------------------------------------------------------------------------------------------
failed-logins   each login attempt of an account  failures in the last hour/day for that account,
                                                  runs of failures, success right after failures,
                                                  how many IPs/countries/devices were involved
password-spray  each attempt from one IP          how many different accounts one IP tried, how many
                                                  failed or did not exist, how fast
unusual-loc.    each successful login             country/region/city/network/IP never used by this
                                                  account before, how fast the country changed
unknown-device  each successful login             browser/OS/device type never used before, bot-like
                                                  user agent, how many devices the account uses
session         each successful login shortly     a second login from a different IP/country/device
                after another                     while the first session is still active
behaviour       each successful login             login hour, weekday, gap and frequency compared
                                                  with the account's own habits, how many things
                                                  changed at once
"""
from __future__ import annotations

import math
import re
from collections import Counter, deque
from functools import lru_cache

HOUR, DAY = 3600.0, 86400.0
UNK = -1.0

# ---------------------------------------------------------------------------
# User agent -> browser family / version, OS family / version, device type, bot flag
# ---------------------------------------------------------------------------
_BOT_RE = re.compile(r"(bot\b|bot/|crawler|spider|curl/|wget/|python-requests|python-urllib|go-http-client|okhttp|"
                     r"java/|libwww|httpclient|scrapy|headless|phantomjs|nslookup|zgrab|masscan|nmap)", re.I)
_BROWSERS = [("Edge", r"Edg(?:e|A|iOS)?/(\d+)"), ("Opera", r"(?:OPR|Opera)[/ ](\d+)"),
             ("Samsung", r"SamsungBrowser/(\d+)"), ("Firefox", r"(?:Firefox|FxiOS)/(\d+)"),
             ("Chrome", r"(?:Chrome|CriOS)/(\d+)"), ("Safari", r"Version/(\d+).*Safari"),
             ("IE", r"(?:MSIE |Trident/.*rv:)(\d+)")]
_OSES = [("Windows Phone", r"Windows Phone(?: OS)? (\d+)"), ("Windows", r"Windows NT (\d+)"),
         ("iOS", r"(?:iPhone|iPad|iPod).*?OS (\d+)"), ("Android", r"Android (\d+)"),
         ("Mac OS X", r"Mac OS X (\d+)"), ("Chrome OS", r"CrOS"), ("Linux", r"Linux")]
_BROWSERS = [(n, re.compile(p, re.I)) for n, p in _BROWSERS]
_OSES = [(n, re.compile(p, re.I)) for n, p in _OSES]


@lru_cache(maxsize=200_000)
def parse_ua(ua: str | None) -> tuple[str | None, str | None, str | None, str | None, str | None, int]:
    """(browser family, browser 'family major', os family, os 'family major', device type, is_bot)."""
    if not ua:
        return None, None, None, None, None, 0
    bot = int(bool(_BOT_RE.search(ua)))
    bfam = bver = ofam = over = None
    for name, rx in _BROWSERS:
        m = rx.search(ua)
        if m:
            bfam, bver = name, f"{name} {m.group(1)}" if m.groups() else name
            break
    for name, rx in _OSES:
        m = rx.search(ua)
        if m:
            ofam = name
            over = f"{name} {m.group(1)}" if m.groups() else name
            break
    low = ua.lower()
    if bot:
        dtype = "bot"
    elif "ipad" in low or "tablet" in low:
        dtype = "tablet"
    elif any(k in low for k in ("mobile", "iphone", "android", "windows phone")):
        dtype = "mobile"
    else:
        dtype = "desktop"
    return bfam or "other", bver or "other", ofam or "other", over or "other", dtype, bot


def _ip16(ip: str | None) -> str | None:
    if not ip or "." not in ip:
        return None
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) == 4 else None


def _new(counter: Counter, value) -> float:
    """1 = never seen in this history, 0 = seen, -1 = value unknown."""
    if value is None or value == "":
        return UNK
    return 0.0 if counter.get(value) else 1.0


def _share(counter: Counter, value, total: int) -> float:
    if value is None or value == "" or total <= 0:
        return UNK
    return counter.get(value, 0) / total


def _lg(x: float) -> float:
    return math.log1p(max(0.0, x))


def _hour_of(ts: float) -> float:
    return (ts % DAY) / HOUR


def _circ(h1: float, h2: float) -> float:
    d = abs(h1 - h2) % 24
    return min(d, 24 - d)


# ---------------------------------------------------------------------------
# Global tables learned from the TRAINING part of the data only (how often attackers use a value)
# ---------------------------------------------------------------------------
class Tables:
    """Smoothed attack rate and log-frequency per value of a field (country, ASN, browser family, ...)."""

    def __init__(self, data: dict | None = None):
        self.data = data or {}       # field -> {"rate": {value: rate}, "count": {value: n}, "prior": p}

    def rate(self, field: str, value) -> float:
        t = self.data.get(field)
        if not t or value is None or value == "":
            return UNK
        return t["rate"].get(str(value), t["prior"])

    def freq(self, field: str, value) -> float:
        t = self.data.get(field)
        if not t or value is None or value == "":
            return UNK
        return _lg(t["count"].get(str(value), 0))

    @staticmethod
    def build(rows, fields, smoothing: float = 50.0) -> "Tables":
        """rows: iterable of (field_values: dict, is_attack: bool)."""
        cnt = {f: Counter() for f in fields}
        att = {f: Counter() for f in fields}
        n = a = 0
        for vals, is_attack in rows:
            n += 1
            a += bool(is_attack)
            for f in fields:
                v = vals.get(f)
                if v is None or v == "":
                    continue
                cnt[f][str(v)] += 1
                if is_attack:
                    att[f][str(v)] += 1
        prior = a / max(n, 1)
        data = {}
        for f in fields:
            data[f] = {"prior": prior, "count": dict(cnt[f]),
                       "rate": {v: (att[f][v] + smoothing * prior) / (c + smoothing) for v, c in cnt[f].items()}}
        return Tables(data)


# ---------------------------------------------------------------------------
# Account history (built from an account's earlier logins)
# ---------------------------------------------------------------------------
class AccountHistory:
    """What we know about one account from its earlier logins. "Known" places/devices come from
    SUCCESSFUL logins only (an attacker's failed attempts must not make his country look familiar)."""

    def __init__(self):
        self.ok = 0
        self.attempts = 0
        self.fails = 0
        self.known = {k: Counter() for k in ("country", "region", "city", "asn", "ip", "ip16", "ua",
                                              "bfam", "bver", "ofam", "over", "dtype")}
        self.hours = Counter()
        self.weekdays = Counter()
        self.gaps: deque = deque(maxlen=50)
        self.last_ok = None            # last successful event (with parsed UA)
        self.first_ts = None
        self.recent: deque = deque()   # (ts, success, ip, country, asn, ua) of every attempt, last 24 h

    def _trim(self, now: float):
        while self.recent and now - self.recent[0][0] > DAY:
            self.recent.popleft()

    def add(self, e):
        self.attempts += 1
        self.fails += 0 if e.success else 1
        if self.first_ts is None:
            self.first_ts = e.ts
        self.recent.append((e.ts, e.success, e.ip, e.country, e.asn, e.ua))
        self._trim(e.ts)
        if not e.success:
            return
        b, bv, o, ov, d, _ = parse_ua(e.ua)
        vals = {"country": e.country, "region": e.region, "city": e.city, "asn": e.asn, "ip": e.ip,
                "ip16": _ip16(e.ip), "ua": e.ua, "bfam": b, "bver": bv, "ofam": o, "over": ov, "dtype": d}
        for k, v in vals.items():
            if v:
                self.known[k][v] += 1
        if self.last_ok is not None:
            self.gaps.append(e.ts - self.last_ok[0].ts)
        self.hours[int(_hour_of(e.ts))] += 1
        self.weekdays[int(e.ts // DAY + 4) % 7] += 1
        self.ok += 1
        self.last_ok = (e, vals)


def _window(recent, now: float, span: float):
    return [r for r in recent if now - r[0] <= span]


# ---------------------------------------------------------------------------
# Subtopic feature functions. Each gets the account/IP history BEFORE the event, and the event.
# ---------------------------------------------------------------------------
FAILED_FEATURES = ["att_1h", "fail_1h", "fail_ratio_1h", "att_24h", "fail_24h", "consec_fail", "success_after_fails",
                   "ips_1h", "countries_1h", "asn_1h", "ua_1h", "min_gap_1h", "median_gap_1h", "ip_new",
                   "hist_ok", "hist_fail_rate", "this_success",
                   "country_new", "asn_new", "ip16_new", "ua_new", "ofam_new", "is_bot",
                   "country_rate", "asn_rate", "bver_rate", "over_rate"]


def failed_features(h: AccountHistory, e, t: Tables) -> list[float]:
    rec = [r for r in h.recent if e.ts - r[0] <= DAY] + [(e.ts, e.success, e.ip, e.country, e.asn, e.ua)]
    w1 = [r for r in rec if e.ts - r[0] <= HOUR]
    fails1 = sum(not r[1] for r in w1)
    consec = 0
    for r in reversed(rec[:-1]):
        if r[1]:
            break
        consec += 1
    gaps = sorted(b[0] - a[0] for a, b in zip(w1, w1[1:]))
    known_ip = _new(h.known["ip"], e.ip) if h.ok else UNK
    return [len(w1), fails1, fails1 / len(w1), len(rec), sum(not r[1] for r in rec), consec + (0 if e.success else 1),
            float(consec) if e.success else 0.0,
            len({r[2] for r in w1 if r[2]}), len({r[3] for r in w1 if r[3]}), len({r[4] for r in w1 if r[4]}),
            len({r[5] for r in w1 if r[5]}),
            gaps[0] if gaps else HOUR, gaps[len(gaps) // 2] if gaps else HOUR, known_ip,
            _lg(h.ok), h.fails / h.attempts if h.attempts else UNK, float(e.success)] + _origin(h, e, t)


def _origin(h: AccountHistory, e, t: Tables) -> list[float]:
    """Where an attempt comes from, compared with the account's normal (successful) logins, plus how often
    attackers use that country / network / browser version / OS version."""
    k = h.known
    b, bv, o, ov, d, bot = parse_ua(e.ua)
    if h.ok:
        nov = [_new(k["country"], e.country), _new(k["asn"], e.asn), _new(k["ip16"], _ip16(e.ip)),
               _new(k["ua"], e.ua), _new(k["ofam"], o)]
    else:
        nov = [UNK] * 5
    return nov + [float(bot) if e.ua else UNK, t.rate("country", e.country), t.rate("asn", e.asn),
                  t.rate("bver", bv), t.rate("over", ov)]


class IPHistory:
    def __init__(self):
        self.recent: deque = deque()   # (ts, user, success, unknown_user, ua, country)

    def add(self, e):
        self.recent.append((e.ts, e.user, e.success, bool(getattr(e, "user_unknown", False)), e.ua,
                            getattr(e, "country", None)))
        while self.recent and e.ts - self.recent[0][0] > DAY:
            self.recent.popleft()


SPRAY_FEATURES = ["users_1h", "users_24h", "att_1h", "att_24h", "fail_1h", "fail_24h", "fail_ratio_24h",
                  "unknown_user_24h", "unknown_share_24h", "users_only_failed_24h", "att_per_user_24h",
                  "ok_users_24h", "ua_24h", "min_gap_1h", "median_gap_24h", "bot_ua",
                  "ua_per_attempt_24h", "os_families_24h", "bver_rate", "over_rate", "dtype_rate",
                  "country_rate", "asn_rate", "countries_24h"]


def spray_features(h: IPHistory, e, t: Tables) -> list[float]:
    rec = [r for r in h.recent if e.ts - r[0] <= DAY] + [(e.ts, e.user, e.success, bool(getattr(e, "user_unknown", False)), e.ua,
                                                          getattr(e, "country", None))]
    w1 = [r for r in rec if e.ts - r[0] <= HOUR]
    users = Counter(r[1] for r in rec)
    ok_users = {r[1] for r in rec if r[2]}
    fails24 = sum(not r[2] for r in rec)
    unk = sum(r[3] for r in rec)
    g1 = sorted(b[0] - a[0] for a, b in zip(w1, w1[1:]))
    g24 = sorted(b[0] - a[0] for a, b in zip(rec, rec[1:]))
    return [len({r[1] for r in w1}), len(users), len(w1), len(rec), sum(not r[2] for r in w1), fails24,
            fails24 / len(rec), unk, unk / len(rec), len(set(users) - ok_users), len(rec) / max(len(users), 1),
            len(ok_users), len({r[4] for r in rec if r[4]}), g1[0] if g1 else HOUR,
            g24[len(g24) // 2] if g24 else DAY, float(parse_ua(e.ua)[5]) if e.ua else UNK,
            len({r[4] for r in rec if r[4]}) / len(rec) if e.ua else UNK,
            len({parse_ua(r[4])[2] for r in rec if r[4]}) if e.ua else UNK,
            t.rate("bver", parse_ua(e.ua)[1]), t.rate("over", parse_ua(e.ua)[3]), t.rate("dtype", parse_ua(e.ua)[4]),
            t.rate("country", e.country), t.rate("asn", e.asn),
            float(len({r[5] for r in rec if r[5]})) if e.country else UNK]


LOCATION_FEATURES = ["country_new", "region_new", "city_new", "asn_new", "ip_new", "ip16_new", "hist_ok",
                     "n_countries", "n_asn", "country_share", "asn_share", "hours_since_last", "country_changed",
                     "fast_country_change", "country_rate", "asn_rate", "country_freq", "asn_freq"]


def location_features(h: AccountHistory, e, t: Tables) -> list[float]:
    k = h.known
    since = (e.ts - h.last_ok[0].ts) / HOUR if h.last_ok else UNK
    last_c = h.last_ok[1]["country"] if h.last_ok else None
    changed = UNK if (not e.country or not last_c) else float(e.country != last_c)
    fast = UNK if changed == UNK else float(changed == 1.0 and 0 <= since < 3)
    return [_new(k["country"], e.country), _new(k["region"], e.region), _new(k["city"], e.city),
            _new(k["asn"], e.asn), _new(k["ip"], e.ip), _new(k["ip16"], _ip16(e.ip)), _lg(h.ok),
            len(k["country"]), len(k["asn"]), _share(k["country"], e.country, h.ok), _share(k["asn"], e.asn, h.ok),
            _lg(since) if since != UNK else UNK, changed, fast,
            t.rate("country", e.country), t.rate("asn", e.asn), t.freq("country", e.country), t.freq("asn", e.asn)]


DEVICE_FEATURES = ["ua_new", "bfam_new", "bver_new", "ofam_new", "over_new", "dtype_new", "is_bot", "is_mobile",
                   "hist_ok", "n_ua", "n_ofam", "n_dtype", "ua_share", "ofam_share", "hours_since_last",
                   "bfam_rate", "ofam_rate", "dtype_rate", "ua_freq", "bver_freq", "bver_rate", "over_rate"]


def device_features(h: AccountHistory, e, t: Tables) -> list[float]:
    k = h.known
    b, bv, o, ov, d, bot = parse_ua(e.ua)
    since = (e.ts - h.last_ok[0].ts) / HOUR if h.last_ok else UNK
    has = e.ua is not None and e.ua != ""
    return [_new(k["ua"], e.ua), _new(k["bfam"], b), _new(k["bver"], bv), _new(k["ofam"], o), _new(k["over"], ov),
            _new(k["dtype"], d), float(bot) if has else UNK, float(d in ("mobile", "tablet")) if has else UNK,
            _lg(h.ok), len(k["ua"]), len(k["ofam"]), len(k["dtype"]), _share(k["ua"], e.ua, h.ok),
            _share(k["ofam"], o, h.ok), _lg(since) if since != UNK else UNK,
            t.rate("bfam", b), t.rate("ofam", o), t.rate("dtype", d), t.freq("ua", e.ua), t.freq("bver", bv),
            t.rate("bver", bv), t.rate("over", ov)]


SESSION_FEATURES = ["minutes_since_prev", "logins_2h", "ips_2h", "countries_2h", "asn_2h", "ua_2h", "fails_2h",
                    "same_ip_prev", "same_country_prev", "same_asn_prev", "same_ua_prev", "same_ip16_prev",
                    "country_switch_30m", "ip_switch_30m", "ip_new", "ua_new", "hist_ok"]


def session_features(h: AccountHistory, e, t: Tables) -> list[float]:
    w = [r for r in h.recent if e.ts - r[0] <= 2 * HOUR]
    oks = [r for r in w if r[1]]
    prev = h.last_ok[0] if h.last_ok else None
    mins = (e.ts - prev.ts) / 60 if prev else UNK

    def same(a, b):
        return UNK if (not a or not b) else float(a == b)

    within30 = [r for r in oks if e.ts - r[0] <= 1800]
    c_sw = UNK if not e.country else float(any(r[3] and r[3] != e.country for r in within30))
    ip_sw = UNK if not e.ip else float(any(r[2] and r[2] != e.ip for r in within30))
    return [_lg(mins) if mins != UNK else UNK, len(oks) + 1,
            len({r[2] for r in oks if r[2]} | ({e.ip} if e.ip else set())),
            len({r[3] for r in oks if r[3]} | ({e.country} if e.country else set())),
            len({r[4] for r in oks if r[4]} | ({e.asn} if e.asn else set())),
            len({r[5] for r in oks if r[5]} | ({e.ua} if e.ua else set())),
            sum(not r[1] for r in w),
            same(prev.ip if prev else None, e.ip), same(prev.country if prev else None, e.country),
            same(prev.asn if prev else None, e.asn), same(prev.ua if prev else None, e.ua),
            same(_ip16(prev.ip) if prev else None, _ip16(e.ip)), c_sw, ip_sw,
            _new(h.known["ip"], e.ip), _new(h.known["ua"], e.ua), _lg(h.ok)]


BEHAVIOUR_FEATURES = ["hour_dev", "hour_seen", "hour_share", "weekday_seen", "gap_ratio", "logins_24h", "rate_ratio_24h",
                      "fail_rate_24h", "fail_rate_change", "n_changed", "hist_ok", "account_age_days", "hour"]


def behaviour_features(h: AccountHistory, e, t: Tables) -> list[float]:
    hr = _hour_of(e.ts)
    if h.ok:
        # circular mean of the account's usual login hours
        s = sum(c * math.sin(2 * math.pi * x / 24) for x, c in h.hours.items())
        c_ = sum(c * math.cos(2 * math.pi * x / 24) for x, c in h.hours.items())
        mean_h = (math.atan2(s, c_) * 24 / (2 * math.pi)) % 24
        dev = _circ(hr, mean_h)
        seen = float(any(h.hours.get((int(hr) + d) % 24) for d in (-1, 0, 1)))
        share = sum(h.hours.get((int(hr) + d) % 24, 0) for d in (-1, 0, 1)) / h.ok
        wd = float(bool(h.weekdays.get(int(e.ts // DAY + 4) % 7)))
    else:
        dev = seen = share = wd = UNK
    gaps = sorted(h.gaps)
    gap = (e.ts - h.last_ok[0].ts) if h.last_ok else None
    gap_ratio = math.log((gap + 60) / (gaps[len(gaps) // 2] + 60)) if (gaps and gap is not None) else UNK
    w = [r for r in h.recent if e.ts - r[0] <= DAY]
    age_days = (e.ts - h.first_ts) / DAY if h.first_ts is not None else 0.0
    base_rate = h.ok / max(age_days, 1.0)
    logins24 = sum(r[1] for r in w) + 1
    fr24 = sum(not r[1] for r in w) / len(w) if w else 0.0
    base_fr = h.fails / h.attempts if h.attempts else UNK
    b, bv, o, ov, d, _ = parse_ua(e.ua)
    changed = sum(x == 1.0 for x in (_new(h.known["country"], e.country), _new(h.known["asn"], e.asn),
                                     _new(h.known["ip16"], _ip16(e.ip)), _new(h.known["ofam"], o),
                                     _new(h.known["bfam"], b), _new(h.known["dtype"], d)))
    return [dev, seen, share, wd, gap_ratio, logins24, _lg(logins24 / max(base_rate, 0.05)), fr24,
            (fr24 - base_fr) if base_fr != UNK else UNK, float(changed), _lg(h.ok), _lg(age_days), hr]


# Domain knowledge the models must respect: these signals can only RAISE the risk (+1) or only LOWER it (-1).
# Without this, a model trained on data where huge bursts are rare could rate 12 failures as safer than 3.
MONOTONIC = {
    "failed-logins": {"att_1h": 1, "fail_1h": 1, "fail_ratio_1h": 1, "fail_24h": 1, "consec_fail": 1,
                      "success_after_fails": 1, "ips_1h": 1, "min_gap_1h": -1, "median_gap_1h": -1},
    "password-spraying": {"users_1h": 1, "users_24h": 1, "fail_1h": 1, "fail_24h": 1, "unknown_user_24h": 1,
                          "users_only_failed_24h": 1},
}

SUBTOPICS = {
    # subtopic id: (feature names, feature function, which history it uses)
    "failed-logins": (FAILED_FEATURES, failed_features, "account"),
    "password-spraying": (SPRAY_FEATURES, spray_features, "ip"),
    "unusual-location": (LOCATION_FEATURES, location_features, "account"),
    "unknown-device": (DEVICE_FEATURES, device_features, "account"),
    "session-activity": (SESSION_FEATURES, session_features, "account"),
    "behavior-changes": (BEHAVIOUR_FEATURES, behaviour_features, "account"),
}
# Which events of a log each subtopic scores (failed-logins / spraying: every attempt; the rest: successful logins)
SCORES_SUCCESS_ONLY = {"unusual-location", "unknown-device", "session-activity", "behavior-changes"}
MIN_HISTORY = {"unusual-location": 1, "unknown-device": 1, "session-activity": 1, "behavior-changes": 3}
SESSION_WINDOW = 2 * HOUR


def eligible(subtopic: str, h, e) -> bool:
    """Is this event scored by this subtopic's model? Exactly the same rule in training and scanning:
    logins are only compared with a history once the account HAS one, the session model only looks
    at a login that follows another successful login within 2 hours, and the spraying model only at an
    IP that has tried more than one account."""
    if subtopic == "password-spraying":
        # spraying = one source trying SEVERAL accounts; a single account is never spraying
        return any(r[1] != e.user for r in h.recent if e.ts - r[0] <= DAY)
    if subtopic not in SCORES_SUCCESS_ONLY:
        return True
    if not e.success or h.ok < MIN_HISTORY[subtopic]:
        return False
    if subtopic == "session-activity":
        return h.last_ok is not None and 0 <= e.ts - h.last_ok[0].ts <= SESSION_WINDOW
    return True


def score_events(subtopic: str, events, tables: Tables):
    """For a pasted log: yield (event, feature vector) for every event this subtopic scores,
    using only the lines BEFORE each event as history (exactly like training)."""
    names, fn, kind = SUBTOPICS[subtopic]
    hists: dict = {}
    for e in sorted(events, key=lambda x: x.ts):
        key = (e.ip or "?") if kind == "ip" else e.user
        h = hists.get(key)
        if h is None:
            h = hists[key] = IPHistory() if kind == "ip" else AccountHistory()
        if eligible(subtopic, h, e):
            yield e, fn(h, e, tables)
        h.add(e)
