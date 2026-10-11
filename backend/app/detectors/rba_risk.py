"""
Risk-Based Authentication (RBA) risk score for one login -- the model the RBA dataset was built for.

Published method (Freeman et al., NDSS 2016; Wiefling et al., 2019/2022):

    risk(login) =  P(features | attacker)       ~ how common these values are across EVERYONE
                   ---------------------------
                   P(features | this account)   ~ how common they are in THIS account's own history

A login from the user's usual country, network, device and browser has a tiny risk; a login from a
country / network / device the account has never used has a large one. Features are scored as two
hierarchies (most general value first), so "same ISP, new IP" is less risky than "new country":

    network:  country -> ASN (internet provider) -> IP address          ("is the LOCATION unusual?")
    client :  device type -> OS -> browser -> full User-Agent string    ("is the DEVICE unusual?")

Our one change to the published formula: the two hierarchies are scored separately and only their
positive (unusual) parts are added, so a familiar browser cannot cancel out a never-seen country.
Attackers copy User-Agent strings easily; with the plain product such an attacker looked "safe".
Measured on simulated attackers (400k RBA logins, same false-alarm rate): attacker who copies the
victim's browser AUC 0.84 -> 0.91, new device on the victim's own network 0.84 -> 0.89.

ONE implementation used in two places, so they can never drift apart:
  * training  (app/ml/training/train_ato_login.py) streams the RBA dataset through it in time order;
  * scanning  (app/detectors/account_takeover.py) streams the log lines a user pastes through it.

What is "trained" from the dataset:
  * the global frequency tables (country, ASN, device, OS, browser) = P(features | attacker) side;
  * the distribution of risk over NORMAL logins, so a raw score becomes "riskier than 99.3% of
    normal logins" -- an alert level an analyst can understand and tune.
Only PAST logins are used for a login's score (history is updated after), so there is no leakage.
Missing values (a pasted SSH log has no browser) are simply skipped.
"""
import math
import re
from dataclasses import dataclass, field

NETWORK = ("country", "asn", "ip")
CLIENT = ("device_type", "os", "browser", "ua")
HIERARCHIES = {"network": NETWORK, "client": CLIENT}
LEVEL_HIERARCHY = {lvl: h for h, levels in HIERARCHIES.items() for lvl in levels}
FINE_LEVELS = ("ip", "ua")              # too many values to ship global tables for -> constant prior
FINE_PRIOR = {"ip": 1e-3, "ua": 1e-3}
ALPHA = 1.0                             # smoothing strength toward the global distribution
_MAX_PATHS = 256                        # per account, per hierarchy level (bounded memory)

LABELS = {"country": "country", "asn": "network (ASN)", "ip": "IP address",
          "device_type": "device type", "os": "operating system", "browser": "browser", "ua": "browser/app (User-Agent)"}


@dataclass
class LoginEvent:
    ts: float                 # unix seconds
    user: str
    ip: str | None
    success: bool
    country: str | None = None
    region: str | None = None
    city: str | None = None
    asn: str | None = None
    ua: str | None = None
    device_type: str | None = None
    os: str | None = None
    browser: str | None = None
    user_unknown: bool = False    # login for an account that does not exist ("invalid user")


# ---- value normalisation (dataset columns and pasted logs must look alike) ----------------
_VER = re.compile(r"^(.*?)[ /]?(\d+)(?:[._]\d+)*\s*$")


def family_major(value: str | None) -> str | None:
    """'Chrome Mobile 81.0.4044' -> 'chrome mobile 81', 'iOS 13.4' -> 'ios 13'. Empty/'-' -> None."""
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in ("", "-", "unknown", "none", "nan", "other"):
        return None
    m = _VER.match(v)
    return f"{m.group(1).strip()} {m.group(2)}".strip() if m else v


_UA_OS = [("android", re.compile(r"android[ /]?(\d+)")), ("ios", re.compile(r"(?:iphone|ipad|cpu)[^)]*? os (\d+)")),
          ("windows", re.compile(r"windows nt (\d+)")), ("mac os x", re.compile(r"mac os x (\d+)")),
          ("linux", re.compile(r"(linux)")), ("chrome os", re.compile(r"(cros)"))]
_UA_BR = [("edge", re.compile(r"edg(?:e|a|ios)?/(\d+)")), ("opera", re.compile(r"(?:opr|opera)[/ ](\d+)")),
          ("firefox", re.compile(r"(?:firefox|fxios)/(\d+)")), ("chrome", re.compile(r"(?:chrome|crios)/(\d+)")),
          ("safari", re.compile(r"version/(\d+).*safari"))]
BOT_RE = re.compile(r"bot|crawl|spider|slurp|nslookup|curl|wget|python|java/|go-http|okhttp|libwww|scrapy|"
                    r"headless|phantom|httpclient|axios|node-fetch|hydra|medusa|sqlmap|nikto|masscan", re.I)


def client_from_ua(ua: str | None) -> tuple[str | None, str | None, str | None]:
    """Best-effort (device_type, os, browser) from a raw User-Agent, for logs that only have the UA."""
    if not ua:
        return None, None, None
    low = ua.lower()
    if BOT_RE.search(low):
        return "bot", None, None
    dev = "tablet" if ("ipad" in low or "tablet" in low) else "mobile" if any(k in low for k in ("mobile", "iphone", "android")) else "desktop"
    os_ = next((f"{name} {m.group(1)}" if m.group(1).isdigit() else name
                for name, rx in _UA_OS for m in [rx.search(low)] if m), None)
    br = next((f"{name} {m.group(1)}" for name, rx in _UA_BR for m in [rx.search(low)] if m), None)
    return dev, os_, br


def _clean(v):
    v = None if v is None else str(v).strip().lower()
    return None if v in (None, "", "-", "unknown", "nan", "none") else v


def values_from_fields(country=None, asn=None, ip=None, device_type=None, os=None, browser=None, ua=None) -> dict:
    """The hierarchy values of one login, normalised. Missing -> None (skipped when scoring)."""
    if ua and not (_clean(device_type) or _clean(os) or _clean(browser)):
        device_type, os, browser = client_from_ua(ua)
    asn = _clean(asn)
    if asn and asn.startswith("as"):
        asn = asn[2:]                     # "AS29695" and "29695" are the same network
    return {"country": _clean(country), "asn": asn, "ip": _clean(ip), "device_type": _clean(device_type),
            "os": family_major(os), "browser": family_major(browser), "ua": _clean(ua)}


def event_values(e: LoginEvent) -> dict:
    return values_from_fields(e.country, e.asn, e.ip, e.device_type, e.os, e.browser, e.ua)


def paths(values: dict):
    """Yield (hierarchy, level, parent_path, path) using only the values that are present."""
    for h, levels in HIERARCHIES.items():
        parent = ()
        for lvl in levels:
            v = values.get(lvl)
            if v is None:
                continue
            path = parent + ((lvl, v),)
            yield h, lvl, parent, path
            parent = path


# ---- global ("attacker side") tables -------------------------------------------------------
class GlobalTables:
    """Counts of every hierarchy path seen in the training data (coarse levels only)."""

    def __init__(self, counts: dict | None = None, children: dict | None = None, total: int = 0):
        self.counts = counts or {}        # path -> logins
        self.children = children or {}    # parent path -> number of distinct child values
        self.total = total

    def add(self, values: dict, weight: int = 1) -> None:
        self.total += weight
        for _, lvl, parent, path in paths(values):
            if lvl in FINE_LEVELS:
                continue
            if path not in self.counts:
                self.counts[path] = 0
                self.children[parent] = self.children.get(parent, 0) + 1
            self.counts[path] += weight

    def prob(self, lvl: str, parent: tuple, path: tuple) -> float:
        """P(value | parent value) across everyone, add-one smoothed; constant prior for IP / UA."""
        if lvl in FINE_LEVELS:
            return FINE_PRIOR[lvl]
        parent_n = self.total if not parent else self.counts.get(parent, 0)
        k = self.children.get(parent, 0) + 1
        return (self.counts.get(path, 0) + 1) / (parent_n + k)

    def to_dict(self) -> dict:
        return {"counts": self.counts, "children": self.children, "total": self.total}

    @classmethod
    def from_dict(cls, d: dict) -> "GlobalTables":
        return cls(d["counts"], d["children"], d["total"])


# ---- attacker side: where do known attackers log in from? ----------------------------------
REPUTATION_LEVELS = ("country", "asn", "device_type")
BETA = 10.0     # how many attacker logins it takes before a value's own attack rate is trusted


def reputation(values: dict, tables: GlobalTables, attack: GlobalTables, beta: float = BETA, seen_paths=()):
    """log( P(value | attacker) / P(value | everyone) ) over country, ASN and device type.

    P(value | attacker) is learned from logins by IPs on the dataset's attacker list ("Is Attack IP"),
    smoothed toward the global share so rarely-seen values stay neutral. Freeman et al. use IP
    reputation lists for exactly this term.
      * a value never seen in the training data is skipped (no evidence either way);
      * a value already in this account's own history (`seen_paths`) never raises it, because
        P(value | this account) is high -- that is the denominator of the RBA formula;
      * only values that point TOWARD attackers are added (log-ratio > 0). A pasted log usually has fewer
        fields than the dataset; this way a login with fewer known fields can never look riskier.
    Returns (log_ratio, strongest_level or None, number_of_levels_used)."""
    total, best, best_lr, used = 0.0, None, 0.0, 0
    for _, lvl, parent, path in paths(values):
        if lvl not in REPUTATION_LEVELS or path not in tables.counts:
            continue
        p_g = tables.prob(lvl, parent, path)
        a_parent = attack.total if not parent else attack.counts.get(parent, 0)
        p_a = (attack.counts.get(path, 0) + beta * p_g) / (a_parent + beta)
        lr = math.log(p_a) - math.log(p_g)
        used += 1
        if lr <= 0 or path in seen_paths:
            continue
        total += lr
        if lr > best_lr:
            best, best_lr = lvl, lr
    return total, best, used


# ---- account side: per-account history and the score ----------------------------------------
@dataclass
class _History:
    n: int = 0
    counts: dict = field(default_factory=dict)    # path -> logins of this account with that path


class RiskState:
    """Feed logins in time order. `score(e)` uses only the past; `update(e)` remembers e."""

    def __init__(self, tables: GlobalTables):
        self.tables = tables
        self.users: dict[str, _History] = {}

    def has_history(self, user: str) -> bool:
        h = self.users.get(user)
        return bool(h and h.n)

    def score(self, e: LoginEvent, values: dict | None = None) -> tuple[float, list[tuple[str, float, bool]]]:
        """Risk = unusual-location part + unusual-device part (each a natural-log ratio, floored at 0),
        plus per-level contributions [(level, log_ratio, never_seen_before)].
        0 when the account has no successful login yet (nothing to compare with)."""
        if e.user_unknown:
            return 0.0, []
        h = self.users.get(e.user)
        values = values or event_values(e)
        total, parts = 0.0, []
        for _, lvl, parent, path in paths(values):
            p_g = self.tables.prob(lvl, parent, path)
            if h is None or h.n == 0:
                continue                      # no history: P(this account) falls back to P(everyone) -> ratio 1
            parent_n = h.n if not parent else h.counts.get(parent, 0)
            c = h.counts.get(path, 0)
            p_u = (c + ALPHA * p_g) / (parent_n + ALPHA)
            lr = math.log(p_g) - math.log(p_u)
            if lvl in FINE_LEVELS:
                # A new IP at the account's usual provider (DHCP) or a browser auto-update is normal:
                # exact IP / exact User-Agent may LOWER the risk when familiar, but never raise it.
                lr = min(lr, 0.0)
            total += lr
            parts.append((lvl, lr, c == 0 and parent_n > 0))
        per = {}
        for lvl, lr, _ in parts:
            per[LEVEL_HIERARCHY[lvl]] = per.get(LEVEL_HIERARCHY[lvl], 0.0) + lr
        total = sum(max(v, 0.0) for v in per.values())
        return total, parts

    def update(self, e: LoginEvent, values: dict | None = None) -> None:
        """Only successful logins of real accounts build the account's 'normal' profile."""
        if e.user_unknown or not e.success:
            return
        h = self.users.get(e.user)
        if h is None:
            h = self.users[e.user] = _History()
        h.n += 1
        for _, _, _, path in paths(values or event_values(e)):
            if path in h.counts or len(h.counts) < _MAX_PATHS * 7:
                h.counts[path] = h.counts.get(path, 0) + 1

    def step(self, e: LoginEvent):
        values = event_values(e)
        r = self.score(e, values)
        self.update(e, values)
        return r


def percentile(log_risk: float, normal_quantiles: list[float]) -> float:
    """Share (0..100) of normal training logins with a LOWER risk than this one."""
    import bisect
    if not normal_quantiles:
        return 0.0
    i = bisect.bisect_left(normal_quantiles, log_risk)
    return 100.0 * i / len(normal_quantiles)


def explain(parts: list[tuple[str, float, bool]], values: dict | None = None) -> list[str]:
    """Readable reasons, strongest first: 'country never used by this account before (ro)'."""
    out = []
    for lvl, lr, new in sorted(parts, key=lambda x: -x[1]):
        if lr < 1.0:
            continue
        v = (values or {}).get(lvl)
        shown = f" ({v[:40]})" if v else ""
        out.append(f"{LABELS[lvl]} never used by this account before{shown}" if new
                   else f"{LABELS[lvl]} rarely used by this account{shown}")
    return out[:4]


# ---- a trained model, ready to score a sequence of logins ----------------------------------
BUNDLE_KIND, BUNDLE_VERSION = "rba-risk", 2   # v2: location and device scored separately (retrain needed)


class RBAModel:
    """Global + attacker tables and the 'normal login' risk distributions learned from the dataset."""

    def __init__(self, bundle: dict):
        if bundle.get("kind") != BUNDLE_KIND or bundle.get("version") != BUNDLE_VERSION:
            raise ValueError("not an RBA risk model bundle (retrain with app.ml.training.train_ato_login)")
        self.tables = GlobalTables.from_dict(bundle["tables"])
        self.attack = GlobalTables.from_dict(bundle["attack_tables"])
        self.beta = float(bundle.get("beta", BETA))
        self.history_q = list(bundle["history_quantiles"])
        self.reputation_q = list(bundle["reputation_quantiles"])
        self.alert = float(bundle.get("alert_percentile", 99.0))
        # three RBA levels (Wiefling et al.): below `medium` allow, medium = ask for extra verification, alert = block/alert
        self.medium = float(bundle.get("medium_percentile", 95.0))

    def assess(self, events: list[LoginEvent]) -> list[dict]:
        """Score each login against the history built from the EARLIER logins in the same list."""
        st, out = RiskState(self.tables), []
        for e in sorted(events, key=lambda x: x.ts):
            values = event_values(e)
            had_history = st.has_history(e.user)
            risk, parts = st.score(e, values)
            hist_pct = percentile(risk, self.history_q) if had_history else None
            rep_pct, rep_level = None, None
            if not e.user_unknown:
                seen = st.users[e.user].counts if had_history else ()
                rep, rep_level, used = reputation(values, self.tables, self.attack, self.beta, seen)
                rep_pct = percentile(rep, self.reputation_q) if used else None
            reasons = explain(parts, values) if hist_pct is not None and hist_pct >= 90 else []
            if rep_pct is not None and rep_pct >= 95 and rep_level:
                reasons.append(f"{LABELS[rep_level]} ({values[rep_level]}) is much more common among known attacker logins")
            top = max(p for p in (hist_pct, rep_pct, 0.0) if p is not None)
            out.append({"event": e, "historyPercentile": hist_pct, "reputationPercentile": rep_pct,
                        "percentile": top, "flagged": top >= self.alert, "elevated": top >= self.medium,
                        "reasons": reasons})
            st.update(e, values)
        return out
