"""
SSL & Domain Analysis - domain REGISTRATION model.

Reads the registry record of a link's domain (RDAP, see domain_facts.py) and judges it the way an analyst would:
how old the domain is, for how long it was registered, which registrar, which name servers, registry locks.
Most phishing domains are new, registered for the minimum period at a few cheap registrars and have no registry
locks; real banks, shops and universities have had theirs for years, often with registry locks.

Model: HistGradientBoosting (scikit-learn), trained by app/ml/training/train_domain_age.py on registry records of
real phishing domains (Phishing.Database) and real sites (Tranco top-1M), collected on the user's PC by
collect_domain_facts.py. File: app/ml/models/domain_age.joblib

Domains that registrars already took down (status "client hold", "redemption period", "pending delete") are NOT
used for training: a live phishing link that someone scans has not been taken down yet, so those statuses would
teach the model something that is never true at scan time.
"""
from __future__ import annotations

import math
import os
from datetime import datetime, timezone

from app.detectors import domain_facts

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "domain_age.joblib")
KIND = "cyberguard-domain-age"
TAKEDOWN_STATUS = ("hold", "redemption", "pending delete", "pending restore")
FEATURES = ["log_age_days", "age_under_30d", "age_under_1y", "term_years", "days_to_expiry", "registrar_rate",
            "registrar_known", "tld_rate", "ns_cloudflare", "ns_aws", "ns_self", "ns_other", "ns_none", "dnssec",
            "server_lock", "client_locks"]
_cache: dict = {}


def taken_down(facts: dict) -> bool:
    return any(any(t in s for t in TAKEDOWN_STATUS) for s in facts.get("status") or [])


def _years(a, b):
    return (a - b).total_seconds() / (365.25 * 86400) if a and b else None


def features(facts: dict, registrar_rates: dict, tld_rates: dict, prior: float) -> list[float] | None:
    """Registry facts -> feature row (same code for training and live scans). None if the record has no date."""
    age = domain_facts.age_days(facts)
    if age is None:
        return None
    created = domain_facts._parse_date(facts.get("created"))
    expires = domain_facts._parse_date(facts.get("expires"))
    checked = domain_facts._parse_date(facts.get("checked_at")) or datetime.now(timezone.utc)
    term = _years(expires, created)
    to_expiry = (expires - checked).total_seconds() / 86400 if expires else -1.0
    reg = (facts.get("registrar") or "").strip().lower()
    tld = (facts.get("domain") or "").rsplit(".", 1)[-1].lower()
    ns = facts.get("nameservers") or []
    dom = (facts.get("domain") or "").lower()
    ns_cf = any("cloudflare" in n for n in ns)
    ns_aws = any("awsdns" in n for n in ns)
    ns_self = any(dom and dom in n for n in ns)
    status = facts.get("status") or []
    return [
        math.log1p(age), float(age < 30), float(age < 365),
        term if term is not None else -1.0, to_expiry,
        registrar_rates.get(reg, prior), float(reg in registrar_rates),
        tld_rates.get(tld, prior),
        float(ns_cf), float(ns_aws), float(ns_self), float(bool(ns) and not (ns_cf or ns_aws or ns_self)), float(not ns),
        float(bool(facts.get("dnssec"))),
        float(any(s.startswith("server") and "prohibited" in s for s in status)),
        float(sum(s.startswith("client") and "prohibited" in s for s in status)),
    ]


def load():
    if not os.path.exists(MODEL_PATH):
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _cache.get("mtime") != mtime:
        try:
            import joblib
            b = joblib.load(MODEL_PATH)
            _cache.update(mtime=mtime, bundle=b if b.get("kind") == KIND and b.get("features") == FEATURES else None)
        except Exception:
            _cache.update(mtime=mtime, bundle=None)
    return _cache["bundle"]


def assess(domain: str, facts: dict | None = None) -> dict | None:
    """-> {"facts", "ageDays", "probability", "level", "thrAlert", "thrVerify", "sentences"} or None (no model /
    no registry record). Live: makes one RDAP lookup (cached for a day)."""
    b = load()
    facts = facts or domain_facts.lookup(domain)
    if not facts.get("ok"):
        return {"facts": facts, "ageDays": None, "probability": None, "level": None, "sentences": [
            f"Registry record not available ({facts.get('error') or 'no RDAP service for this ending'})."]}
    age = domain_facts.age_days(facts)
    sentences = [f"Registered {domain_facts.describe_age(age)} ago"
                 + (f" ({facts['created'][:10]})" if facts.get("created") else "")
                 + (f" at {facts['registrar']}" if facts.get("registrar") else "")]
    created, expires = domain_facts._parse_date(facts.get("created")), domain_facts._parse_date(facts.get("expires"))
    if created and expires:
        sentences.append(f"Registered until {facts['expires'][:10]} ({_years(expires, created):.1f}-year term)")
    if b is None:
        return {"facts": facts, "ageDays": age, "probability": None, "level": None, "sentences": sentences}
    row = features(facts, b["registrar_rates"], b["tld_rates"], b["prior"])
    if row is None:
        return {"facts": facts, "ageDays": age, "probability": None, "level": None, "sentences": sentences}
    p = float(b["model"].predict_proba([row])[0][1])
    level = "high" if p >= b["thr_alert"] else "medium" if p >= b["thr_verify"] else "low"
    return {"facts": facts, "ageDays": age, "probability": p, "level": level, "thrAlert": b["thr_alert"],
            "thrVerify": b["thr_verify"], "sentences": sentences, "trainedAt": b.get("trained_at")}
