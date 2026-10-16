"""
Domain spoofing detection (brand name placed inside a domain the brand does not own):
paypal-login-secure.com, sbi-kyc-update.in, coinbase-wallet.app, netflix-billing-help.xyz, naversecurity.us ...

How it works
  1. The registered part of the domain is searched for a protected brand name (the 10,000 most visited
     sites from Tranco + CyberGuard's Indian banks / brands). Look-alike letters are read the way a person
     reads them (paypa1-support.com contains "paypal").
  2. Domains the brand really owns and very popular sites are never judged.
  3. ~25 numbers describe WHERE the brand sits and WHAT surrounds it: at the start / end, cut off by a
     hyphen or glued inside another word ("upDATEZONE" is not the brand "datezone"), security words around
     it (login, verify, kyc, wallet ...), how common the brand is as an ordinary English word ("world",
     "media" are words, "coinbase" is a name), how often legitimate sites use that domain ending, and how
     often that brand's name was abused by real phishing domains in the training data ...
  4. A model trained on REAL domains (PhiUSIIL phishing vs Tranco + PhiUSIIL legitimate domains that also
     contain a brand name) turns them into a probability: app/ml/training/train_domain_spoofing.py

The same feature code is used for training and for scanning.
A brand placed in a SUB-domain (paypal.com.evil-site.net) is reported by the URL engine's rules; this model
judges the part an attacker actually registers (evil-site.net).
"""
from __future__ import annotations

import math
import os
import unicodedata
from functools import lru_cache

from app.detectors.lookalike_domain import (COMMON_TLDS, CONTROLLED_SUFFIXES, _DIGIT, _latin_lookalike,
                                            decode_label, split_domain)

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "domain_spoofing.joblib")

SECURITY_WORDS = (
    "login", "logon", "signin", "signon", "verify", "verification", "secure", "security", "account", "accounts",
    "update", "confirm", "password", "wallet", "banking", "bank", "support", "billing", "invoice", "recovery",
    "recover", "suspend", "suspended", "alert", "unlock", "locked", "kyc", "otp", "auth", "authenticate", "id",
    "online", "service", "services", "customer", "care", "help", "helpdesk", "refund", "reward", "rewards", "claim",
    "bonus", "gift", "pay", "payment", "payments", "portal", "web", "app", "mobile", "official", "team", "center",
    "centre", "connect", "access", "member", "members", "user", "client", "check", "validate", "validation",
    "activate", "activation", "reset", "renew", "notice", "notification", "case", "appeal", "dispute", "mfa",
    "2fa", "token", "airdrop", "crypto", "giveaway", "free", "prize", "winner", "lottery", "tax", "irs", "gov",
)
_SEC = set(SECURITY_WORDS)

FEATURES = [
    "brand_len", "brand_rank_log", "brand_word_rank_log", "label_len", "rest_len", "rest_share",
    "brand_at_start", "brand_at_end", "left_cut", "right_cut", "brand_splits_word", "n_tokens",
    "security_words", "rest_word_cover", "rest_best_word_rank_log", "n_hyphens", "n_digits",
    "tld_common", "tld_share_log", "tld_is_country", "same_tld_as_brand", "non_ascii", "via_lookalike_letters",
    "brands_found", "rest_is_one_word", "brand_phish_rate", "brand_seen_log",
]
PRIOR_WEIGHT = 5.0        # how many "average" domains the per-brand history starts with
NOT_A_WORD = 5.5          # log10 rank given to anything outside the 60,000-word list


# ---------------------------------------------------------------------------
@lru_cache(maxsize=200_000)
def letters(label: str) -> str:
    """Label as a reader sees it, hyphens kept: pаypa1-login -> paypal-login."""
    s = decode_label(label)
    s = "".join(_latin_lookalike(ch) for ch in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch)).lower()
    # a short digit run touching letters reads as letters (paypa1, g00gle); longer runs stay digits (163mail, 888)
    out, k = [], 0
    while k < len(s):
        if s[k].isdigit():
            e = k
            while e < len(s) and s[e].isdigit():
                e += 1
            run = s[k:e]
            touches = (k > 0 and s[k - 1].isalpha()) or (e < len(s) and s[e].isalpha())
            out.append("".join(_DIGIT.get(c, c) for c in run) if len(run) <= 2 and touches else run)
            k = e
        else:
            out.append(s[k])
            k += 1
    return "".join(out).replace("_", "-")


def brand_key(label: str) -> str:
    return letters(label).replace("-", "")


class BrandTable:
    """Protected brands (key = letters without hyphens) + the English word list + domain-ending statistics."""

    def __init__(self, brands: dict, owned: dict, words: dict, tld_share: dict, allow=(), stats=None, prior=0.1,
                 curated=(), prior_curated=None):
        self.brands = brands          # key -> (rank, official domain, suffix, word_rank)
        self.owned = owned            # key -> set of registered domains the brand owns
        self.words = words            # word -> rank (1 = most common)
        self.tld_share = tld_share    # suffix -> share of popular sites using it
        self.allow = set(allow)
        self.stats = stats or {}      # brand -> (phishing domains, all domains) seen in the training data
        self.prior = prior            # share of phishing among all brand-carrying training domains
        self.curated = set(curated)   # CyberGuard's own protected brands (Indian banks, payment apps, big brands)
        self.prior_curated = prior if prior_curated is None else prior_curated
        self.maxlen = max((len(k) for k in brands), default=0)

    def to_state(self):
        return {"brands": self.brands, "owned": {k: sorted(v) for k, v in self.owned.items()},
                "words": self.words, "tld_share": self.tld_share, "allow": sorted(self.allow),
                "stats": self.stats, "prior": self.prior, "curated": sorted(self.curated),
                "prior_curated": self.prior_curated}

    @classmethod
    def from_state(cls, st):
        return cls({k: tuple(v) for k, v in st["brands"].items()}, {k: set(v) for k, v in st["owned"].items()},
                   st["words"], st["tld_share"], st["allow"], {k: tuple(v) for k, v in st.get("stats", {}).items()},
                   st.get("prior", 0.1), st.get("curated", ()), st.get("prior_curated"))

    def brand_history(self, key: str, stats=None) -> tuple[float, float]:
        """Smoothed share of phishing among domains carrying this brand, and how many were seen."""
        ph, n = (stats if stats is not None else self.stats).get(key, (0, 0))
        prior = self.prior_curated if key in self.curated else self.prior
        return (ph + PRIOR_WEIGHT * prior) / (n + PRIOR_WEIGHT), math.log10(1 + n)

    def word_rank_log(self, w: str) -> float:
        r = self.words.get(w)
        return math.log10(r) if r else NOT_A_WORD


def _after_cut(s: str, cuts: set, i: int) -> str:
    """The text between the last hyphen/digit edge before position i and i."""
    start = max([c for c in cuts if c < i] + [0])
    return s[start:i]


def find_brands(norm: str, table: BrandTable):
    """All protected brands inside the label. -> list of (key, start, end) in the hyphen-free string."""
    s = norm.replace("-", "")
    cuts = set()                     # positions where the original label had a hyphen or a digit run edge
    pos = 0
    for ch in norm:
        if ch == "-":
            cuts.add(pos)
            continue
        pos += 1
    for k in range(1, len(s)):
        if s[k].isdigit() != s[k - 1].isdigit():
            cuts.add(k)
    found = []
    for i in range(len(s)):
        for j in range(i + 3, min(len(s), i + table.maxlen) + 1):
            key = s[i:j]
            if key not in table.brands or key == s:
                continue
            # the brand must start a part of the name: at the start, after a hyphen/digit, or after whole words
            # (secure-PAYPAL, securePAYPAL, myPAYPAL) -- "tbank" in "mellatbank", "ustream" in "virtustream" are not
            if not (i == 0 or i in cuts or _segment_cover(_after_cut(s, cuts, i), table.words)[0] == 1.0):
                continue
            if len(key) <= 4:                        # sbi, irs, dhl: also must END a part (sbi-kyc, sbionline)
                after = s[j:min([c for c in cuts if c > j] + [len(s)])]
                if not (j == len(s) or j in cuts or _segment_cover(after[:12], table.words)[0] == 1.0
                        or any(after.startswith(w) for w in _SEC if len(w) >= 3)):
                    continue
            official = table.brands[key][1].split(".")[0]
            if "-" not in official and any(i < c < j for c in cuts) and not (j == len(s) or j in cuts):
                continue          # across a hyphen only as whole parts: ICICI-BANK-update yes, sparkass-E-ONLINEdienste no
            found.append((key, i, j))
            found.append((key, i, j))
    return found, s, cuts


def _segment_cover(text: str, words: dict) -> tuple[float, float]:
    """Share of the text covered by dictionary words (greedy, longest first) and the best word's rank."""
    if not text:
        return 1.0, 0.0
    covered, best, i = 0, None, 0
    while i < len(text):
        hit = None
        for j in range(min(len(text), i + 20), i + 1, -1):
            w = text[i:j]
            r = words.get(w)
            if w in _SEC or (r and (len(w) >= 4 or r <= 1_500)):    # 3-letter junk words do not count
                hit = w
                break
        if hit:
            covered += len(hit)
            r = words.get(hit, 1)
            best = r if best is None else min(best, r)
            i += len(hit)
        else:
            i += 1
    return covered / len(text), (math.log10(best) if best else NOT_A_WORD)


def spoofing_features(domain: str, table: BrandTable, stats=None):
    """-> (features, details) or (None, details) when there is nothing to judge."""
    reg, label, suffix = split_domain(domain)
    details = {"domain": reg, "brand": None, "brandDomain": None, "signs": []}
    if not label:
        return None, details
    if reg in table.allow:
        details["allowlisted"] = True
        return None, details
    if any(("." + reg).endswith(c) for c in CONTROLLED_SUFFIXES):
        details["controlledSuffix"] = True
        return None, details
    norm = letters(label)
    found, s, cuts = find_brands(norm, table)
    if not found:
        details["noBrand"] = True
        return None, details
    # the longest brand name, then the most popular one
    key, i, j = max(found, key=lambda f: (f[2] - f[1], -table.brands[f[0]][0]))
    rank, official, b_suffix, b_word = table.brands[key]
    if reg in table.owned.get(key, ()):
        details["ownedByBrand"] = True
        return None, details
    details.update(brand=key, brandDomain=official, brandRank=rank)
    rest = s[:i] + "-" + s[j:]
    rest_parts = [p for p in rest.split("-") if p]
    rest_txt = "".join(rest_parts)
    # does an ordinary word run across the brand's edge?  upDATEZONE / virginiaSCAKES
    splits = 0.0
    for edge in ((i,) if i not in cuts and i > 0 else ()) + ((j,) if j not in cuts and j < len(s) else ()):
        for a in range(max(0, edge - 12), edge):
            for b in range(edge + 1, min(len(s), edge + 12) + 1):
                w = s[a:b]
                if len(w) >= 4 and w in table.words and not (a >= i and b <= j):
                    splits = 1.0
                    break
            if splits:
                break
    sec = [w for w in SECURITY_WORDS if len(w) >= 3 and w in rest_txt]
    sec += [p for p in rest_parts if p in _SEC and p not in sec]
    cover, best_rank = _segment_cover(rest_txt, table.words)
    raw = decode_label(label)
    feats = {
        "brand_len": len(key), "brand_rank_log": math.log10(max(rank, 1)), "brand_word_rank_log": b_word,
        "label_len": len(s), "rest_len": len(rest_txt), "rest_share": len(rest_txt) / max(len(s), 1),
        "brand_at_start": float(i == 0), "brand_at_end": float(j == len(s)),
        "left_cut": float(i == 0 or i in cuts), "right_cut": float(j == len(s) or j in cuts),
        "brand_splits_word": splits, "n_tokens": float(len([p for p in norm.split("-") if p])),
        "security_words": float(len(set(sec))), "rest_word_cover": cover, "rest_best_word_rank_log": best_rank,
        "n_hyphens": float(label.count("-")), "n_digits": float(sum(c.isdigit() for c in label)),
        "tld_common": float(suffix in COMMON_TLDS),
        "tld_share_log": math.log10(max(table.tld_share.get(suffix, 0.0), 1e-7)),
        "tld_is_country": float(len(suffix.split(".")[-1]) == 2), "same_tld_as_brand": float(suffix == b_suffix),
        "non_ascii": float(not raw.isascii()),
        "via_lookalike_letters": float(key not in raw.replace("-", "")),
        "brands_found": float(len({f[0] for f in found})),
        "rest_is_one_word": float(len(rest_parts) == 1 and rest_parts[0] in table.words),
    }
    feats["brand_phish_rate"], feats["brand_seen_log"] = table.brand_history(key, stats)
    signs = [f"contains the name '{key}' (official site: {official})"]
    if sec:
        signs.append("security / account words next to it: " + ", ".join(sorted(set(sec))[:4]))
    if feats["via_lookalike_letters"]:
        signs.append("the name is written with look-alike letters")
    if label.count("-") >= 2:
        signs.append(f"{label.count('-')} hyphens")
    if suffix != b_suffix:
        signs.append(f"ending .{suffix} (the brand uses .{b_suffix})")
    details["signs"] = signs
    return [float(feats[n]) for n in FEATURES], details


# ---------------------------------------------------------------------------
_cache: dict = {}


def load_model():
    if not os.path.exists(MODEL_PATH):
        _cache.clear()
        return None
    mtime = os.path.getmtime(MODEL_PATH)
    if _cache.get("mtime") != mtime:
        try:
            import joblib
            b = joblib.load(MODEL_PATH)
            ok = isinstance(b, dict) and b.get("kind") == "cyberguard-domain-spoofing" and list(b["features"]) == FEATURES
            b = {**b, "table_obj": BrandTable.from_state(b["table"])} if ok else None
        except Exception:
            b = None
        _cache.update(mtime=mtime, bundle=b)
    return _cache.get("bundle")


def assess(domain: str):
    """-> dict with probability, level and plain-language details, or None if there is no model."""
    b = load_model()
    if b is None or not domain:
        return None
    feats, details = spoofing_features(domain, b["table_obj"])
    if feats is None:
        return {"probability": 0.0, "level": "low", **details}
    p = float(b["model"].predict_proba([feats])[0][1])
    level = "high" if p >= b["thr_alert"] else "medium" if p >= b["thr_verify"] else "low"
    return {"probability": p, "level": level, "thrAlert": b["thr_alert"], "thrVerify": b["thr_verify"], **details}
