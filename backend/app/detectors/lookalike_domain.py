"""
Look-alike domain detection (typosquatting and homoglyphs): paypa1.com, rnicrosoft.com, gooogle.com,
xn--pypal-4ve.com ("pаypal" with a Cyrillic а), hdfcbnak.com, paypal-.com ...

How it works
  1. The domain's registered part is compared with a protected list of well-known sites (the most
     visited sites from the Tranco list + CyberGuard's Indian banks / brands).
  2. Both are first reduced to a "skeleton": letters from other alphabets that look Latin (Cyrillic а,
     Greek ο), digits that look like letters (0->o, 1->l, 3->e) and letter pairs that look like one letter
     (rn->m, vv->w, cl->d) are replaced, accents and hyphens dropped.
  3. The nearest protected site is found (rapidfuzz, Damerau-Levenshtein distance) and ~25 numbers
     describe HOW the domain differs from it (one letter swapped / missing / doubled / a neighbouring key /
     a homoglyph / another alphabet / a different ending ...) and how popular the imitated site is.
  4. A trained model (app/ml/training/train_lookalike_domain.py) turns those numbers into a probability.

The same feature code is used for training and for scanning.
"""
from __future__ import annotations

import math
import os
import unicodedata
from functools import lru_cache

from rapidfuzz import process
from rapidfuzz.distance import DamerauLevenshtein, Levenshtein

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models", "lookalike_domain.joblib")

# Characters from other alphabets that look like Latin letters (the ones used in real IDN attacks)
_CONFUSABLE = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l",
    "ɡ": "g", "ь": "b", "ы": "bi", "п": "n", "г": "r", "л": "n", "д": "d", "ӧ": "o", "ӱ": "y",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "ω": "w", "γ": "y", "μ": "u",
    # Latin look-alikes
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ƅ": "b", "ɑ": "a", "ɩ": "i", "ʀ": "r",
    "ß": "ss", "æ": "ae", "œ": "oe",
}
# Unicode TR39 confusables (confusables.txt) that look like a Latin letter or digit; generated once.
_UNI_SRC = (
    "\xd7\u0131\u017f\u018d\u01bd\u01c0\u0223\u0251\u0261\u0263\u0269\u026a\u026f\u028b\u028f\u02db\u037a"
    "\u03b1\u03b3\u03b9\u03bd\u03bf\u03c1\u03c3\u03c5\u03f1\u03f2\u03f3\u0430\u0431\u0433\u0435\u043e"
    "\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u0461\u0475\u04af\u04bb\u04bd\u04cf\u0501\u051b\u051d"
    "\u0561\u0563\u0566\u0570\u0578\u057c\u057d\u0581\u0584\u0585\u06f1\u06f5\u0966\u09ea\u09ed\u0a66"
    "\u0a67\u0a6a\u0ae6\u0b03\u0b68\u0be6\u0c02\u0c66\u0c82\u0ce6\u0d02\u0d20\u0d66\u0d6d\u0d82\u0e50"
    "\u0ed0\u101d\u1040\u10e7\u10ff\u146f\u1472\u14bf\u1541\u157d\u15af\u166e\u16c1\u1d04\u1d0f\u1d11"
    "\u1d1c\u1d20\u1d21\u1d22\u1d26\u1d83\u1d8c\u1e9d\u1eff\u1fbe\u2110\u2111\u212e\u213d\u2223\u2228"
    "\u22c1\u2373\u2374\u237a\u23fd\u292b\u292c\u2a2f\u2c85\u2c9f\u2ca3\u2ca5\u2d4f\ua4d2\ua4f2\ua647"
    "\ua6ef\ua731\ua799\ua79f\uab32\uab35\uab3d\uab47\uab48\uab4e\uab52\uab5a\uab75\uab81\uab83\uab93"
    "\uaba9\uabaa\uabaf\uffe8\U0001028a\U00010309\U0001031a\U00010320\U0001042c\U0001043d\U00010448"
    "\U000104ea\U000104f6\U00011706\U0001170a\U0001170e\U0001170f\U000118c0\U000118c1\U000118c3\U000118c4"
    "\U000118c6\U000118c8\U000118ca\U000118cc\U000118d5\U000118d6\U000118d7\U000118d8\U000118dc\U00016f28"
    "\U00016f3b\U0001d206\U0001d212\U0001d408\U0001d43c\U0001d470\U0001d4d8\U0001d540\U0001d574\U0001d5a8"
    "\U0001d5dc\U0001d610\U0001d644\U0001d678\U0001d6a4\U0001d6b0\U0001d6c2\U0001d6c4\U0001d6ca\U0001d6ce"
    "\U0001d6d0\U0001d6d2\U0001d6d4\U0001d6d6\U0001d6e0\U0001d6ea\U0001d6fc\U0001d6fe\U0001d704\U0001d708"
    "\U0001d70a\U0001d70c\U0001d70e\U0001d710\U0001d71a\U0001d724\U0001d736\U0001d738\U0001d73e\U0001d742"
    "\U0001d744\U0001d746\U0001d748\U0001d74a\U0001d754\U0001d75e\U0001d770\U0001d772\U0001d778\U0001d77c"
    "\U0001d77e\U0001d780\U0001d782\U0001d784\U0001d78e\U0001d798\U0001d7aa\U0001d7ac\U0001d7b2\U0001d7b6"
    "\U0001d7b8\U0001d7ba\U0001d7bc\U0001d7be\U0001d7c8\U0001d7cf\U0001d7d9\U0001d7e3\U0001d7ed\U0001d7f7"
    "\U0001fbf1"
)
_UNI_DST = "xifgsl8agyiiwuyiiayivopoupcja6reopcyxsijwvyheidqwwqqhnnugfoloo89o98o89oooooooo9oooooyodb2xxbxlcoouvwzrgyfyilleylvvipalxxxropcldli2sfueforruuyirwzvsclll8locsouvwwwvsiz7o3969ouyl337lllllllllllilayivopouplayivopouplayivopouplayivopouplayivopoupllllll"
_EXTRA = {"\u0259": "e", "\u014b": "n", "\u01bf": "p", "\u0131": "i"}   # schwa, eng, wynn, dotless i
_DIGIT = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"}
_PAIRS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))
_KEYBOARD = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
_KEY_POS = {c: (r, i) for r, row in enumerate(_KEYBOARD) for i, c in enumerate(row)}
CONTROLLED_SUFFIXES = (".gov.in", ".nic.in", ".bank.in", ".gov", ".mil")
COMMON_TLDS = {"com", "net", "org", "in", "co.in", "co", "io", "gov.in", "ac.in", "edu", "gov", "uk", "co.uk"}

FEATURES = [
    "dist_raw", "dist_skel", "norm_dist_skel", "len_brand", "len_query", "len_diff", "same_tld", "tld_common",
    "brand_rank_log", "skeleton_identical", "non_ascii", "mixed_script", "is_idn", "digit_lookalike",
    "pair_lookalike", "hyphen_only", "transposition", "omission", "addition", "repetition", "keyboard_neighbour",
    "vowel_swap", "bitsquat", "contains_brand", "neighbours_within_1", "query_digits", "query_hyphens",
    "prefix_match", "suffix_match",
]


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
@lru_cache(maxsize=100_000)
def decode_label(label: str) -> str:
    """xn--pypal-4ve -> pаypal (the Unicode a user would see)."""
    label = (label or "").strip().lower()
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except Exception:
            try:
                import idna
                return idna.decode(label)
            except Exception:
                return label
    return label


_UNI = dict(zip(_UNI_SRC, _UNI_DST))


@lru_cache(maxsize=10_000)
def _latin_lookalike(ch: str) -> str:
    """One character -> the Latin letter it imitates (or itself)."""
    if ch.isascii():
        return ch
    if ch in _CONFUSABLE:
        return _CONFUSABLE[ch]
    if ch in _UNI:
        return _UNI[ch]
    if ch in _EXTRA:
        return _EXTRA[ch]
    name = unicodedata.name(ch, "")
    # "LATIN SMALL LETTER C WITH HOOK" (ƈ), "LATIN LETTER SMALL CAPITAL G" (ɢ), "... M WITH HOOK" (ɱ) ...
    for prefix in ("LATIN SMALL LETTER ", "LATIN LETTER SMALL CAPITAL "):
        if name.startswith(prefix):
            rest = name[len(prefix):].split(" WITH ")[0]
            if len(rest) == 1 and rest.isalpha():
                return rest.lower()
    return ch


@lru_cache(maxsize=200_000)
def skeleton(label: str) -> str:
    """What a reader would 'see': other alphabets, digits and letter pairs that look Latin are mapped."""
    s = decode_label(label)
    s = "".join(_latin_lookalike(ch) for ch in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    if sum(ch.isdigit() for ch in s) * 2 < len(s):     # g00gle -> google, but 1984 / 365 stay numbers
        s = "".join(_DIGIT.get(ch, ch) for ch in s)
    for a, b in _PAIRS:
        s = s.replace(a, b)
    return s.replace("-", "").replace("_", "")


def _scripts(s: str) -> set:
    out = set()
    for ch in s:
        if ch.isascii():
            if ch.isalpha():
                out.add("LATIN")
            continue
        try:
            out.add(unicodedata.name(ch).split()[0])
        except ValueError:
            out.add("?")
    return out


_extract = None


def split_domain(domain: str) -> tuple[str, str, str]:
    """-> (registered domain, label left of the public suffix, suffix). Offline Public Suffix List."""
    global _extract
    if _extract is None:
        import tldextract
        _extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
    d = (domain or "").strip().lower().rstrip(".")
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":", 1)[0]
    if not d.isascii():                       # pаypal.com typed in Unicode -> xn--pypal-4ve.com (as browsers do)
        try:
            d = d.encode("idna").decode("ascii")
        except Exception:
            pass
    ext = _extract(d)
    if not ext.domain or not ext.suffix:
        return d, ext.domain or d, ext.suffix or ""
    return f"{ext.domain}.{ext.suffix}", ext.domain, ext.suffix


# ---------------------------------------------------------------------------
# Protected brand index
# ---------------------------------------------------------------------------
class BrandIndex:
    """Protected sites, searchable by skeleton. rows: list of (registered_domain, rank)."""

    def __init__(self, rows, allowlist=()):
        self.exact = {}                  # registered domain -> rank
        best = {}                        # skeleton -> (rank, label, suffix, domain)
        for dom, rank in rows:
            reg, label, suffix = split_domain(dom)
            if not label or len(skeleton(label)) < 4:
                continue
            self.exact.setdefault(reg, rank)
            sk = skeleton(label)
            if sk not in best or rank < best[sk][0]:
                best[sk] = (rank, label, suffix, reg)
        self.skeletons = list(best)
        self.info = [best[k] for k in self.skeletons]
        self.allow = set(allowlist) | set(self.exact)

    def nearest(self, sk: str, limit: int = 8):
        cutoff = max(2, min(4, len(sk) // 3))
        hits = process.extract(sk, self.skeletons, scorer=DamerauLevenshtein.distance, limit=limit,
                               score_cutoff=cutoff)
        return [(self.skeletons[i], d, self.info[i]) for _, d, i in hits]

    def to_state(self):
        return {"skeletons": self.skeletons, "info": self.info, "exact": self.exact, "allow": sorted(self.allow)}

    @classmethod
    def from_state(cls, st):
        obj = cls.__new__(cls)
        obj.skeletons, obj.info, obj.exact = st["skeletons"], [tuple(x) for x in st["info"]], st["exact"]
        obj.allow = set(st["allow"])
        return obj


# ---------------------------------------------------------------------------
# Edit-type helpers (query skeleton q vs brand skeleton b)
# ---------------------------------------------------------------------------
def _one_sub(q, b):
    if len(q) != len(b):
        return None
    diff = [i for i, (x, y) in enumerate(zip(q, b)) if x != y]
    return diff[0] if len(diff) == 1 else None


def _is_transposition(q, b):
    if len(q) != len(b) or q == b:
        return False
    diff = [i for i, (x, y) in enumerate(zip(q, b)) if x != y]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and q[diff[0]] == b[diff[1]] and q[diff[1]] == b[diff[0]]


def _is_omission(q, b):
    return len(q) == len(b) - 1 and any(b[:i] + b[i + 1:] == q for i in range(len(b)))


def _added_char(q, b):
    if len(q) != len(b) + 1:
        return None
    for i in range(len(q)):
        if q[:i] + q[i + 1:] == b:
            return i
    return None


def _keyboard_neighbour(a, b):
    pa, pb = _KEY_POS.get(a), _KEY_POS.get(b)
    return bool(pa and pb and abs(pa[0] - pb[0]) <= 1 and abs(pa[1] - pb[1]) <= 1)


def lookalike_features(domain: str, index: BrandIndex):
    """-> (features, details) or (None, details) when the domain is protected / on the allowlist itself."""
    reg, label, suffix = split_domain(domain)
    details = {"domain": reg, "brand": None, "brandDomain": None, "tricks": []}
    if not label:
        return None, details
    if reg in index.allow:
        details["allowlisted"] = True
        return None, details
    if any(("." + reg).endswith(c) for c in CONTROLLED_SUFFIXES):
        details["controlledSuffix"] = True          # only the government / RBI-approved banks can register these
        return None, details
    raw = decode_label(label)
    q = skeleton(label)
    hits = index.nearest(q) if len(q) >= 3 else []
    if not hits:
        details["noNearBrand"] = True
        return [UNK_DIST, UNK_DIST, 1.0, 0, len(q), 0, 0, float(suffix in COMMON_TLDS), 7.0, 0, float(not raw.isascii()),
                float(len(_scripts(raw)) > 1), float(label.startswith("xn--")), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                sum(c.isdigit() for c in label), label.count("-"), 0, 0], details
    # best = smallest skeleton distance, then the most popular site
    b_sk, d_skel, (rank, b_label, b_suffix, b_reg) = min(hits, key=lambda h: (h[1], h[2][0]))
    details.update(brand=b_label, brandDomain=b_reg, brandRank=rank)
    d_raw = DamerauLevenshtein.distance(raw, b_label)
    ident = float(d_skel == 0 and raw != b_label)
    non_ascii = float(not raw.isascii())
    digit_lk = float(any(c in _DIGIT for c in raw) and not any(c.isdigit() for c in b_label)
                     and DamerauLevenshtein.distance("".join(_DIGIT.get(c, c) for c in raw), b_label) < d_raw)
    pair_lk = float(any(a in raw and a not in b_label for a, _ in _PAIRS) and d_skel < d_raw)
    hyphen_only = float("-" in raw and raw.replace("-", "") == b_label)
    sub_at = _one_sub(q, b_sk)
    added = _added_char(q, b_sk)
    tricks = []
    if ident and non_ascii:
        tricks.append("letters from another alphabet")
    if digit_lk:
        tricks.append("digits that look like letters")
    if pair_lk:
        tricks.append("letter pairs that look like one letter (rn = m, vv = w)")
    if hyphen_only:
        tricks.append("an extra hyphen")
    feats = {
        "dist_raw": d_raw, "dist_skel": d_skel, "norm_dist_skel": d_skel / max(len(b_sk), 1),
        "len_brand": len(b_sk), "len_query": len(q), "len_diff": len(q) - len(b_sk),
        "same_tld": float(suffix == b_suffix), "tld_common": float(suffix in COMMON_TLDS),
        "brand_rank_log": math.log10(max(rank, 1)), "skeleton_identical": ident, "non_ascii": non_ascii,
        "mixed_script": float(len(_scripts(raw)) > 1), "is_idn": float(label.startswith("xn--")),
        "digit_lookalike": digit_lk, "pair_lookalike": pair_lk, "hyphen_only": hyphen_only,
        "transposition": float(_is_transposition(q, b_sk)), "omission": float(_is_omission(q, b_sk)),
        "addition": float(added is not None),
        "repetition": float(added is not None and ((added > 0 and q[added] == q[added - 1]) or
                                                   (added + 1 < len(q) and q[added] == q[added + 1]))),
        "keyboard_neighbour": float(sub_at is not None and _keyboard_neighbour(q[sub_at], b_sk[sub_at])),
        "vowel_swap": float(sub_at is not None and q[sub_at] in "aeiou" and b_sk[sub_at] in "aeiou"),
        "bitsquat": float(sub_at is not None and bin(ord(q[sub_at]) ^ ord(b_sk[sub_at])).count("1") == 1),
        "contains_brand": float(b_sk in q and q != b_sk),
        "neighbours_within_1": float(sum(1 for _, d, _ in hits if d <= 1)),
        "query_digits": float(sum(c.isdigit() for c in label)), "query_hyphens": float(label.count("-")),
        "prefix_match": float(os.path.commonprefix([q, b_sk]).__len__()) / max(len(b_sk), 1),
        "suffix_match": float(os.path.commonprefix([q[::-1], b_sk[::-1]]).__len__()) / max(len(b_sk), 1),
    }
    for key, name in (("transposition", "two letters swapped"), ("omission", "a letter left out"),
                      ("repetition", "a letter doubled"), ("keyboard_neighbour", "a neighbouring key typed"),
                      ("vowel_swap", "a vowel changed"), ("bitsquat", "a one-bit character change")):
        if feats[key]:
            tricks.append(name)
    if feats["addition"] and not feats["repetition"]:
        tricks.append("an extra letter")
    if d_skel == 0 and not ident and suffix != b_suffix:
        tricks.append(f"the same name with a different ending (.{suffix} instead of .{b_suffix})")
    if sub_at is not None and not tricks:
        tricks.append("one letter changed")
    details["tricks"] = tricks
    return [float(feats[n]) for n in FEATURES], details


UNK_DIST = 10.0

# ---------------------------------------------------------------------------
# Scanner entry point
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
            ok = isinstance(b, dict) and b.get("kind") == "cyberguard-lookalike" and list(b["features"]) == FEATURES
            b = {**b, "index_obj": BrandIndex.from_state(b["index"])} if ok else None
        except Exception:
            b = None
        _cache.update(mtime=mtime, bundle=b)
    return _cache.get("bundle")


def assess(domain: str):
    """-> dict with probability, level and plain-language details, or None if no model / nothing to judge."""
    b = load_model()
    if b is None or not domain:
        return None
    feats, details = lookalike_features(domain, b["index_obj"])
    if feats is None:
        return {"probability": 0.0, "level": "low", **details}
    p = float(b["model"].predict_proba([feats])[0][1])
    level = "high" if p >= b["thr_alert"] else "medium" if p >= b["thr_verify"] else "low"
    if feats[FEATURES.index("dist_raw")] == 0 and level == "high":
        # exactly the same name, only the ending differs (britishcouncil.gr, paypal.co): big brands own many of
        # their country domains, so the name alone cannot prove an imitation -> "verify", not "alert"
        level = "medium"
        details["sameNameOtherEnding"] = True
    return {"probability": p, "level": level, "thrAlert": b["thr_alert"], "thrVerify": b["thr_verify"], **details}
