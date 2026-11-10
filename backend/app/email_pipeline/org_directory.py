"""
Who is allowed to send as whom.

A list of organisations that phishers commonly pretend to be, the keywords
that show an email is claiming to be them, and the domains they really send
from. Enrichment uses it to answer: "this email says it is from X — is the
sender domain actually X's?"

Extend ORG_ENTITIES for your users (your own college, company, local banks).
A real organisation missing from this list can never cause a false alarm on
its own: it is simply not checked.
"""
import json
import os
import re

from app.detectors.url_features_v2 import BRAND_DOMAINS

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mail.com",
    "gmx.com", "gmx.net", "zoho.com", "zohomail.in", "protonmail.com", "proton.me",
    "rediffmail.com", "yandex.com", "yandex.ru", "tutanota.com", "mail.ru", "inbox.com",
}

# Suffixes only government bodies can register in India (and a few abroad).
GOVERNMENT_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".gov.uk", ".mil")
EDUCATION_SUFFIXES = (".ac.in", ".edu", ".edu.in", ".res.in", ".ac.uk", ".edu.au")

EXECUTIVE_TITLES = re.compile(
    r"\b(ceo|cfo|coo|cto|md|managing director|chairman|chairperson|founder|co-founder|president|"
    r"vice president|vp|director|head of [a-z]+|general manager|boss|partner)\b", re.I)

ACADEMIC_TITLES = re.compile(
    r"\b(hod|head of department|professor|prof\.?|dean|registrar|principal|vice[- ]chancellor|"
    r"controller of examinations?|examination cell|exam cell|faculty|university|college)\b", re.I)

# ---------------------------------------------------------------------------
# Organisation entities
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_FIN_JSON = os.path.join(_HERE, "..", "ml", "training", "data", "financial_institutions.json")


BANK_ALIASES = {
    "sbi": ["state bank of india", "sbi yono", "yono sbi"],
    "hdfc bank": ["hdfc"],
    "icici bank": ["icici"],
    "punjab national bank": ["pnb"],
    "kotak mahindra bank": ["kotak"],
    "bank of baroda": ["bob world", "bob card"],   # (10 Nov) not "bob" (a name) or "baroda" (the city)
    "union bank of india": ["union bank"],
    "idfc first bank": ["idfc"],
}


COMMON_WORDS = {"yes", "first", "axis", "union", "indian", "central", "federal", "capital", "unity", "city"}


def _load_banks() -> list[dict]:
    try:
        with open(_FIN_JSON, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    out = []
    given = data.get("_keywords") or {}         # (10 Nov) banks added from RBI's list name their own keywords
    for name, domains in data.items():
        if name.startswith("_") or name in ("rbi", "reserve bank of india", "state bank of india"):
            continue                            # RBI is a government entity below; "state bank of india" = sbi
        if name in given:                       # the list's own names replace the raw key ("chase" -> "chase bank")
            kws = set(given[name]) | set(BANK_ALIASES.get(name, []))
        else:
            kws = {name} | set(BANK_ALIASES.get(name, []))
            # "hdfc bank" -> "hdfc". (10 Nov) Never an everyday word or an "of ..." phrase: "axis" (x-axis), "union of
            # india" (court papers), "of america" are not banks.
            short = name[: -len(" bank")].strip() if name.endswith(" bank") else ""
            if len(short) >= 4 and " of " not in f" {short} " and short not in COMMON_WORDS:
                kws.add(short)
        out.append({"name": name.title() if len(name) > 4 else name.upper(), "category": "bank",
                    "keywords": sorted(kws), "domains": set(domains), "suffixes": ()})
    return out


ORG_ENTITIES: list[dict] = [
    # ---- Government (India) -----------------------------------------------
    {"name": "Income Tax Department", "category": "government",
     "keywords": ["income tax department", "income tax", "incometax"],
     "domains": {"incometax.gov.in", "incometaxindia.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "UIDAI / Aadhaar", "category": "government", "keywords": ["uidai", "aadhaar", "aadhar"],
     "domains": {"uidai.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "Reserve Bank of India", "category": "government", "keywords": ["reserve bank of india", "rbi"],
     "domains": {"rbi.org.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "CBI / Police / Cyber Crime", "category": "government",
     "keywords": ["cbi", "central bureau of investigation", "cyber crime", "cybercrime", "police",
                  "narcotics", "ncb", "enforcement directorate", "digital arrest", "crime branch"],
     "domains": {"cbi.gov.in", "cybercrime.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "TRAI / DoT", "category": "government",
     "keywords": ["trai", "telecom regulatory", "department of telecommunications"],
     "domains": {"trai.gov.in", "dot.gov.in", "sancharsaathi.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "Passport Seva / MEA", "category": "government", "keywords": ["passport seva", "passport office"],
     "domains": {"passportindia.gov.in", "mea.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "EPFO", "category": "government", "keywords": ["epfo", "provident fund"],
     "domains": {"epfindia.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "Parivahan / e-Challan", "category": "government", "keywords": ["parivahan", "e-challan", "echallan", "traffic challan"],
     "domains": {"parivahan.gov.in", "echallan.parivahan.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "Customs", "category": "government", "keywords": ["customs department", "indian customs", "cbic"],
     "domains": {"cbic.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    # ---- Education -------------------------------------------------------
    {"name": "AICTE / UGC", "category": "education", "keywords": ["aicte", "ugc", "university grants commission"],
     "domains": {"aicte-india.org", "ugc.gov.in", "ugc.ac.in"}, "suffixes": GOVERNMENT_SUFFIXES + EDUCATION_SUFFIXES},
    {"name": "BPUT", "category": "education", "keywords": ["bput", "biju patnaik university"],
     "domains": {"bput.ac.in"}, "suffixes": ()},
    # ---- Payment apps & brands frequently impersonated in India -----------------
    {"name": "Paytm", "category": "brand", "keywords": ["paytm"], "domains": {"paytm.com", "paytmbank.com", "paytmmoney.com"}, "suffixes": ()},
    {"name": "PhonePe", "category": "brand", "keywords": ["phonepe"], "domains": {"phonepe.com"}, "suffixes": ()},
    {"name": "Google Pay", "category": "brand", "keywords": ["google pay", "gpay"], "domains": {"google.com"}, "suffixes": ()},
    {"name": "NPCI / UPI", "category": "brand", "keywords": ["npci", "bhim"], "domains": {"npci.org.in", "bhimupi.org.in"}, "suffixes": ()},
    {"name": "IRCTC", "category": "brand", "keywords": ["irctc"], "domains": {"irctc.co.in"}, "suffixes": ()},
    {"name": "Jio", "category": "brand", "keywords": ["jio", "reliance jio"], "domains": {"jio.com", "ril.com"}, "suffixes": ()},
    {"name": "Airtel", "category": "brand", "keywords": ["airtel"], "domains": {"airtel.in", "airtel.com"}, "suffixes": ()},
    {"name": "India Post", "category": "brand", "keywords": ["india post", "indiapost", "speed post"], "domains": {"indiapost.gov.in"}, "suffixes": GOVERNMENT_SUFFIXES},
    {"name": "Meta / Instagram", "category": "brand", "keywords": ["instagram"], "domains": {"instagram.com", "facebookmail.com", "meta.com", "facebook.com", "mail.instagram.com"}, "suffixes": ()},
] + _load_banks()

# Global brands from the URL detector's list (paypal, microsoft, amazon, ...).
_existing = {kw for e in ORG_ENTITIES for kw in e["keywords"]}
for _brand, _domains in BRAND_DOMAINS.items():
    if _brand in _existing or _brand in ("onlinesbi", "hdfcbank", "icicibank", "axisbank", "chase", "ledger", "allegro"):
        continue                    # (10 Nov) chase / ledger / allegro are everyday words (brand_text.AMBIGUOUS)
    _extra = set()
    if _brand == "microsoft":
        _extra = {"microsoftonline.com", "accountprotection.microsoft.com"}
    if _brand == "amazon":
        _extra = {"amazon.in"}
    ORG_ENTITIES.append({"name": _brand.title(), "category": "brand", "keywords": [_brand],
                         "domains": set(_domains) | _extra, "suffixes": ()})

# Short keywords (<=4 chars, e.g. "sbi", "rbi", "cbi") must match as whole
# words; longer ones can match anywhere.
for _e in ORG_ENTITIES:
    _e["_patterns"] = [re.compile(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", re.I) for k in _e["keywords"]]


def registered(domain: str) -> str:
    from app.detectors.url_features_v2 import registered_domain
    return registered_domain((domain or "").lower())


def is_official_sender(entity: dict, domain: str) -> bool:
    """True if `domain` legitimately belongs to the organisation."""
    domain = (domain or "").lower()
    if not domain or domain in FREEMAIL_DOMAINS:
        return False
    reg = registered(domain)
    for d in entity["domains"]:
        if domain == d or domain.endswith("." + d) or reg == d:
            return True
    # (10 Nov) <bank>.bank.in: RBI's zone that only real Indian banks can register (IDRBT checks every one), so
    # kotak.bank.in / hdfc.bank.in are the bank's own even when our list has only the older .com address.
    if entity.get("category") == "bank" and reg.endswith(".bank.in"):
        label = reg[: -len(".bank.in")]
        for k in entity.get("keywords", []):
            k = k.replace(" ", "")
            if label == k or (len(k) >= 4 and label.startswith(k)):
                return True
    return any(domain.endswith(s) for s in entity.get("suffixes", ()))


def find_entities(text: str) -> list[dict]:
    """Organisations mentioned in a piece of text."""
    if not text:
        return []
    hits = []                                   # (entity, [(start, end) of each name match])
    for e in ORG_ENTITIES:
        spans = [(m.start(), m.end()) for p in e["_patterns"] for m in p.finditer(text)]
        if spans:
            hits.append((e, spans))
    # (10 Nov) a name inside a longer name of ANOTHER organisation is not a mention of it: "State Bank of India"
    # and "Reserve Bank of India" contain "Bank of India", "Indian Overseas Bank" is not "Indian Bank".
    def inside_other(e, span):
        return any(o is not e and os_ <= span[0] and span[1] <= oe and (oe - os_) > (span[1] - span[0])
                   for o, spans in hits for os_, oe in spans)
    return [e for e, spans in hits if any(not inside_other(e, sp) for sp in spans)]


def official_sender_entity(sender_domain: str, text: str) -> dict | None:
    """(10 Nov) The organisation named in `text` that `sender_domain` really belongs to, else None.
    A genuine alert from alerts@hdfcbank.net that mentions the shop you paid (Zomato, Amazon) comes from HDFC Bank:
    the shop's name is not a claim to BE the shop. Free-mail addresses never count."""
    domain = (sender_domain or "").lower().strip()
    if not domain or domain in FREEMAIL_DOMAINS:
        return None
    for e in find_entities(text or ""):
        if is_official_sender(e, domain):
            return e
    return None
