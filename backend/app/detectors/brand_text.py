"""
Shared helpers for Organization/Brand Impersonation.

mask_brands(): replaces any known brand name in a text with a neutral token
BEFORE it reaches the classifier (both at training time and at scan time).
Why: in real data, phishing messages mention brand names far more often than
ordinary chat does, so an unmasked model learns "mentions Netflix = phishing"
— it flags "watching netflix tonight" as a scam. Masking forces the model to
learn from the SURROUNDING language (urgency, verify/pay/click demands,
threats) instead of from which brand is named.

find_brands(): returns which known brands a text claims to be from — used by
the detector for the sender-domain check.

Uses whole-word matching. (A plain substring match makes "irs" match the word
"first" — a bug that also existed in the project's original rule layer.)
"""
from __future__ import annotations

import re

from app.detectors.url_features_v2 import BRAND_DOMAINS

# Extra names people use for a brand -> the BRAND_DOMAINS key they belong to.
BRAND_ALIASES = {
    "iphone": "apple", "ipad": "apple", "macbook": "apple", "icloud": "apple", "apple id": "apple",
    "gmail": "google", "youtube": "google", "google pay": "google", "gpay": "google",
    "office 365": "microsoft", "office365": "microsoft", "outlook": "microsoft", "xbox": "microsoft",
    "amazon prime": "amazon", "prime video": "amazon",
    "i.r.s": "irs", "insta": "instagram", "fb": "facebook",
    "trust wallet": "trustwallet", "ledger live": "ledger",
}

MASK_TOKEN = "brandx"

# Brand names that are also everyday words. Matching them in free text would
# produce false "this message claims to be from <brand>" hits ("chase after her").
AMBIGUOUS = {"chase", "ledger", "allegro"}


def _build_pattern() -> re.Pattern:
    names = (set(BRAND_DOMAINS.keys()) | set(BRAND_ALIASES.keys())) - AMBIGUOUS
    # longest first so "amazon prime" wins over "amazon"
    ordered = sorted(names, key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(n) for n in ordered) + r")(?![a-z0-9])", re.I)


_PATTERN = _build_pattern()


def mask_brands(text: str) -> str:
    return _PATTERN.sub(MASK_TOKEN, text or "")


def find_brands(text: str) -> list[str]:
    """Canonical BRAND_DOMAINS keys named in the text, in order of first appearance, de-duplicated."""
    found: list[str] = []
    for m in _PATTERN.finditer(text or ""):
        name = m.group(1).lower()
        canonical = BRAND_ALIASES.get(name, name)
        if canonical in BRAND_DOMAINS and canonical not in found:
            found.append(canonical)
    return found