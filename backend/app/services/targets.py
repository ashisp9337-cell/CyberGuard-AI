"""
Who is being targeted?  Used by the dashboard's "Most targeted" widget.

For every threat scan we work out:
  * services  - the organisation/brand the attacker pretended to be or attacked
                (SBI, Income Tax Department, Microsoft, BPUT ...)
  * accounts  - the user accounts / mailboxes that were attacked
                (email recipients, usernames in login logs)

Nothing is guessed: if no known organisation or account name appears in the
scan, that scan simply adds nothing to the list.
"""
import re

from app.email_pipeline import org_directory as orgs

# Usernames inside pasted login logs ("user=alice", "Failed password for root", ...)
_USER_RES = [
    re.compile(r"invalid user ([\w.@-]+)", re.I),
    re.compile(r"failed password for (?:invalid user )?([\w.@-]+)", re.I),
    re.compile(r"\b(?:user(?:name)?|account|upn|login)\s*[=:]\s*\"?([\w.@-]+)", re.I),
]
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_SKIP_ACCOUNTS = {"unknown", "-", "none", "null", "n/a"}


def _url_words(text: str) -> str:
    """'https://sbi-yono-kyc.web.app/x' -> 'sbi yono kyc web app x' so brand names inside a link are found."""
    return re.sub(r"[^a-z0-9]+", " ", text.lower())


def services_for(scan) -> list[dict]:
    """Organisations targeted/impersonated in one scan: [{"name", "category"}]."""
    result = scan.result or {}
    email = result.get("email") or {}

    # Emails: the pipeline already worked out which organisation the mail claims to be.
    claimed = email.get("claimed_entities") or []
    if claimed:
        seen, out = set(), []
        for c in claimed:
            if c.get("name") and c["name"] not in seen:
                seen.add(c["name"])
                out.append({"name": c["name"], "category": c.get("category", "")})
        return out

    # Everything else: look for known organisation names in what was scanned.
    text = " ".join([scan.target or "", result.get("explanation", "") or ""])
    is_url = scan.input_type == "url" or scan.module_id == "url-security"
    if is_url:
        text += " " + _url_words(scan.target or "")
    found = orgs.find_entities(text)
    if is_url:
        found += [e for e in _brands_inside_link(scan.target or "") if e not in found]
    return [{"name": e["name"], "category": e["category"]} for e in found]


def _brands_inside_link(url: str) -> list[dict]:
    """Brand names glued to other words in a link: 'microsoftonline', 'paypalsecure', 'hdfcbanklogin'.
    Only one-word names of 5+ letters are matched this way, so short ones ('sbi') can't fire by accident."""
    host = re.sub(r"^[a-z]+://", "", url.lower()).split("/")[0].split("@")[-1]
    labels = [p for p in re.split(r"[.\-_]", host) if p]
    out = []
    for e in orgs.ORG_ENTITIES:
        for kw in e["keywords"]:
            if len(kw) >= 5 and " " not in kw and any(kw in lab for lab in labels):
                out.append(e)
                break
    return out


def accounts_for(scan) -> list[str]:
    """User accounts / mailboxes attacked in one scan."""
    result = scan.result or {}
    email = result.get("email") or {}
    found = [a.lower() for a in (email.get("to_addresses") or [])]

    if scan.module_id == "credential":
        text = scan.target or ""
        for rx in _USER_RES:
            found += [m.lower().strip(".,;") for m in rx.findall(text)]
        found += [m.lower() for m in _EMAIL_RE.findall(text)]

    out, seen = [], set()
    for a in found:
        if a and a not in seen and a not in _SKIP_ACCOUNTS:
            seen.add(a)
            out.append(a)
    return out