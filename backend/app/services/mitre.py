"""
MITRE ATT&CK mapping: which attacker technique a detection points to, explained in plain language.

Every saved scan (manual or automatic, see app/services/scan_store.py) gets:
    result["mitre"]        = ["T1566.002", "T1583.001", ...]   technique IDs, most specific first
    result["mitreDetails"] = [{id, name, tactic, explanation, url, evidence: [...]}, ...]

Where the IDs come from, in order:
  1. Technique IDs the detector already attached (email pipeline, account-takeover signals,
     cyber-threat command patterns, attachment checks).
  2. Rules on the triggered indicators (look-alike domain -> T1583.001, redirect -> T1608.005 ...).
  3. A sensible default for the module when nothing more specific matched
     (an SMS phishing hit -> T1660, an impersonation hit -> T1656 ...).

Safe results get no techniques: a technique is only shown when there is something to explain.
Source of names and tactics: MITRE ATT&CK Enterprise and Mobile matrices (attack.mitre.org).
"""
from __future__ import annotations

# id: (name, tactic, plain-language explanation)
CATALOGUE: dict[str, tuple[str, str, str]] = {
    # ---- Initial access: phishing family
    "T1566": ("Phishing", "Initial Access",
              "The attacker sends a fake message to trick someone into clicking a link, opening a file or "
              "handing over information. It is the most common way attacks start."),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access",
                  "The fake message carries a harmful file (invoice, document, archive). Opening it runs the "
                  "attacker's code or asks for a password."),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access",
                  "The fake message carries a link to a page the attacker controls, usually a copy of a real "
                  "login or payment page that steals what you type."),
    "T1566.003": ("Phishing: Spearphishing via Service", "Initial Access",
                  "The fake message arrives through a social network or chat app instead of email, where people "
                  "are less careful."),
    "T1660": ("Phishing (Mobile, SMS)", "Initial Access (Mobile)",
              "Smishing: a fake SMS or messaging-app text, often pretending to be a bank, courier or government "
              "office, that pushes you to tap a link or call a number."),
    "T1534": ("Internal Spearphishing", "Lateral Movement",
              "The attacker uses (or pretends to be) a trusted insider such as a manager to send phishing to "
              "colleagues, because people trust messages from inside the organisation."),
    # ---- Impersonation / infrastructure
    "T1656": ("Impersonation", "Defense Evasion",
              "The attacker pretends to be a trusted person or organisation (bank, government office, teacher, "
              "boss) so the victim follows instructions without checking."),
    "T1583.001": ("Acquire Infrastructure: Domains", "Resource Development",
                  "The attacker registers a look-alike or brand-new domain (for example sbi-kyc-update.top) so "
                  "the link looks believable at a glance."),
    "T1608.005": ("Stage Capabilities: Link Target", "Resource Development",
                  "The attacker prepares the page a phishing link points to, often hidden behind redirects or "
                  "URL shorteners so filters cannot see the real destination."),
    "T1204.001": ("User Execution: Malicious Link", "Execution",
                  "The attack only works if the victim clicks the link. That is why the message uses urgency, "
                  "fear or a reward."),
    "T1204.002": ("User Execution: Malicious File", "Execution",
                  "The attack only works if the victim opens the file, so it is disguised as something expected "
                  "such as an invoice or assignment."),
    # ---- Credential access / accounts
    "T1110": ("Brute Force", "Credential Access",
              "Many password guesses against an account until one works. Repeated failed sign-ins are the sign."),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access",
                  "Repeated guesses against one account, often common passwords such as 123456 or the account "
                  "name."),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access",
                  "A few common passwords tried across many real accounts, slowly, so no single account gets "
                  "locked out."),
    "T1078": ("Valid Accounts", "Initial Access, Persistence, Defense Evasion",
              "The attacker signs in with a real, stolen username and password, so the activity looks normal. "
              "Unusual place, device or time gives it away."),
    "T1078.003": ("Valid Accounts: Local Accounts", "Privilege Escalation",
                  "A local account is used or given more rights than normal, letting the attacker control the "
                  "machine."),
    "T1090": ("Proxy", "Command and Control",
              "Traffic is routed through a VPN, proxy or Tor so the attacker's real location is hidden."),
    "T1098": ("Account Manipulation", "Persistence",
              "After getting in, the attacker changes the account (password, recovery email, permissions) to "
              "keep control and lock the owner out."),
    "T1556": ("Modify Authentication Process", "Credential Access, Persistence",
              "Sign-in protection such as multi-factor authentication is changed or switched off so the "
              "attacker can get back in."),
    "T1114.003": ("Email Collection: Email Forwarding Rule", "Collection",
                  "A hidden rule silently copies the victim's incoming mail to the attacker."),
    # ---- Execution / defence evasion on hosts
    "T1059": ("Command and Scripting Interpreter", "Execution",
              "The attacker runs commands through a shell or script, for example a reverse shell that gives "
              "them remote control."),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution",
                  "PowerShell is used to run attacker code, often encoded (-enc) or with Invoke-Expression so it "
                  "is hard to read."),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution",
                  "cmd.exe is used to run attacker commands."),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", "Execution",
                  "VBScript run through wscript or cscript, a common way malicious attachments start."),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion",
              "Commands or files are encoded or scrambled (Base64, hex escapes) so security tools and people "
              "cannot read them easily."),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access",
                  "Tools such as mimikatz read passwords and tokens out of Windows memory."),
    "T1105": ("Ingress Tool Transfer", "Command and Control",
              "The attacker downloads more tools onto the machine, for example with certutil -urlcache."),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", "Defense Evasion",
                  "A trusted Windows program (regsvr32) is abused to run attacker code and slip past defences."),
    # ---- Exfiltration / impact
    "T1567": ("Exfiltration Over Web Service", "Exfiltration",
              "Data is copied out to a cloud or file-sharing service (Mega, Drive, Dropbox) that looks like "
              "normal web traffic."),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration",
              "A large amount of data leaves the network over a channel that is not normally used for it."),
    "T1052.001": ("Exfiltration over Physical Medium: USB", "Exfiltration",
                  "Data is copied to a USB drive or other removable media."),
    "T1499": ("Endpoint Denial of Service", "Impact",
              "A flood of requests overwhelms a service or API so real users cannot use it."),
}

# ---- indicator-label rules -> technique
LABEL_RULES: list[tuple[tuple[str, ...], str]] = [
    (("look-alike", "lookalike", "typosquat", "newly registered", "new domain", "young domain", "domain age",
      "brand name in", "impersonates a brand", "brand impersonation"), "T1583.001"),
    (("redirect", "shortener", "shortened", "hides the real destination"), "T1608.005"),
    (("attachment", "macro", "executable"), "T1204.002"),
    (("impersonat", "claims to be", "display name", "does not match the claimed"), "T1656"),
]

URL_SUBTOPIC_EXTRA: dict[str, list[str]] = {
    "domain-spoofing": ["T1656"],
    "lookalike-domain": ["T1583.001"],
    "redirect-analysis": ["T1608.005"],
    "fake-login-page": ["T1608.005"],
}
MODULE_DEFAULTS: dict[str, list[str]] = {
    "url-security": ["T1566.002"],
    "impersonation": ["T1656", "T1566"],
    "deepfake": ["T1656"],
}
PHISHING_SUBTOPIC_DEFAULTS: dict[str, list[str]] = {
    "sms-analysis": ["T1660"],
    "social-media-analysis": ["T1566.003"],
    "qr-phishing": ["T1566.002"],
    "malicious-url": ["T1566.002"],
    "fraudulent-website": ["T1566.002"],
    "email-analysis": ["T1566"],
}
CREDENTIAL_SUBTOPIC_DEFAULTS: dict[str, list[str]] = {
    "failed-logins": ["T1110"],
    "password-spraying": ["T1110.003"],
    "unusual-location": ["T1078"],
    "unknown-device": ["T1078"],
    "session-activity": ["T1078"],
    "behavior-changes": ["T1078", "T1098"],
}


def url_for(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _ids(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        value = [value]
    return [v.strip().upper() for v in value if isinstance(v, str) and v.strip().upper().startswith("T")]


def map_result(module_id: str, subtopic_id: str, result: dict) -> list[str]:
    """Technique IDs for one detector result, most specific first. Safe results map to nothing."""
    if result.get("classification", "safe") == "safe":
        return []
    out: list[str] = []
    evidence: dict[str, list[str]] = {}

    def add(tid: str, why: str | None = None):
        if tid not in out:
            out.append(tid)
        if why:
            evidence.setdefault(tid, [])
            if why not in evidence[tid] and len(evidence[tid]) < 4:
                evidence[tid].append(why)

    for tid in _ids(result.get("mitre")):
        add(tid)
    for ind in result.get("indicators", []):
        if not ind.get("triggered"):
            continue
        for tid in _ids(ind.get("mitre")):
            add(tid, ind.get("label"))
        label = (ind.get("label", "") + " " + ind.get("description", "")).lower()
        for keys, tid in LABEL_RULES:
            if any(k in label for k in keys):
                add(tid, ind.get("label"))
    if module_id == "phishing":
        for tid in PHISHING_SUBTOPIC_DEFAULTS.get(subtopic_id, ["T1566"]):
            add(tid)
    elif module_id == "credential":
        if not any(t.startswith(("T1110", "T1078", "T1098", "T1556")) for t in out):
            for tid in CREDENTIAL_SUBTOPIC_DEFAULTS.get(subtopic_id, ["T1078"]):
                add(tid)
    elif module_id == "impersonation":
        for tid in MODULE_DEFAULTS["impersonation"]:
            add(tid)
        if subtopic_id == "management-impersonation":
            add("T1534")
    elif module_id in MODULE_DEFAULTS:
        for tid in MODULE_DEFAULTS[module_id]:
            add(tid)
        if module_id == "url-security":
            for tid in URL_SUBTOPIC_EXTRA.get(subtopic_id, []):
                add(tid)
    # A sub-technique makes its parent redundant (T1566.002 already says "phishing").
    out = [t for t in out if not ("." not in t and any(o.startswith(t + ".") for o in out))]
    result["_mitreEvidence"] = {t: evidence.get(t, []) for t in out}
    return out[:8]


def describe(ids: list[str], evidence: dict | None = None) -> list[dict]:
    evidence = evidence or {}
    out = []
    for tid in ids:
        name, tactic, explanation = CATALOGUE.get(tid, ("MITRE ATT&CK technique", "", "See the MITRE ATT&CK page for details."))
        out.append({"id": tid, "name": name, "tactic": tactic, "explanation": explanation, "url": url_for(tid),
                    "evidence": list(evidence.get(tid, []))})
    return out


def brief(ids: list[str]) -> list[dict]:
    """Short form for lists (incidents, alerts): id, name, tactic, explanation, url."""
    return [{k: d[k] for k in ("id", "name", "tactic", "explanation", "url")} for d in describe(ids)]


def annotate(module_id: str, subtopic_id: str, result: dict) -> list[str]:
    """Set result["mitre"] and result["mitreDetails"]; returns the IDs."""
    ids = map_result(module_id, subtopic_id, result)
    ev = result.pop("_mitreEvidence", {})
    result["mitre"] = ids
    result["mitreDetails"] = describe(ids, ev)
    return ids
