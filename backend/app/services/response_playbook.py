"""
Response playbook: turns a detection result into SPECIFIC response actions.

Before this, every result at the same risk level got the same generic advice
("Block the source immediately"), whatever the threat was. Now the actions
depend on WHAT was detected:

    phishing email      -> quarantine email, block the link's domain, warn user
    account takeover    -> revoke sessions, force password reset + MFA, block IP
    impersonation       -> report impersonation (1930 / cybercrime.gov.in), verify via official channel
    deepfake media      -> flag for manual verification
    malware / exfil     -> isolate host, block outbound destination
    high / critical     -> notify SOC, escalate incident, preserve evidence

Each action:
    {"id", "action", "title", "detail", "priority", "owner"}
    action   - one of the 10 response types from the problem statement (+ a few extras)
    priority - "immediate" | "high" | "normal"
    owner    - "user" (the person who got the message) or "soc" (admin / security team)

Nothing is executed here; these are recommendations. Automatic execution
(quarantine, alerts) comes in the Response & Notifications module.
"""
import re
from urllib.parse import urlparse

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.I)
PRIVATE_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)")

THREAT_LEVELS = ("suspicious", "high_risk", "critical")
PRIORITY_ORDER = {"immediate": 0, "high": 1, "normal": 2}

# India-specific reporting channels (official).
REPORT_CYBERCRIME = "Report it on the National Cyber Crime Reporting Portal (cybercrime.gov.in) or call 1930"
REPORT_CHAKSHU = "Report the fraud message/call on Sanchar Saathi → Chakshu (sancharsaathi.gov.in)"


def _has(labels: set[str], *words: str) -> bool:
    return any(w in lab for lab in labels for w in words)


def _hosts(text: str) -> list[str]:
    out = []
    for u in URL_RE.findall(text or ""):
        host = urlparse(u if "://" in u else "http://" + u).hostname or ""
        if host and host not in out:
            out.append(host)
    return out


def _public_ips(text: str) -> list[str]:
    out = []
    for ip in IP_RE.findall(text or ""):
        if not PRIVATE_IP.match(ip) and ip not in out:
            out.append(ip)
    return out


def _is_official(host: str) -> bool:
    try:
        from app.detectors import trusted_domains
        return trusted_domains.is_trusted("https://" + host + "/")
    except Exception:
        return False


def build_actions(result: dict, module_id: str, subtopic_id: str, target: str = "") -> list[dict]:
    classification = result.get("classification", "safe")
    if classification not in THREAT_LEVELS:
        return []

    labels = {i["label"].lower() for i in result.get("indicators", []) if i.get("triggered")}
    labels |= {(i.get("label") or "").lower() for i in (result.get("email") or {}).get("indicators", []) if i.get("triggered")}
    email = result.get("email") or {}
    text = " ".join([target or "", " ".join(l.get("url", "") for l in email.get("links", []) if isinstance(l, dict))])
    hosts = _hosts(text)
    if module_id == "url-security" or subtopic_id in ("malicious-url", "fraudulent-website", "qr-phishing"):
        h = urlparse(target if "://" in (target or "") else "http://" + (target or "")).hostname
        if h and h not in hosts:
            hosts.insert(0, h)
    hosts = [h for h in hosts if not _is_official(h)]   # never block a real bank/brand site
    ips = _public_ips(target)
    if (result.get("category") or "").startswith("Possible account takeover"):
        module_id = "credential"   # a genuine security alert about the user's own account
    high = classification in ("high_risk", "critical")
    critical = classification == "critical"
    is_email = subtopic_id == "email-analysis" or bool(email)

    actions: list[dict] = []

    def add(action, title, detail, priority="high", owner="soc"):
        if not any(a["action"] == action and a["title"] == title for a in actions):
            actions.append({"id": f"{action}:{len(actions)}", "action": action, "title": title,
                            "detail": detail, "priority": priority, "owner": owner})

    # ---------------- Phishing / URLs / QR ----------------
    if module_id in ("phishing", "url-security"):
        if is_email and (result.get("quarantine") or {}).get("status") == "quarantined":
            add("quarantine_email", "Email quarantined automatically",
                "CYBERGUARD has already held this email in quarantine. Release it from the dashboard only if you are sure it is safe.",
                "immediate")
        elif is_email:
            add("quarantine_email", "Quarantine this email",
                "Move it out of the inbox for everyone who received it, so nobody else clicks it.",
                "immediate")
        for h in hosts[:3]:
            add("block_url", f"Block {h}",
                f"Add {h} to the DNS / web-proxy blocklist so the link cannot be opened from the network.",
                "immediate" if high else "high")
        if subtopic_id == "qr-phishing" or _has(labels, "qr"):
            add("warn_user", "Do not scan or pay through this QR code",
                "QR codes can hide a fake payment or login page. Pay only by typing the merchant's UPI ID yourself.",
                "immediate", "user")
        if _has(labels, "credential", "login", "password", "otp", "kyc", "verify"):
            add("reset_credentials", "If anything was entered, change the password now",
                "If you typed a password, OTP or card details on the page, change the password, enable MFA and call your bank.",
                "immediate", "user")
        if subtopic_id in ("sms-analysis", "social-media-analysis"):
            add("report_impersonation", "Report the message", f"{REPORT_CHAKSHU}. If money was lost: {REPORT_CYBERCRIME}.",
                "high", "user")
        elif hosts and not is_email:
            add("report_impersonation", "Report the phishing site",
                "Report it to the brand it copies and on cybercrime.gov.in so it can be taken down.", "normal", "user")

    # ---------------- Impersonation ----------------
    if module_id == "impersonation" or _has(labels, "impersonat", "look-alike sender", "display name"):
        add("warn_user", "Do not reply, pay or share OTP",
            "Verify the person through a phone number or website you already know -- never the contact details in this message.",
            "immediate", "user")
        add("report_impersonation", "Report the impersonation",
            f"Inform the real organisation/person being impersonated. {REPORT_CYBERCRIME}.", "high", "user")
        if subtopic_id == "government-impersonation" or _has(labels, "digital arrest", "government", "police", "cbi"):
            add("warn_user", "There is no 'digital arrest' in Indian law",
                "Police, CBI, ED and customs never demand money or keep you on a video call. Hang up and report it.",
                "immediate", "user")
        if subtopic_id in ("financial-impersonation", "management-impersonation") or _has(labels, "payment", "gift card", "transfer", "bank"):
            add("hold_payment", "Hold any payment or transfer",
                "Do not move money until the request is confirmed by a call-back on a known number. If money was sent, call 1930 within the first hour.",
                "immediate", "user")

    # ---------------- Account takeover ----------------
    if module_id == "credential":
        takeover = _has(labels, "successful login after", "impossible travel", "mfa", "attack chain",
                        "forwarding", "recovery", "privilege")
        if takeover or high:
            add("revoke_session", "Revoke all active sessions",
                "Sign the account out everywhere so a stolen session token stops working.", "immediate")
            add("require_mfa", "Force a password reset and re-enrol MFA",
                "Reset the password and require multi-factor authentication on the next sign-in.", "immediate")
        else:
            add("require_mfa", "Require additional authentication",
                "Ask for MFA / step-up verification on the next sign-in from this account.", "high")
        for ip in ips[:3]:
            add("block_ip", f"Block IP {ip}",
                f"Block {ip} at the firewall / identity provider; it is the source of the suspicious logins.",
                "immediate" if high else "high")
        if _has(labels, "password spray", "spraying"):
            add("block_ip", "Turn on lockout / rate-limiting for the login page",
                "Spraying tries one password on many accounts. Smart lockout and per-IP rate limits stop it.", "high")
        if _has(labels, "unrecognized device", "new device", "device"):
            add("block_device", "Remove the unknown device",
                "Remove or block the unrecognised device from the account's trusted devices.", "high")
        if _has(labels, "forwarding", "inbox rule"):
            add("remove_persistence", "Delete the mail-forwarding / inbox rule",
                "The attacker set up a rule to copy mail. Remove it and check what was forwarded.", "immediate")
        if _has(labels, "mfa", "recovery"):
            add("remove_persistence", "Restore MFA and recovery settings",
                "Remove any MFA method, phone or recovery email the owner did not add.", "immediate")
        if _has(labels, "privilege"):
            add("remove_persistence", "Remove the new admin rights",
                "Roll back the permission change and review what was done with it.", "immediate")
        if _has(labels, "bulk data", "download", "exfil"):
            add("contain_data", "Check what data was downloaded",
                "Review the download/export logs and treat the data as exposed.", "immediate")

    # ---------------- Deepfake ----------------
    if module_id == "deepfake":
        add("flag_media", "Flag for manual verification",
            "Have a person check the media and confirm with the real speaker/sender over a separate channel before acting on it.",
            "high")
        add("warn_user", "Do not act on this media alone",
            "Do not transfer money or share information because of this video/voice/image until it is verified.", "immediate", "user")

    # ---------------- Cyber threat (malware, network, API, exfil) ----------------
    if module_id == "cyber-threat":
        if subtopic_id == "malware-detection" or _has(labels, "hash", "powershell", "mimikatz", "malware", "command"):
            add("isolate_host", "Isolate the affected machine",
                "Disconnect it from the network (EDR isolation) before the malware spreads; do not switch it off.", "immediate")
        for ip in ips[:3]:
            add("block_ip", f"Block IP {ip}", f"Block traffic to/from {ip} at the firewall.", "immediate" if high else "high")
        if subtopic_id == "data-exfiltration" or _has(labels, "exfil", "upload", "transfer"):
            add("contain_data", "Stop the outbound transfer",
                "Block the destination and disable the account or API key doing the transfer.", "immediate")
        if subtopic_id == "api-abuse":
            add("block_ip", "Revoke or rate-limit the abused API key",
                "Rotate the key and add per-key rate limits.", "immediate" if high else "high")
        if subtopic_id == "insider-threat":
            add("escalate_incident", "Involve HR / management",
                "Insider cases need HR and legal involvement; preserve evidence before confronting anyone.", "high")

    # ---------------- Everyone, by severity ----------------
    if not any(a["action"] == "warn_user" for a in actions):
        add("warn_user", "Warn the user", "Tell the affected user what was found and what not to do.",
            "high" if high else "normal", "user")
    if high:
        add("notify_soc", "Notify the SOC / administrator",
            "Send this detection to the security team with the indicators above.", "immediate" if critical else "high")
    if critical:
        add("escalate_incident", "Escalate as a security incident",
            "Open an incident ticket, assign an owner and start the response timeline.", "immediate")
        add("preserve_evidence", "Preserve evidence",
            "Keep the original message/file/logs unchanged for investigation and any police complaint.", "high")

    actions.sort(key=lambda a: PRIORITY_ORDER[a["priority"]])
    return actions


def apply(result: dict, module_id: str, subtopic_id: str, target: str = "") -> dict:
    """Attach `responseActions` and put the specific actions at the top of `recommendations`."""
    actions = build_actions(result, module_id, subtopic_id, target)
    result["responseActions"] = actions
    if actions:
        specific = [f"{a['title']}: {a['detail']}" for a in actions]
        generic = [r for r in result.get("recommendations", [])
                   if r not in specific and not r.lower().startswith(("block the source", "quarantine the affected",
                                                                      "escalate to the incident"))]
        result["recommendations"] = specific + generic[:2]
    return result