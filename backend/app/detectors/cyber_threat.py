"""
Real, deterministic rule engine for general cyber-threat/event analysis
(module 6: "Intelligent Cyber Threat Detection"). Operates on the actual
submitted event text/fields — no randomness.
"""
import re
import uuid
from app.detectors.base import build_result

MALWARE_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
SUSPICIOUS_KEYWORDS = ["powershell -enc", "base64", "reverse shell", "mimikatz", "cmd.exe /c",
                        "wscript", "regsvr32", "certutil -urlcache", "invoke-expression"]

# Attack-tool command patterns, each with the MITRE ATT&CK technique it is evidence of
# (explained to the user by app/services/mitre.py).  (regex, label, description, severity, weight, mitre)
COMMAND_PATTERNS = [
    (re.compile(r"mimikatz|sekurlsa|lsass\.dmp|procdump[^\n]*lsass", re.I), "Credential dumping tool (mimikatz / LSASS)",
     "A tool that reads passwords out of Windows memory was referenced.", "critical", 60, ["T1003.001"]),
    (re.compile(r"reverse shell|\bnc(?:\.exe)?\s+(?:-\w+\s+)*-e\s|/bin/(?:ba)?sh\s+-i|/dev/tcp/", re.I), "Reverse shell",
     "A command that hands remote control of the machine to someone else.", "critical", 55, ["T1059"]),
    (re.compile(r"powershell(?:\.exe)?\b[^\n]*\s-(?:e|en|enc|encodedcommand)\b", re.I), "Encoded PowerShell command",
     "PowerShell was run with a hidden (encoded) command, a common way to sneak attacker code past filters.",
     "critical", 55, ["T1059.001", "T1027"]),
    (re.compile(r"invoke-expression|\biex\s*\(|downloadstring\(", re.I), "PowerShell download-and-run",
     "PowerShell fetched and ran code in one step (Invoke-Expression / DownloadString).", "high", 40, ["T1059.001"]),
    (re.compile(r"certutil(?:\.exe)?\b[^\n]*-(?:urlcache|decode)|bitsadmin[^\n]*/transfer", re.I),
     "Built-in Windows tool used to download files",
     "certutil or bitsadmin was used to pull a file from the internet, a classic attacker trick.", "high", 35, ["T1105"]),
    (re.compile(r"regsvr32[^\n]*(?:scrobj|/i:|https?://)", re.I), "Regsvr32 running a remote script",
     "regsvr32 was told to load a script, a known way to bypass application controls.", "high", 40, ["T1218.010"]),
    (re.compile(r"\b[wc]script(?:\.exe)?\b[^\n]*\.(?:vbs|vbe|js|jse)\b", re.I), "Script host running a script file",
     "wscript/cscript ran a script file, a common first step of malicious attachments.", "medium", 15, ["T1059.005"]),
    (re.compile(r"\bcmd(?:\.exe)?\s+/c\b", re.I), "Command shell executing a command",
     "cmd.exe /c ran a command. Normal on its own, suspicious together with the other signs.", "low", 8, ["T1059.003"]),
    (re.compile(r"frombase64string|\bbase64\b", re.I), "Base64-encoded content",
     "Encoded content that hides what a command really does.", "medium", 10, ["T1027"]),
    (re.compile(r"(?:upload|uploaded|copy|copied|sync)[^\n]{0,80}(?:mega\.nz|mega\.io|dropbox|drive\.google|wetransfer|anonfiles)|\brclone\b", re.I),
     "Upload to a cloud storage service", "Data was sent to a personal cloud or file-sharing service.", "high", 40, ["T1567"]),
    (re.compile(r"(?:copy|copied|write|wrote)[^\n]{0,80}(?:usb|removable)", re.I), "Copy to removable media",
     "Files were copied to a USB or removable drive.", "medium", 30, ["T1052.001"]),
]


def analyze_event_text(text: str, extra_fields: dict | None = None, subtopic_title: str = "Intelligent Cyber Threat Detection") -> dict:
    text = (text or "").strip()
    extra_fields = extra_fields or {}
    lower = text.lower()

    indicators = []

    def add(triggered, label, desc, severity, weight, mitre=None):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                           "triggered": bool(triggered), "mitre": mitre, "id": f"IND_{uuid.uuid4().hex[:12]}"})

    hashes = MALWARE_HASH_RE.findall(text)
    add(len(hashes) > 0, "File hash referenced",
        f"{len(hashes)} file hash(es) found in the event — cross-check against threat intelligence.",
        "high", 14)

    pattern_hits = 0
    for rx, label, desc, sev, weight, mitre in COMMAND_PATTERNS:
        if rx.search(text):
            pattern_hits += 1
            add(True, label, desc, sev, weight, mitre)
    cmd_hit = pattern_hits == 0 and any(kw in lower for kw in SUSPICIOUS_KEYWORDS)
    add(cmd_hit, "Suspicious command/process pattern",
        "Event text contains command patterns commonly associated with post-exploitation tooling.",
        "critical", 26)

    def gi(key, default=0):
        try:
            return int(extra_fields.get(key, default) or default)
        except (ValueError, TypeError):
            return default

    request_rate = gi("requestsPerMinute", 0)
    add(request_rate > 500, "Excessive API request rate",
        f"{request_rate} requests/minute far exceeds a typical baseline.", "medium", 12, ["T1499"])

    data_transfer_mb = gi("dataTransferMb", 0)
    add(data_transfer_mb > 500, "Large unscheduled data transfer",
        f"{data_transfer_mb}MB transferred — review whether this matches expected business activity.",
        "high", 18, ["T1048"])

    off_hours = str(extra_fields.get("offHours", "")).strip().lower() in ("1", "true", "yes")
    add(off_hours, "Activity outside business hours",
        "Event occurred outside the organization's normal operating hours.", "low", 8)

    obfuscation_markers = lower.count("%") + lower.count("\\x")
    add(obfuscation_markers > 5, "Obfuscated payload indicators",
        "Content shows signs of encoding/obfuscation commonly used to evade detection.", "high", 16, ["T1027"])

    triggered = [i for i in indicators if i["triggered"]]
    score = sum(i["weight"] for i in indicators if i["triggered"])
    confidence = 50 + min(len(triggered) * 7, 35) if (text or extra_fields) else 0

    if not text and not extra_fields:
        explanation = "No event content or metadata was submitted to analyze."
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"].lower() for i in top)
        explanation = f"Rule engine flagged {len(triggered)} indicator(s), most notably: {names}."
    else:
        explanation = "No rule-based threat indicators were detected in the submitted event."

    return build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Cyber Threat Engine — Rule-Based",
        threat_type=subtopic_title, explanation=explanation,
    )
