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


# Each command pattern above can only match if one of these words is in the text (every alternative of the pattern
# contains one of them), so the pattern is skipped when none is present: same result, much faster on whole log files.
_NEEDS = {
    "Credential dumping tool (mimikatz / LSASS)": ("mimikatz", "sekurlsa", "lsass"),
    "Reverse shell": ("reverse shell", "nc", "/bin/", "/dev/tcp"),
    "Encoded PowerShell command": ("powershell",),
    "PowerShell download-and-run": ("invoke-expression", "iex", "downloadstring"),
    "Built-in Windows tool used to download files": ("certutil", "bitsadmin"),
    "Regsvr32 running a remote script": ("regsvr32",),
    "Script host running a script file": ("script",),
    "Command shell executing a command": ("cmd",),
    "Base64-encoded content": ("base64",),
    "Upload to a cloud storage service": ("mega.nz", "mega.io", "dropbox", "drive.google", "wetransfer", "anonfiles",
                                          "rclone"),
    "Copy to removable media": ("usb", "removable"),
}


def analyze_event_text(text: str, extra_fields: dict | None = None, subtopic_title: str = "Intelligent Cyber Threat Detection") -> dict:
    text = (text or "").strip()
    extra_fields = extra_fields or {}
    lower = text.lower()

    indicators = []

    def add(triggered, label, desc, severity, weight, mitre=None):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                           "triggered": bool(triggered), "mitre": mitre, "id": f"IND_{uuid.uuid4().hex[:12]}"})

    # Windows event logs (Security / Sysmon / PowerShell / Defender as JSON or XML; added 26 Oct): parsed first, so the
    # generic text patterns below do not count the same command lines a second time
    win_floor, winsum = _windows_text(text, add)
    hashes = MALWARE_HASH_RE.findall(text) if not winsum else []
    add(len(hashes) > 0, "File hash referenced",
        f"{len(hashes)} file hash(es) found in the event — cross-check against threat intelligence.",
        "high", 14)

    pattern_hits = 0
    for rx, label, desc, sev, weight, mitre in ([] if winsum else COMMAND_PATTERNS):
        if any(w in lower for w in _NEEDS.get(label, ("",))) and rx.search(text):
            pattern_hits += 1
            add(True, label, desc, sev, weight, mitre)
    cmd_hit = pattern_hits == 0 and not winsum and any(kw in lower for kw in SUSPICIOUS_KEYWORDS)
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

    obfuscation_markers = 0 if winsum else lower.count("%") + lower.count("\\x")
    add(obfuscation_markers > 5, "Obfuscated payload indicators",
        "Content shows signs of encoding/obfuscation commonly used to evade detection.", "high", 16, ["T1027"])

    # Web / API requests in the text (added 22 Oct): attack-type patterns + the trained API-abuse model.
    floor, web = _web_requests(text, add)
    # Whole-log incidents (added 23 Oct): every line is read, bursts and signatures become incidents.
    log_floor, logsum = _log_incidents(text, add, skip_web_attacks=bool(web and web["attackTypes"]))
    floor = max(floor, log_floor)
    # Network flow records / Zeek / firewall logs (added 24 Oct): connections judged by behaviour.
    net_floor, netsum = _network_text(text, add)
    floor = max(floor, net_floor)
    # User activity logs (logons, USB, file copies, e-mail, web; added 26 Oct): Insider Risk / UEBA engine. A Windows
    # log covering a week or more also feeds its interactive logons to it (unusual logon times, new computers).
    floor = max(floor, win_floor)
    ins_text = text
    if winsum and winsum.get("activityDays", 0) >= 7:
        ins_text = winsum["_activity"]
    ins_floor, inssum = _insider_text(ins_text, add)
    floor = max(floor, ins_floor)

    triggered = [i for i in indicators if i["triggered"]]
    score = max(sum(i["weight"] for i in indicators if i["triggered"]), floor)
    confidence = 50 + min(len(triggered) * 7, 35) if (text or extra_fields) else 0

    if not text and not extra_fields:
        explanation = "No event content or metadata was submitted to analyze."
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        names = ", ".join(i["label"][:1].lower() + i["label"][1:] for i in top)   # keeps IDs like U007 / IPs as written
        explanation = f"Rule engine flagged {len(triggered)} indicator(s), most notably: {names}."
    else:
        explanation = "No rule-based threat indicators were detected in the submitted event."

    result = build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Cyber Threat Engine — Rule-Based"
                    + (" + API-abuse request model (CSIC 2010 + CommonCrawl trained)" if web and web["modelAvailable"] else ""),
        threat_type=subtopic_title, explanation=explanation,
    )
    if logsum and not ((inssum or winsum) and not logsum["incidents"]):   # explained by the insider / Windows engine
        result["logAnalysis"] = {"linesRead": logsum["linesRead"], "timeRange": logsum["timeRange"],
                                 "truncated": logsum["truncated"], "format": logsum.get("format"),
                                 "formatRecognised": bool(logsum.get("format")),
                                 "incidents": [{k: i[k] for k in ("label", "severity", "lines", "sources")}
                                               for i in logsum["incidents"]],
                                 "details": logsum["details"][:20]}
        if logsum["incidents"]:
            result["explanation"] = (f"Read {logsum['linesRead']:,} log lines and found {len(logsum['incidents'])} kind(s) "
                                     f"of attack activity. " + result.get("explanation", ""))
        elif netsum or inssum or winsum:
            pass                 # flow records / activity / Windows logs: their own summary below explains them
        elif logsum.get("format"):
            result["explanation"] = (f"Read {logsum['linesRead']:,} log lines ({logsum['format']}) and found no attack "
                                     f"incidents. " + result.get("explanation", ""))
        else:
            # an unfamiliar log must never look like a clean bill of health (added 24 Oct)
            result["explanation"] = (f"Read {logsum['linesRead']:,} log lines, but the log format was not recognised. "
                                     "The log reader knows Linux system / SSH, web server (Apache / Nginx), Exim mail, "
                                     "Suricata and Windows Security event logs; on this file only the general checks "
                                     "ran, so a low score does not prove it is safe. " + result.get("explanation", ""))
    if netsum:
        _attach_network(result, netsum)
    if inssum:
        _attach_insider(result, inssum, keep_rest=bool(winsum))
        if inssum["trained"]:
            result["analysisEngine"] = ("CYBERGUARD Insider Risk Engine (UEBA) - own + peer baselines and a model "
                                        "trained on CERT r4.2")
    if winsum:
        _attach_windows(result, winsum)          # last, so the Windows findings are read first
        if not inssum:
            result["analysisEngine"] = ("CYBERGUARD Windows Event Engine - rules from MITRE ATT&CK, tested on OTRF "
                                        "attack recordings")
    if web:
        top = web["top"]
        result["webRequests"] = {"requests": web["requests"], "flaggedByModel": web["flaggedByModel"],
                                 "attackTypes": {k: v["count"] for k, v in web["attackTypes"].items()},
                                 "riskiestRequest": top["line"], "probability": top["probability"]}
    return result


def _windows_text(text: str, add) -> tuple[int, dict | None]:
    """Windows event export -> one indicator per incident (medium and above); floor critical 80 / high 71 / medium
    51. Low-severity notes are kept in the summary only."""
    if not text or ("EventID" not in text and "EventCode" not in text and "event_id" not in text):
        return 0, None
    try:
        from app.detectors import windows_events
        summary = windows_events.analyze_text(text)
    except Exception:          # never let the Windows reader break a scan
        return 0, None
    if not summary:
        return 0, None
    floor = 0
    for inc in summary["incidents"]:
        if inc["severity"] not in ("critical", "high", "medium"):
            continue
        where = f"{inc['user']} on {inc['host']}" if inc["host"] != "?" else inc["user"]
        when = f", {inc['first']}" if inc["first"] else ""
        ex = "; ".join(str(e)[:160] for e in inc["examples"][:2])
        add(True, f"Windows: {inc['label']} ({where})",
            f"{inc['lens']} - seen {inc['count']}x{when}. {('Example: ' + ex) if ex else ''}".strip(),
            inc["severity"], inc["weight"], [inc["mitre"]])
        floor = max(floor, {"critical": 80, "high": 71, "medium": 51}[inc["severity"]])
    return floor, summary


def _attach_windows(result: dict, summary: dict) -> None:
    result["windowsEvents"] = {k: v for k, v in summary.items() if not k.startswith("_")}
    real = [i for i in summary["incidents"] if i["severity"] in ("critical", "high", "medium")]
    head = (f"Read {summary['events']:,} Windows events ({summary['format']}) from {summary['hosts']} computer(s)"
            + (f" and found {len(real)} incident(s): " + ", ".join(sorted({i['lens'].lower() for i in real})) + ". "
               if real else " and found no attack or misuse pattern. "))
    if not real:
        head += ("The rules cover credential theft, security tools switched off, suspicious PowerShell and Windows "
                 "tools, new accounts and admin-group changes, persistence and remote commands; attacks they do not "
                 "know can still hide. ")
    result["explanation"] = head + result.get("explanation", "")


def _insider_text(text: str, add) -> tuple[int, dict | None]:
    """Activity log -> one indicator per person in the triage queue at 'review' or 'alert' level; the riskiest
    person's score is the floor (alert 71-100, review 51-70)."""
    if not text or "," not in text:
        return 0, None
    try:
        from app.detectors import insider_risk
        summary = insider_risk.analyze_text(text)
    except Exception:          # never let the activity reader break a scan
        return 0, None
    if not summary:
        return 0, None
    floor = 0
    for q in summary["queue"][:5]:
        pat = q.get("pattern") or {}
        sev = ("critical" if q["level"] == "alert" and pat.get("strength") == "high" else
               "high" if q["level"] == "alert" else "medium")
        parts = []
        if q["exfiltration"]:
            parts.append("Data exfiltration: " + "; ".join(q["exfiltration"][:4]) + ".")
        if q["abnormal"]:
            parts.append("Abnormal activity: " + "; ".join(q["abnormal"][:4]) + ".")
        if pat:
            parts.append(f"Insider pattern: {pat['name']} ({pat['why']}).")
        where = ("rule finding (model not trained)" if not summary["trained"] else
                 "beyond every ordinary working day seen in training" if q["risk"] >= 99.995 else
                 f"riskier than {q['risk']:.2f}% of ordinary working days")
        add(True, f"Insider risk: {q['user']} - {pat.get('name', 'unusual activity')}",
            f"{q['level'].capitalize()} level on {q['date']} ({where}; {q['flaggedDays']} day(s) flagged). "
            + " ".join(parts), sev, 0, q["mitre"] or None)
        floor = max(floor, q["score"])
    return floor, summary


def _attach_insider(result: dict, summary: dict, keep_rest: bool = False) -> None:
    result["insiderRisk"] = summary
    head = (f"Read {summary['events']:,} activity events ({summary['format']}) for {summary['people']} people "
            f"({summary['userDays']:,} person-days). ")
    if summary["alerts"] or summary["reviews"]:
        head += (f"{summary['alerts']} person(s) at alert level and {summary['reviews']} at review level - "
                 f"exfiltration signs for {summary['lenses']['exfiltration']}, abnormal activity for "
                 f"{summary['lenses']['abnormal']}, a known insider pattern for {summary['lenses']['insider']}. ")
        if summary["trained"] and summary.get("falseAlertsPerDay") is not None:
            head += (f"For scale: in testing about {summary['falseAlertsPerDay']} ordinary person-days per day (of "
                     "~600) also reached alert level, so treat the list as a review queue, not proof. ")
    else:
        head += "Nobody reached the review level. "
    if summary["notes"]:
        head += " ".join(summary["notes"]) + " "
    keep = summary["alerts"] or summary["reviews"] or keep_rest
    result["explanation"] = head + (result.get("explanation", "") if keep else "")


def _apply_network(summary: dict, add) -> int:
    """Network incidents -> indicators; returns the score floor (critical 80, high 71, medium 51). The per-connection
    model is SUPPORTING only: it adds a low-weight note and never sets a floor."""
    floor = 0
    for inc in summary["incidents"]:
        add(True, f"Network incident: {inc['label']}", inc["description"], inc["severity"], inc["weight"],
            [inc["mitre"]])
        floor = max(floor, {"critical": 80, "high": 71, "medium": 51}.get(inc["severity"], 0))
    m = summary.get("model")
    if m and m["flagged"]:
        add(True, "Connection model: attack-like connections (supporting)",
            f"The per-connection model (trained on CIC-IDS2017) marks {m['flagged']:,} of {m['connections']:,} "
            f"connections as attack-like. It misses most attack types it was not trained on and marks about 0.1-1% "
            f"of normal connections, so on its own this is not evidence of an attack.", "low", 5)
    return floor


def _attach_network(result: dict, summary: dict) -> None:
    result["networkAnalysis"] = {k: summary[k] for k in ("format", "connections", "httpRequests", "timeRange",
                                                          "sources", "targets", "topTalkers", "model")}
    result["networkAnalysis"]["incidents"] = [{k: i[k] for k in ("label", "severity", "connections", "sources",
                                                                 "targets", "mitre")} for i in summary["incidents"]]
    n = len(summary["incidents"])
    head = (f"Read {summary['connections']:,} network connections ({summary['format']})"
            + (f" and found {n} kind(s) of attack activity. " if n else " and found no attack behaviour. "))
    if not n:
        head += ("The checks cover port scans, internal host sweeps, floods, failed-connection floods, login "
                 "brute force, backdoor ports and web attacks in unencrypted HTTP; slow or encrypted attacks "
                 "can still hide in normal-looking traffic. ")
    result["explanation"] = head + result.get("explanation", "")


def _network_text(text: str, add) -> tuple[int, dict | None]:
    if not text or not ("," in text or "\t" in text or "SRC=" in text or "id.orig_h" in text):
        return 0, None
    try:
        from app.detectors import network_traffic
        summary = network_traffic.analyze_text(text)
    except Exception:          # never let the flow reader break a scan
        return 0, None
    if not summary:
        return 0, None
    return _apply_network(summary, add), summary


def analyze_network_capture(path: str, file_name: str = "capture", subtopic_title: str = "Network Traffic") -> dict:
    """A packet capture (.pcap / .pcapng): read, never replayed."""
    from app.detectors import network_traffic
    indicators = []

    def add(triggered, label, desc, severity, weight, mitre=None):
        indicators.append({"label": label, "description": desc, "severity": severity, "weight": weight,
                           "triggered": bool(triggered), "mitre": mitre, "id": f"IND_{uuid.uuid4().hex[:12]}"})

    try:
        summary = network_traffic.analyze_capture(path)
    except Exception as exc:   # noqa: BLE001 - a broken capture is reported, never crashes the scan
        result = build_result(indicators=[], base_score=0, confidence=0,
                              engine_name="CYBERGUARD Network Traffic Engine", threat_type=subtopic_title,
                              explanation=f"{file_name} could not be read as a packet capture ({type(exc).__name__}). "
                                          "Save it from Wireshark as .pcap or .pcapng and try again.")
        return result
    floor = _apply_network(summary, add)
    triggered = [i for i in indicators if i["triggered"]]
    score = max(sum(i["weight"] for i in triggered), floor)
    confidence = 50 + min(len(triggered) * 7, 35) if summary["connections"] else 0
    result = build_result(
        indicators=indicators, base_score=score, confidence=confidence,
        engine_name="CYBERGUARD Network Traffic Engine - behaviour levels learned from CIC-IDS2017 (corrected)"
                    + (" + supporting connection model" if summary.get("model") else ""),
        threat_type=subtopic_title, explanation="")
    st = summary.get("readStats") or {}
    note = (" The capture was cut off; everything before the cut was read." if st.get("truncated") else "") + \
           (" Only the first part of a very large capture was read." if st.get("stopped_early") else "")
    _attach_network(result, summary)
    result["explanation"] = result["explanation"].strip() + note
    return result


def _log_incidents(text: str, add, skip_web_attacks: bool = False) -> tuple[int, dict | None]:
    """Whole-log analysis (app/detectors/log_incidents.py). Critical incidents -> at least 80, high -> 71,
    medium -> 51. Burst sizes are chosen from the AIT attack data (app/ml/models/log_analysis.json)."""
    try:
        from app.detectors import log_incidents
        summary = log_incidents.analyze(text)
    except Exception:          # never let the log reader break a scan
        return 0, None
    if not summary:
        return 0, None
    floor = 0
    for inc in summary["incidents"]:
        if skip_web_attacks and inc["category"] == "web_attack":
            continue           # already listed request by request above
        add(True, f"Log incident: {inc['label']}", inc["description"], inc["severity"], inc["weight"], [inc["mitre"]])
        floor = max(floor, {"critical": 80, "high": 71, "medium": 51}.get(inc["severity"], 0))
    return floor, summary


def _model_points(p: float, level: str, ta: float, tv: float) -> int:
    """Model verdict on the 0-100 scale: alert level -> 71-100, verify level -> 51-70."""
    if level == "high":
        return min(100, 71 + round(29 * (p - ta) / max(1 - ta, 1e-6)))
    return min(70, 51 + round(19 * (p - tv) / max(ta - tv, 1e-6)))


def _web_requests(text: str, add) -> tuple[int, dict | None]:
    """Judge every HTTP request in the text. Returns (score floor, assessment or None).

    A request matching an attack pattern (SQL injection, XSS, path traversal ...) is an alert: on real traffic these
    patterns fired on 0.01% of 283,176 CommonCrawl links and 0 of 72,000 CSIC normal requests. The model alone needs
    more evidence in a long log, because one unusual request among many normal ones is common (tested: with "any
    request" 10% of normal 20-request logs would have been raised): short pastes (1-3 requests) use its level directly,
    longer logs need two or more requests at the level."""
    try:
        from app.detectors import api_abuse
        web = api_abuse.assess(text)
    except Exception:          # a broken / missing model never breaks the scan
        return 0, None
    if not web:
        return 0, None
    floor = 0
    for name, info in web["attackTypes"].items():
        add(True, f"Web attack in a request: {name}",
            f"{info['description']} Seen in {info['count']} request(s), e.g. {info['example'][:160]}", "critical", 30,
            [info["mitre"]])
        floor = max(floor, 71 if name != "Header / response splitting" else 51)
    if web["modelAvailable"]:
        n, flagged, alerts = web["requests"], web["flaggedByModel"], web["alertByModel"]
        top, ta, tv = web["top"], web["thrAlert"], web["thrVerify"]
        short = n <= 3
        level = ("high" if (alerts >= 1 and (short or flagged >= 2)) else
                 "medium" if (flagged >= 1 and (short or flagged >= 2)) else "low")
        if level != "low" and top["level"] in ("high", "medium"):
            floor = max(floor, _model_points(top["probability"], top["level"] if level == "high" else "medium", ta, tv))
        add(level != "low",
            {"high": "API-abuse model: requests look like web attacks",
             "medium": "API-abuse model: unusual requests - check carefully"}.get(level, "API-abuse model: requests look normal"),
            f"The trained request model (CSIC 2010 attacks + real requests from thousands of websites) checked {n} "
            f"request(s): {flagged} reached its 'check' level and {alerts} its alert level (alert level flags about "
            f"0.1% of real requests). Riskiest: {top['line'][:160]}"
            + ("" if short or flagged >= 2 else " A single unusual request in a longer log is shown but not raised "
               "on its own."), {"high": "high", "medium": "medium"}.get(level, "low"), 0, ["T1190"])
    return floor, web
