"""Windows event logs (Security, Sysmon, System, PowerShell, Defender) -> SOC incidents, attributed to user and host.

Covers what the CERT insider data could not: process starts and their command lines, account / group / permission
changes, attempts to switch off security controls, persistence, credential theft, discovery bursts, data staging.
Rules are written from MITRE ATT&CK technique descriptions (not tuned on any test data) and tested on OTRF
Security-Datasets - real Windows telemetry recorded while known attack techniques ran
(app/ml/training/test_windows_rules.py).

Reads: JSON lines / JSON arrays (Winlogbeat, NXLog, Sentinel, Splunk JSON exports - nested fields are flattened),
Event Viewer "Save as XML", and .evtx files (converted to XML by app/services/analysis_service.py). Nothing is run.
"""
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

from app.detectors.insider_signals import parse_time

MAX_EVENTS = 300_000
WINDOW_S = 600
EVTX_WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evtx_worker.py")

# --------------------------------------------------------------------------------------------------- field names
_ALIASES = {
    "id": ("eventid", "eventcode", "event_id", "winlog.event_id", "event.code", "system.eventid", "eventid.#text"),
    # UTC fields first, so events of one file are never mixed with local-time ones (a time-zone gap of hours would
    # break the 10-minute windows); EventTime (local) only as a last resort
    "time": ("@timestamp", "system.timecreated.systemtime", "timecreated.systemtime", "utctime", "timegenerated",
             "timecreated", "event.created", "timestamp", "eventtime"),
    "host": ("hostname", "computer", "computername", "host.name", "winlog.computer_name", "system.computer"),
    "channel": ("channel", "winlog.channel", "logname", "system.channel"),
    "subject_user": ("subjectusername", "winlog.event_data.subjectusername", "user", "user.name", "accountname",
                     "account"),
    "subject_domain": ("subjectdomainname", "winlog.event_data.subjectdomainname"),
    "target_user": ("targetusername", "winlog.event_data.targetusername", "samaccountname"),
    "member": ("membername", "winlog.event_data.membername"),
    "member_sid": ("membersid", "winlog.event_data.membersid"),
    "target_sid": ("targetsid", "winlog.event_data.targetsid"),
    "details": ("details", "winlog.event_data.details"),
    "image": ("newprocessname", "image", "processname", "process.executable", "winlog.event_data.newprocessname",
              "winlog.event_data.image"),
    "parent": ("parentprocessname", "parentimage", "process.parent.executable", "winlog.event_data.parentimage",
               "winlog.event_data.parentprocessname"),
    "cmd": ("commandline", "processcommandline", "process.command_line", "winlog.event_data.commandline"),
    "script": ("scriptblocktext", "winlog.event_data.scriptblocktext", "payload"),
    "logon_type": ("logontype", "winlog.event_data.logontype"),
    "ip": ("ipaddress", "sourceaddress", "source.ip", "winlog.event_data.ipaddress"),
    "service": ("servicename", "winlog.event_data.servicename"),
    "service_path": ("imagepath", "servicefilename", "winlog.event_data.imagepath", "winlog.event_data.servicefilename"),
    "task": ("taskname", "winlog.event_data.taskname"),
    "task_content": ("taskcontent", "winlog.event_data.taskcontent"),
    "target_object": ("targetobject", "objectname", "winlog.event_data.targetobject"),
    "target_image": ("targetimage", "winlog.event_data.targetimage"),
    "source_image": ("sourceimage", "winlog.event_data.sourceimage"),
    "granted_access": ("grantedaccess", "winlog.event_data.grantedaccess"),
    "share_target": ("relativetargetname", "winlog.event_data.relativetargetname"),
    "wmi_name": ("name", "winlog.event_data.name"),
    "wmi_dest": ("destination", "consumer", "winlog.event_data.destination", "winlog.event_data.consumer", "message"),
}
_PRIV_GROUPS = re.compile(r"^(administrators|domain admins|enterprise admins|schema admins|account operators|"
                          r"backup operators|server operators|print operators|dnsadmins|group policy creator owners|"
                          r"remote desktop users|remote management users|hyper-v administrators)$", re.I)
# well-known SIDs of privileged groups (work whatever language Windows is in): Domain / Schema / Enterprise Admins,
# Group Policy Creator Owners, and the built-in Administrators, Account / Server / Print / Backup Operators,
# Remote Desktop Users, Remote Management Users
_PRIV_SIDS = re.compile(r"-(512|518|519|520)$|^S-1-5-32-(544|548|549|550|551|555|580)$", re.I)
_SYSTEM_USERS = re.compile(r"^(system|local service|network service|-|anonymous logon|dwm-\d+|umfd-\d+|"
                           r"[^\\]*\$)$", re.I)


def _flatten(obj, prefix="", out=None):
    """{"winlog": {"event_id": 1}} -> {"winlog.event_id": 1} (keys lower-cased)."""
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}{str(k).lower()}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out)
        else:
            out[key] = v
    return out


def _pick(flat, key):
    for name in _ALIASES[key]:
        v = flat.get(name)
        if v not in (None, "", []):
            if isinstance(v, (list, dict)):
                v = json.dumps(v)
            return str(v)
    for name in _ALIASES[key]:               # a nested source: match on the last part of the key
        last = name.rsplit(".", 1)[-1]
        for k, v in flat.items():
            if k.endswith("." + last) and v not in (None, "", []):
                return str(v)
    return ""


def _user(v):
    v = (v or "").strip()
    return v.split("\\")[-1] if v else ""


def _time_field(flats) -> str | None:
    """ONE time field for the whole file: the most preferred one that (nearly) every event has. Mixing fields mixes
    clocks - one export had UTC on its Sysmon events only and local time on all of them, 16 hours apart."""
    n = len(flats)
    if not n:
        return None
    for name in _ALIASES["time"]:
        if sum(1 for f in flats if f.get(name) not in (None, "")) >= 0.95 * n:
            return name
    return None


def _normalise(flat, time_key: str | None = None) -> dict | None:
    try:
        eid = int(str(_pick(flat, "id")).strip() or -1)
    except ValueError:
        return None
    if eid < 0:
        return None
    ev = {k: _pick(flat, k) for k in _ALIASES if k != "id"}
    ev["id"] = eid
    ev["channel"] = ev["channel"].lower()
    ev["subject_user"] = _user(ev["subject_user"])
    ev["target_user"] = _user(ev["target_user"])
    t = str(flat.get(time_key) or "") if time_key else ev["time"]
    ev.pop("time")
    ev["t"] = parse_time(t.replace("T", " ").split(".")[0]) if t else None
    ev["host"] = ev["host"].split(".")[0].upper() if ev["host"] else ""
    if ev["member"] in ("", "-"):
        ev["member"] = ev["member_sid"]
    return ev


# -------------------------------------------------------------------------------------------------------- readers
def _from_json(text):
    s = text.strip()
    if s.startswith("["):
        try:
            data = json.loads(s)
            return [x for x in data if isinstance(x, dict)][:MAX_EVENTS]
        except ValueError:
            return []
    out = []
    for ln in s.splitlines():
        ln = ln.strip().rstrip(",")
        if ln.startswith("{"):
            try:
                out.append(json.loads(ln))
            except ValueError:
                continue
            if len(out) >= MAX_EVENTS:
                break
    return out


def _from_xml(text):
    if re.search(r"<!DOCTYPE|<!ENTITY", text[:5000], re.I):
        return []                            # never expand entities from an uploaded file
    body = re.sub(r"\sxmlns(:\w+)?=\"[^\"]*\"", "", text)
    if "<Events" not in body[:2000]:
        body = "<Events>" + re.sub(r"<\?xml[^>]*\?>", "", body) + "</Events>"
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    out = []
    for e in root.iter("Event"):
        flat = {}
        sysn = e.find("System")
        if sysn is not None:
            for c in sysn:
                tag = c.tag.lower()
                flat[f"system.{tag}"] = (c.text or "").strip() or c.attrib.get("SystemTime", "")
                if tag == "timecreated":
                    flat["system.timecreated.systemtime"] = c.attrib.get("SystemTime", "")
        for d in e.iter("Data"):
            if d.attrib.get("Name"):
                flat[d.attrib["Name"].lower()] = (d.text or "").strip()
        out.append(flat)
        if len(out) >= MAX_EVENTS:
            break
    return out


def looks_like(text: str) -> str:
    """'json' / 'xml' when the text is a Windows event export, else ''."""
    head = (text or "")[:20000]
    if "<Event" in head and "<EventID" in head:
        return "xml"
    if head.lstrip()[:1] in "[{" and re.search(r'"(EventID|EventCode|event_id|winlog)"', head):
        return "json"
    return ""


def parse(text: str) -> tuple[list[dict], str]:
    kind = looks_like(text)
    raw = _from_xml(text) if kind == "xml" else _from_json(text) if kind == "json" else []
    flats = [r if kind == "xml" else _flatten(r) for r in raw]
    key = _time_field(flats)
    evs = [ev for ev in (_normalise(f, key) for f in flats) if ev]
    return evs, kind


# ------------------------------------------------------------------------------------------------------- the rules
def _rx(p):
    return re.compile(p, re.I)


# Command / script rules: (key, title, regex on command line or PowerShell script text, severity, weight, mitre, lens)
COMMAND_RULES = [
    ("encoded_ps", "Hidden / encoded PowerShell", _rx(r"powershell[^\n]*\s-(e|en|enc|enco|encodedcommand)\s|"
     r"frombase64string\(|-w(indowstyle)?\s+hidden[^\n]*-nop|\biex\s*\(|invoke-expression[^\n]*(downloadstring|"
     r"net\.webclient)|downloadstring\(|net\.webclient\)\.download"), "high", 30, "T1059.001", "attack"),
    ("lolbin", "Windows tool abused to fetch or run code", _rx(
        r"certutil[^\n]*-(urlcache|decode)|bitsadmin[^\n]*/(transfer|addfile)|mshta(\.exe)?\s+[\"']?(https?:|"
        r"javascript:|vbscript:)|regsvr32[^\n]*(/i:https?|scrobj)|rundll32[^\n]*javascript:|wmic[^\n]*/format:"
        r"[\"']?https?|wmic[^\n]*\.xsl|installutil[^\n]*/u\b|cmstp[^\n]*/s\b|hh(\.exe)?\s+https?:|"
        r"msbuild(\.exe)?\s+[^\n]*\.(xml|csproj|proj)\b|register-cimprovider|mavinject"), "high", 30, "T1218",
     "attack"),
    ("cred_dump", "Password / credential theft tool", _rx(
        r"mimikatz|sekurlsa|lsadump::|kerberos::|invoke-mimikatz|procdump[^\n]*lsass|comsvcs(\.dll)?[^\n]*minidump|"
        r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|ntdsutil[^\n]*(ifm|ac i ntds)|esentutl[^\n]*/y[^\n]*"
        r"(sam|ntds)|\\ntds\.dit|invoke-ninjacopy|invoke-powerdump|rubeus|dumpert|get-vaultcredential|"
        r"invoke-dcsync|lsass\.dmp"), "critical", 50, "T1003", "attack"),
    ("security_off", "Security control switched off", _rx(
        r"wevtutil(\.exe)?\s+(cl|clear-log|sl|set-log)\b|clear-eventlog|set-mppreference[^\n]*-disable|"
        r"netsh[^\n]*(advfirewall|firewall)[^\n]*(state\s+off|opmode\s+disable)|auditpol[^\n]*(/clear|/remove|"
        r"/success:disable|/failure:disable)|sc(\.exe)?\s+(config|stop)\s+eventlog|stop-service[^\n]*eventlog|"
        r"\\control\\minint|processcreationincludecmdline_enabled[^\n]*\b0\b|"
        r"\\services\\eventlog[^\n]*\bstart\b[^\n]*\b4\b"), "critical", 45, "T1562", "bypass"),
    ("firewall_open", "Firewall opened", _rx(r"netsh[^\n]*(advfirewall\s+firewall\s+add\s+rule|firewall\s+add\s+"
                                             r"portopening)|new-netfirewallrule"), "medium", 15, "T1562.004",
     "bypass"),
    ("recovery_off", "Backups / recovery deleted (ransomware step)", _rx(
        r"vssadmin[^\n]*delete\s+shadows|wmic[^\n]*shadowcopy[^\n]*delete|bcdedit[^\n]*recoveryenabled\s+no|"
        r"wbadmin[^\n]*delete\s+(catalog|systemstatebackup)"), "critical", 50, "T1490", "attack"),
    ("add_user", "Account created or given admin rights by command", _rx(
        r"net1?(\.exe)?\s+user\s+\S+\s+\S*\s*/add|net1?(\.exe)?\s+(local)?group\s+[\"']?(administrators|domain admins|"
        r"remote desktop users)[\"']?\s+\S+\s+/add|add-localgroupmember|new-localuser"), "high", 35, "T1136",
     "permission"),
    ("remote_exec", "Command run on another computer", _rx(
        r"psexe(c|svc)|wmic[^\n]*/node:[^\n]*process\s+call\s+create|winrs(\.exe)?\s+-r:|invoke-command[^\n]*"
        r"-computername|schtasks[^\n]*/create[^\n]*/s\s|enter-pssession|new-pssession|invoke-wmimethod[^\n]*"
        r"-computername|invoke-smbexec|invoke-psexec"), "high", 30, "T1021", "attack"),
    ("staging", "Data packed or uploaded (possible exfiltration)", _rx(
        r"\b(7z|7za|rar|winrar)(\.exe)?\s+a\b|compress-archive|makecab|rclone(\.exe)?\s+(copy|sync)|"
        r"curl(\.exe)?[^\n]*\s(-t|--upload-file|-f|--form)\s|invoke-webrequest[^\n]*-method\s+(post|put)[^\n]*"
        r"-infile"), "medium", 20, "T1560.001", "exfiltration"),
]
DISCOVERY = _rx(r"\b(whoami|systeminfo|ipconfig\s+/all|nltest|quser|query\s+user|tasklist|netstat\s+-an|arp\s+-a|"
                r"route\s+print|dsquery|net1?(\.exe)?\s+(user|group|localgroup|view|share|accounts|session)|"
                r"get-ad(user|group|computer)|get-netlocalgroup|get-domaingroup|get-netuser|nslookup)\b")
OFFICE_PARENT = _rx(r"\\(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|acrord32|acrobat)\.exe$")
SHELL_CHILD = _rx(r"\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$")
SUSPICIOUS_PATH = _rx(r"\\(temp|tmp|appdata|public|downloads)\\|\\programdata\\(?!microsoft\\)|%temp%|%appdata%|"
                      r"powershell|cmd(\.exe)?\s+/c|mshta|rundll32|regsvr32|wscript|cscript|-enc")
# what an autostart (Run key) value must contain to be worth more than a note: per-user apps in AppData (Teams,
# Zoom ...) start this way all the time, scripts and temp / public folders do not
RUN_SUSPICIOUS = _rx(r"powershell|cmd(\.exe)?\s+/c|mshta|rundll32|regsvr32|wscript|cscript|-enc|\\(temp|tmp|public)\\|"
                     r"\\programdata\\(?!microsoft\\)|\.(vbs|js|bat|ps1|hta)\b")
LSASS_OK = _rx(r"\\(lsass|csrss|wininit|services|svchost|msmpeng|wmiprvse|vmtoolsd|lsm|smss|mrt|"
               r"vmacthlp|msiexec)\.exe$|^c:\\windowsazure\\guestagent")      # + Microsoft's Azure VM agent

# ---- added 26 Oct, written from MITRE ATT&CK (T1562, T1112, T1543, T1546.003, T1055, T1021, T1047, T1087) -------
# Registry changes that switch off or weaken a protection: (regex on the key, regex the new value must match or None,
# key, title, severity, weight, mitre). Programs that legitimately manage these keys are ignored (REG_OK).
REG_RULES = [
    (_rx(r"\\control\\minint$"), None, "log_off_reg", "Event logging switched off (MiniNt registry key)", "critical", 45,
     "T1562.002"),
    (_rx(r"\\services\\eventlog\\start$"), _rx(r"0x0+4\b"), "log_off_reg", "Event log service disabled (registry)",
     "critical", 45, "T1562.002"),
    (_rx(r"\\services\\eventlog\\[^\\]+\\file$"), None, "log_moved", "Event log file moved somewhere else",
     "high", 30, "T1562.002"),
    (_rx(r"processcreationincludecmdline_enabled$"), _rx(r"0x0+\b"), "cmdline_log_off",
     "Command-line logging switched off", "high", 30, "T1562.003"),
    (_rx(r"\\wdigest\\uselogoncredential$"), _rx(r"0x0+1\b"), "wdigest_on",
     "Windows set to keep passwords in memory (WDigest)", "critical", 45, "T1112"),
    (_rx(r"\\control\\lsa\\lmcompatibilitylevel$"), _rx(r"0x0+[0-2]\b"), "ntlm_weak",
     "Login security weakened (old NTLM allowed)", "high", 30, "T1562.010"),
    (_rx(r"\\msv1_0\\(ntlmminclientsec|restrictsendingntlmtraffic)$"), None, "ntlm_weak",
     "Login security weakened (NTLM settings changed)", "high", 30, "T1562.010"),
    (_rx(r"\\terminal server\\fdenytsconnections$"), _rx(r"0x0+\b"), "rdp_on", "Remote Desktop switched on",
     "medium", 20, "T1021.001"),
    (_rx(r"\\windows defender\\.*\\?disable[a-z]*$"), _rx(r"0x0+1\b"), "defender_off_reg",
     "Microsoft Defender protection turned off (registry)", "critical", 45, "T1562.001"),
]
REG_OK = _rx(r"\\(svchost|services|msmpeng|tiworker|trustedinstaller|msiexec|lsass|gpupdate|mpcmdrun|wininit)\.exe$")
SERVICE_KEY = _rx(r"\\services\\[^\\]+\\(imagepath|parameters\\servicedll)$")
INJECT_OK = _rx(r"\\(csrss|dwm|wininit|services|svchost|lsass|smss|winlogon|werfault|msmpeng|vmtoolsd)\.exe$")
WMI_BUILTIN = _rx(r"SCM Event Log (Filter|Consumer)|BVTFilter|BVTConsumer")   # Windows' own subscriptions
REMOTE_PARENT = _rx(r"\\(wmiprvse|wsmprovhost)\.exe$")
REMOTE_CHILD = _rx(r"\\(cmd|powershell|pwsh|net1?|whoami|mshta|rundll32|regsvr32|cscript|wscript|msbuild|"
                   r"certutil|bitsadmin|nltest|reg|sc|schtasks)\.exe$")
ADMIN_PIPES = {"svcctl": ("remote_admin_pipe", "Services / tasks / registry controlled from another computer", "high", 30,
                          "T1021.002", "attack"),
               "atsvc": ("remote_admin_pipe", "Services / tasks / registry controlled from another computer", "high", 30,
                         "T1021.002", "attack"),
               "winreg": ("remote_admin_pipe", "Services / tasks / registry controlled from another computer", "high", 30,
                          "T1021.002", "attack"),
               "samr": ("remote_discovery_pipe", "User accounts / sessions listed over the network", "medium", 20,
                        "T1087.002", "abnormal"),
               "srvsvc": ("remote_discovery_pipe", "User accounts / sessions listed over the network", "medium", 20,
                          "T1049", "abnormal")}

LENSES = {"attack": "Attacker activity", "bypass": "Security controls bypassed", "permission":
          "Account / permission change", "persistence": "Persistence", "exfiltration": "Data staging / exfiltration",
          "abnormal": "Abnormal activity", "credential": "Credential theft"}


def _who(ev):
    u = ev["subject_user"] or ev["target_user"]
    return u if u and not _SYSTEM_USERS.match(u) else (u or "?")


def _event_rules(ev):
    """Single-event rules -> list of (key, title, severity, weight, mitre, lens, detail)."""
    out, eid, ch = [], ev["id"], ev["channel"]
    sysmon = "sysmon" in ch
    text = " ".join(x for x in (ev["cmd"], ev["script"] if (eid in (4104, 4103) or "powershell" in ch) else "") if x)
    if text and (eid in (4688, 4104, 4103, 800) or (sysmon and eid == 1) or not ch):
        for key, title, rx, sev, w, mitre, lens in COMMAND_RULES:
            if rx.search(text):
                out.append((key, title, sev, w, mitre, "credential" if key == "cred_dump" else lens, text[:300]))
    if (eid == 4688 or (sysmon and eid == 1)) and OFFICE_PARENT.search(ev["parent"]) and SHELL_CHILD.search(ev["image"]):
        out.append(("office_child", "Office / PDF app started a shell or script", "critical", 45, "T1204.002", "attack",
                    f"{ev['parent'].rsplit(chr(92), 1)[-1]} -> {ev['image'].rsplit(chr(92), 1)[-1]}"))
    if sysmon and eid == 10 and ev["target_image"].lower().endswith("\\lsass.exe") \
            and not LSASS_OK.search(ev["source_image"]):
        try:
            acc = int(ev["granted_access"], 16)
        except ValueError:
            acc = 0
        if acc & 0x10:                       # PROCESS_VM_READ: what a memory dump needs
            out.append(("lsass_read", "Program read the password store (LSASS) memory", "critical", 50, "T1003.001",
                        "credential", f"{ev['source_image']} (access {ev['granted_access']})"))
    if eid == 4720 and "security" in ch:
        out.append(("user_created", "New user account created", "high", 30, "T1136.001", "permission",
                    f"{ev['target_user']} by {ev['subject_user']}"))
    if eid in (4728, 4732, 4756) and "security" in ch:
        group = ev["target_user"]
        member = ev["member"].split(",")[0].replace("CN=", "") or "?"
        priv = bool(_PRIV_GROUPS.match(group or "")) or bool(_PRIV_SIDS.search(ev["target_sid"] or ""))
        out.append(("group_add", f"Member added to {'a privileged' if priv else 'a security'} group",
                    "critical" if priv else "medium", 45 if priv else 15, "T1098.007", "permission",
                    f"{member} -> {group} by {ev['subject_user']}"))
    if eid == 4724 and "security" in ch and ev["target_user"] and ev["target_user"] != ev["subject_user"]:
        out.append(("pwd_reset", "Someone else's password was reset", "medium", 15, "T1098", "permission",
                    f"{ev['target_user']} by {ev['subject_user']}"))
    if eid in (1102, 104) and ("security" in ch or "system" in ch or eid == 1102):
        out.append(("log_cleared", "Event log cleared", "critical", 50, "T1070.001", "bypass",
                    f"by {ev['subject_user'] or '?'}"))
    if eid == 4719 and "security" in ch:
        out.append(("audit_policy", "Audit policy changed", "high", 30, "T1562.002", "bypass",
                    f"by {ev['subject_user'] or '?'}"))
    if eid in (5001, 5010, 5012) and "defender" in ch:
        out.append(("defender_off", "Microsoft Defender protection turned off", "critical", 45, "T1562.001", "bypass",
                    f"event {eid}"))
    if eid in (4698, 4702) and "security" in ch:
        susp = bool(SUSPICIOUS_PATH.search(ev["task_content"] or ""))
        out.append(("sched_task", f"Scheduled task {'created' if eid == 4698 else 'changed'}"
                    + (" running a script / temp file" if susp else ""), "high" if susp else "low",
                    25 if susp else 5, "T1053.005", "persistence", ev["task"]))
    if (eid == 7045 and "system" in ch) or (eid == 4697 and "security" in ch):
        susp = bool(SUSPICIOUS_PATH.search(ev["service_path"] or "")) or "psexesvc" in ev["service"].lower()
        out.append(("service_install", "New service installed" + (" running a script / temp file" if susp else ""),
                    "high" if susp else "low", 25 if susp else 5, "T1543.003", "persistence",
                    f"{ev['service']}: {ev['service_path'][:200]}"))
    if sysmon and eid == 13 and re.search(r"\\currentversion\\(run|runonce)\\|\\userinitmprlogonscript|"
                                          r"\\winlogon\\(userinit|shell)", ev["target_object"], re.I):
        susp = bool(RUN_SUSPICIOUS.search(ev["details"] or "")) or "userinitmprlogonscript" in ev["target_object"].lower()
        out.append(("run_key", "Program set to start automatically (registry)" + (" - a script / temp file"
                    if susp else ""), "medium" if susp else "low", 20 if susp else 5, "T1547.001", "persistence",
                    f"{ev['target_object'][:160]} = {ev['details'][:120]}"))
    if sysmon and eid in (12, 13, 14) and not REG_OK.search(ev["image"]):
        key = ev["target_object"]
        for rx_key, rx_val, rkey, title, sev, w, mitre in REG_RULES:
            if rx_key.search(key) and (rx_val is None or rx_val.search(ev["details"] or "")):
                out.append((rkey, title, sev, w, mitre, "bypass", f"{key[:160]} = {(ev['details'] or '')[:60]} "
                            f"(by {ev['image'].rsplit(chr(92), 1)[-1] or '?'})"))
                break
    if sysmon and eid in (12, 13, 14) and SERVICE_KEY.search(ev["target_object"]) \
            and (SUSPICIOUS_PATH.search(ev["details"] or "") or "%comspec%" in (ev["details"] or "").lower()):
        out.append(("service_reg", "Service set to run a script / command (registry)", "high", 30, "T1543.003",
                    "persistence", f"{ev['target_object'][:160]} = {(ev['details'] or '')[:120]}"))
    if ((sysmon and eid in (19, 20, 21)) or (eid == 5861 and "wmi" in ch)) \
            and not WMI_BUILTIN.search(f"{ev['wmi_name']} {ev['wmi_dest']}"):
        out.append(("wmi_subscription", "WMI event subscription (runs code automatically on a trigger)", "high", 30,
                    "T1546.003", "persistence", (ev["wmi_name"] or ev["wmi_dest"] or f"event {eid}")[:200]))
    if sysmon and eid == 8 and ev["source_image"] and not INJECT_OK.search(ev["source_image"]):
        out.append(("remote_thread", "Program injected code into another program", "high", 35, "T1055", "attack",
                    f"{ev['source_image'].rsplit(chr(92), 1)[-1]} -> {ev['target_image'].rsplit(chr(92), 1)[-1]}"))
    if (eid == 4688 or (sysmon and eid == 1)) and REMOTE_PARENT.search(ev["parent"]) and REMOTE_CHILD.search(ev["image"]):
        how = "PowerShell remoting" if "wsmprovhost" in ev["parent"].lower() else "WMI"
        out.append(("remote_child", f"Command started from another computer ({how})", "high", 30,
                    "T1021.006" if how != "WMI" else "T1047", "attack",
                    f"{ev['parent'].rsplit(chr(92), 1)[-1]} -> {(ev['cmd'] or ev['image'])[:200]}"))
    if eid == 5145 and "security" in ch:
        pipe = (ev["share_target"] or "").strip().lower()
        who = ev["subject_user"] or ""
        if pipe in ADMIN_PIPES and who and not who.endswith("$") and not _SYSTEM_USERS.match(who):
            key, title, sev, w, mitre, lens = ADMIN_PIPES[pipe]
            out.append((key, title, sev, w, mitre, lens, f"\\pipe\\{pipe} from {ev['ip'] or '?'}"))
    return out


def analyze(evs: list[dict]) -> dict:
    """Events -> incidents grouped by (rule, user, host) + discovery / failed-logon bursts."""
    groups = defaultdict(lambda: {"count": 0, "first": None, "last": None, "examples": []})
    meta = {}
    users, hosts = Counter(), Counter()
    disc = defaultdict(list)                  # (user, host) -> [(t, command)]
    fails = defaultdict(list)                 # target user -> [t]
    success = defaultdict(list)
    for ev in evs:
        who, host = _who(ev), ev["host"] or "?"
        if who and who != "?" and not _SYSTEM_USERS.match(who):
            users[who] += 1
        hosts[host] += 1
        for key, title, sev, w, mitre, lens, detail in _event_rules(ev):
            g = groups[(key, title, who, host)]
            g["count"] += 1
            t = ev["t"]
            if t:
                g["first"] = t if g["first"] is None or t < g["first"] else g["first"]
                g["last"] = t if g["last"] is None or t > g["last"] else g["last"]
            if len(g["examples"]) < 3 and detail not in g["examples"]:
                g["examples"].append(detail)
            meta[(key, title, who, host)] = (sev, w, mitre, lens)
        cmd = ev["cmd"] if (ev["id"] == 4688 or ("sysmon" in ev["channel"] and ev["id"] == 1)) else ""
        if cmd and ev["t"]:
            m = DISCOVERY.search(cmd)
            if m:
                disc[(who, host)].append((ev["t"], m.group(1).lower().split()[0]))
        if ev["id"] == 4625 and ev["t"]:
            fails[ev["target_user"] or "?"].append(ev["t"])
        if ev["id"] == 4624 and ev["t"]:
            success[ev["target_user"] or "?"].append(ev["t"])

    incidents = []
    for k, g in groups.items():
        sev, w, mitre, lens = meta[k]
        incidents.append({"rule": k[0], "label": k[1], "user": k[2], "host": k[3], "severity": sev, "weight": w,
                          "mitre": mitre, "lens": LENSES[lens], "count": g["count"],
                          "first": g["first"].isoformat(sep=" ") if g["first"] else None,
                          "last": g["last"].isoformat(sep=" ") if g["last"] else None, "examples": g["examples"]})
    for (who, host), items in disc.items():         # hands-on-keyboard discovery: 5+ different commands in 10 min
        items.sort()
        best = 0
        for i in range(len(items)):
            kinds = {c for t, c in items[i:] if (t - items[i][0]).total_seconds() <= WINDOW_S}
            best = max(best, len(kinds))
        if best >= 5:
            machine = who.endswith("$") or who.lower() == "system"     # management agents collect inventory like this
            incidents.append({"rule": "discovery", "label": "Burst of discovery commands (someone exploring the system)",
                              "user": who, "host": host, "severity": "low" if machine else "medium",
                              "weight": 5 if machine else 20, "mitre": "T1087",
                              "lens": LENSES["abnormal"], "count": len(items),
                              "first": items[0][0].isoformat(sep=" "), "last": items[-1][0].isoformat(sep=" "),
                              "examples": sorted({c for _, c in items})[:8]})
    for user, ts in fails.items():                  # password guessing, and whether it then worked
        ts.sort()
        best = max((sum(1 for t in ts[i:] if (t - ts[i]).total_seconds() <= WINDOW_S) for i in range(len(ts))),
                   default=0)
        if best >= 10:
            guessed = any(0 <= (s - ts[-1]).total_seconds() <= WINDOW_S for s in success.get(user, []))
            incidents.append({"rule": "brute_force", "label": "Password guessing" + (" - then a successful logon"
                                                                                       if guessed else ""),
                              "user": user, "host": "?", "severity": "critical" if guessed else "high",
                              "weight": 45 if guessed else 30, "mitre": "T1110", "lens": LENSES["abnormal"],
                              "count": len(ts), "first": ts[0].isoformat(sep=" "), "last": ts[-1].isoformat(sep=" "),
                              "examples": [f"{best} failed logons within 10 minutes"]})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    incidents.sort(key=lambda i: (order[i["severity"]], -i["weight"], -i["count"]))
    times = [e["t"] for e in evs if e["t"]]
    return {"events": len(evs), "hosts": len(hosts), "users": len(users),
            "timeRange": [min(times).isoformat(sep=" "), max(times).isoformat(sep=" ")] if times else None,
            "channels": dict(Counter(e["channel"] or "?" for e in evs).most_common(6)),
            "incidents": incidents,
            "lenses": dict(Counter(i["lens"] for i in incidents if i["severity"] in ("critical", "high", "medium")))}


def evtx_to_xml(path: str, timeout: float = 120) -> tuple[str, str]:
    """.evtx file -> (event XML, note). Read by a separate Python process with a time limit; nothing is run."""
    try:
        run = subprocess.run([sys.executable, "-I", EVTX_WORKER, path], capture_output=True, timeout=timeout,
                             check=False)
    except subprocess.TimeoutExpired:
        return "", f"reading the .evtx file took longer than {timeout:.0f} s and was stopped"
    except OSError as exc:
        return "", f"the .evtx reader could not start ({type(exc).__name__})"
    text = run.stdout.decode("utf-8", "replace")
    m = re.search(r"<!-- read (\d+) records; stopped: (.*?) -->", text)
    if not m:
        last = (run.stderr.decode("utf-8", "replace").strip().splitlines() or ["no output"])[-1]
        return "", f"the .evtx file could not be read ({last[:120]})"
    note = m.group(2).strip()
    if int(m.group(1)) == 0:              # nothing readable: never let an unreadable file look like a clean one
        return "", "No events could be read from this .evtx file (it may be damaged, empty or not an event log)" + \
            (f" - {note}." if note else ".")
    return text[:m.start()], (note[:1].upper() + note[1:] + ".") if note else ""


INTERACTIVE_LOGON = {"2", "7", "10", "11"}            # at the keyboard, unlock, remote desktop, cached


def activity_csv(evs) -> tuple[str, int]:
    """Successful interactive logons / logoffs as an Insider Risk activity log (date,user,pc,activity,details) and the
    number of days it covers, so the own-baseline engine can judge unusual logon times and new computers."""
    rows, days = ["date,user,pc,activity,details"], set()
    for e in evs:
        if not e["t"] or not e["host"]:
            continue
        if e["id"] == 4624 and e["logon_type"] in INTERACTIVE_LOGON and e["target_user"] \
                and not _SYSTEM_USERS.match(e["target_user"]):
            rows.append(f"{e['t']:%Y-%m-%d %H:%M:%S},{e['target_user']},{e['host']},logon,")
            days.add(e["t"].date())
        elif e["id"] in (4634, 4647) and e["target_user"] and not _SYSTEM_USERS.match(e["target_user"]):
            rows.append(f"{e['t']:%Y-%m-%d %H:%M:%S},{e['target_user']},{e['host']},logoff,")
    return "\n".join(rows) + "\n", len(days)


def analyze_text(text: str) -> dict | None:
    evs, kind = parse(text)
    if not evs:
        return None
    s = analyze(evs)
    s["format"] = {"xml": "Windows event log (XML)", "json": "Windows event log (JSON)"}.get(kind, kind)
    s["_activity"], s["activityDays"] = activity_csv(evs)
    return s
