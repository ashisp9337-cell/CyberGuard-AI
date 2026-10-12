"""
Watcher 3 -- Windows sign-in events on this PC (Module 4: failed logins, brute force, spraying).

Technology: Windows' own built-in tool `wevtutil` reads the Security event log (read-only):
   Event 4625 = "An account failed to log on"   (wrong password, unknown user ...)
   Event 4624 = "An account was successfully logged on"
Every WINDOWS_EVENTS_POLL_SECONDS the last hour of these events is turned into log lines and given
to the same Credential Theft engine you use manually (rules + RBA risk model). New risky patterns
(e.g. 8 failed logins then a success, or many usernames tried from one IP) are saved + alerted.

Windows only lets ADMINISTRATORS read the Security log: start the backend terminal with
"Run as administrator", otherwise this watcher shows "needs setup" and everything else still works.
Background service sign-ins (logon type 5) and machine accounts (NAME$) are ignored -- they are noise.
"""
import os
import platform
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

from app.automation.engine import Watcher, get_state, save_and_alert, update_state
from app.core.config import get_settings

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
USER_LOGON_TYPES = {"2", "3", "7", "8", "10", "11"}     # interactive, network, unlock, cleartext, RDP, cached
NOISE_USERS = {"system", "local service", "network service", "anonymous logon", "-", ""}
QUERY = ("*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 3600000]]]")


def parse_events(xml_text: str) -> list[dict]:
    """wevtutil /f:xml output (several <Event> elements) -> list of simple dicts, oldest first."""
    if not xml_text.strip():
        return []
    root = ET.fromstring(f"<Events>{xml_text}</Events>")
    out = []
    for ev in root.findall("e:Event", NS):
        sysn = ev.find("e:System", NS)
        data = {d.get("Name"): (d.text or "") for d in ev.findall("e:EventData/e:Data", NS)}
        out.append({
            "id": int(sysn.findtext("e:EventID", default="0", namespaces=NS)),
            "record": int(sysn.findtext("e:EventRecordID", default="0", namespaces=NS)),
            "time": sysn.find("e:TimeCreated", NS).get("SystemTime", ""),
            "user": data.get("TargetUserName", ""), "domain": data.get("TargetDomainName", ""),
            "ip": data.get("IpAddress", ""), "logon_type": data.get("LogonType", ""),
            "sub_status": data.get("SubStatus", "").lower(), "workstation": data.get("WorkstationName", ""),
        })
    return sorted(out, key=lambda e: e["record"])


def to_log_lines(events: list[dict]) -> list[str]:
    """Only real user sign-ins, in the text format the Credential Theft engine already understands."""
    lines = []
    for e in events:
        user = e["user"].strip()
        if user.lower() in NOISE_USERS or user.endswith("$") or user.upper().startswith(("DWM-", "UMFD-")):
            continue
        if e["id"] == 4624 and e["logon_type"] not in USER_LOGON_TYPES:
            continue
        try:
            ts = datetime.fromisoformat(e["time"][:19]).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            ts = e["time"][:19].replace("T", " ")
        ip = e["ip"] if e["ip"] not in ("-", "") else "local"
        if e["id"] == 4625:
            missing = " Sub Status: 0xC0000064 (user does not exist)" if e["sub_status"] == "0xc0000064" else ""
            lines.append(f"{ts} EventID=4625 An account failed to log on. Account Name: {user} "
                         f"Source Network Address: {ip} Logon Type: {e['logon_type']}{missing}")
        else:
            lines.append(f"{ts} EventID=4624 An account was successfully logged on. Account Name: {user} "
                         f"Source Network Address: {ip} Logon Type: {e['logon_type']}")
    return lines


def read_security_log() -> str:
    cmd = ["wevtutil", "qe", "Security", f"/q:{QUERY}", "/f:xml", "/c:500"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if p.returncode != 0:
        err = (p.stderr or p.stdout).strip()
        if "access is denied" in err.lower() or p.returncode == 5:
            raise PermissionError("Windows allows only administrators to read sign-in events. Close the backend, "
                                  "open the terminal with right-click > 'Run as administrator', and start it again.")
        raise RuntimeError(f"wevtutil failed: {err[:200]}")
    return p.stdout


class WindowsLogonWatcher(Watcher):
    name = "windows"
    title = "Windows sign-ins on this PC"
    what = "Failed and successful Windows logons are checked for brute force, password spraying and unusual sign-ins."
    modules = ["Credential theft & account takeover"]
    technology = "Windows Security event log (events 4624/4625) via built-in wevtutil + CyberGuard Credential engine"

    def __init__(self):
        super().__init__()
        self.interval_seconds = max(60, get_settings().WINDOWS_EVENTS_POLL_SECONDS)

    def configured(self):
        if platform.system() != "Windows":
            return False, "Only available when the backend runs on Windows."
        return True, ""

    def check(self) -> dict:
        from app.detectors import account_takeover
        events = parse_events(read_security_log())
        return self.analyse(events, account_takeover)

    def analyse(self, events: list[dict], account_takeover) -> dict:
        st = get_state(self.name)
        last = int(st.get("lastRecord", 0))
        new = [e for e in events if e["record"] > last]
        if events:
            update_state(self.name, lastRecord=max(e["record"] for e in events))
        lines = to_log_lines(events)
        new_lines = to_log_lines(new)
        if not new_lines:
            return {"checked": 0, "threats": 0, "note": f"No new sign-ins ({len(lines)} in the last hour)"}
        result = account_takeover.analyze_event({}, "Windows sign-in monitoring", text="\n".join(lines))
        signature = sorted(i["label"] for i in result["indicators"] if i["triggered"])
        self.record(f"{len(new_lines)} new Windows sign-in event(s)", result["riskScore"], result["classification"])
        threats, finding = 0, None
        if result["riskScore"] >= 51 and signature != st.get("lastSignature"):
            host = os.environ.get("COMPUTERNAME") or socket.gethostname()
            scan_id = save_and_alert(module_id="credential", subtopic_id="failed-logins",
                                     subtopic_title="Windows sign-in monitoring", result=result,
                                     target=f"Windows sign-ins on {host}", target_type="text",
                                     source="windows", metadata={"events": len(lines)})
            if scan_id:
                threats, finding = 1, f"{signature[0] if signature else 'Risky sign-ins'} (score {result['riskScore']})"
            update_state(self.name, lastSignature=signature)
        return {"checked": len(new_lines), "threats": threats, "finding": finding,
                "note": f"{len(new_lines)} new sign-in event(s) checked"}
