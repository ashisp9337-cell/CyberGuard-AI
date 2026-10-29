"""Insider Risk - the per-event signal rules, shared WORD FOR WORD by training (prepare_insider_data.py) and the live
detector, so a log line is judged the same way in both.

Each activity event (logon, USB connect, file copy, e-mail, web visit) adds to one "user-day" record of counts.
Site categories are matched on the exact domain or its sub-domains (so inbox.com is NOT box.com, lifehacker.com is NOT a
hacking site). The lists are general real-world lists, not taken from any answer key:
  * leak      - public leak / whistle-blowing sites
  * cloud     - file-sharing / upload services (a common exfiltration channel, MITRE T1567.002)
  * spyware   - keylogger / employee-monitoring / spyware vendors (MITRE T1056.001 when installed on someone else's PC)
  * job       - job-search sites (a known "about to leave" precursor in insider-threat research)
"""
import os
import re
from collections import defaultdict
from datetime import datetime

FEATURES = ["logon_n", "logon_after", "logon_weekend", "first_min", "last_min", "usb_n", "usb_after", "file_n",
            "file_after", "file_exe", "file_doc", "file_zip", "email_n", "email_ext", "email_personal",
            "email_personal_attach", "email_attach", "email_kb", "email_after", "web_job", "web_cloud", "web_leak",
            "web_spyware"]

LEAK = ("wikileaks.org", "wikileaks.ch", "cryptome.org", "ddosecrets.com", "publeaks.nl")
CLOUD = ("dropbox.com", "box.com", "box.net", "mega.nz", "mega.co.nz", "mega.io", "drive.google.com", "docs.google.com",
         "onedrive.live.com", "1drv.ms", "mediafire.com", "rapidshare.com", "sendspace.com", "4shared.com",
         "yousendit.com", "hightail.com", "wetransfer.com", "we.tl", "pastebin.com", "filedropper.com",
         "zippyshare.com", "megaupload.com", "hotfile.com", "depositfiles.com", "uploaded.net", "anonfiles.com",
         "file.io", "gofile.io", "transfer.sh", "icloud.com")
SPYWARE_VENDORS = ("refog.com", "spectorsoft.com", "spectorpro.com", "ardamax.com", "actualkeylogger.com",
                   "spyrix.com", "webwatchernow.com", "softactivity.com", "relytec.com", "spytech-web.com",
                   "flexispy.com", "mspy.com", "best-spy-soft.com", "wolfeye.us", "kidlogger.net", "elitekeylogger.com")
SPYWARE_RE = re.compile(r"keylog|spyware|(^|[.-])spy([.-]|soft|ware)", re.I)
JOB = ("monster.com", "careerbuilder.com", "indeed.com", "simplyhired.com", "glassdoor.com", "hotjobs.yahoo.com",
       "dice.com", "job-hunt.org", "jobhuntersbible.com", "ziprecruiter.com", "naukri.com", "monsterindia.com",
       "shine.com", "timesjobs.com", "angel.co", "wellfound.com", "hired.com", "theladders.com")
JOB_RE = re.compile(r"(^|[.-])(jobs?|careers?)([.-]|$)|jobhunt|recruit|hiring", re.I)
PERSONAL_MAIL = ("gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "ymail.com", "hotmail.com", "outlook.com",
                 "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.net",
                 "protonmail.com", "proton.me", "zoho.com", "yandex.com", "rediffmail.com", "comcast.net",
                 "verizon.net", "earthlink.net", "juno.com", "netzero.net", "cox.net", "bellsouth.net", "att.net",
                 "sbcglobal.net", "inbox.com", "tutanota.com")

EXE = (".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".scr", ".jar")
DOC = (".doc", ".docx", ".pdf", ".xls", ".xlsx", ".csv", ".ppt", ".pptx", ".txt", ".rtf", ".odt", ".ods")
ZIP = (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2")

_DATE_FORMATS = ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                 "%Y-%m-%d %H:%M:%S.%f", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M")
_CERT_DATE = re.compile(r"(\d{2})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2})")


def parse_time(s):
    """CERT's MM/DD/YYYY HH:MM:SS (fast path) or a common ISO / SIEM timestamp; None when unreadable."""
    s = (s or "").strip().strip('"')
    m = _CERT_DATE.fullmatch(s)
    if m:
        mo, d, y, hh, mi, ss = map(int, m.groups())
        try:
            return datetime(y, mo, d, hh, mi, ss)
        except ValueError:
            return None
    s = s.rstrip("Z")
    if len(s) > 6 and s[-6] in "+-" and s[-3] == ":":       # drop a +05:30 style offset (local clock time is used)
        s = s[:-6]
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def after_hours(t):
    """Weekend, or before 07:00 / from 19:00 (the organisation-wide 'office hours'; per-person hours are learned)."""
    return t.weekday() >= 5 or t.hour < 7 or t.hour >= 19


def domain_of(url):
    u = (url or "").strip().strip('"').split("://", 1)[-1]
    d = u.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":", 1)[0].lower().rstrip(".")
    return d.removeprefix("www.")


def _in(d, names):
    return any(d == n or d.endswith("." + n) for n in names)


def site_category(dom):
    """'leak' | 'cloud' | 'spyware' | 'job' | '' for a domain (www. already removed by domain_of)."""
    d = (dom or "").lower().removeprefix("www.")
    if not d:
        return ""
    if _in(d, LEAK):
        return "leak"
    if _in(d, CLOUD):
        return "cloud"
    if _in(d, SPYWARE_VENDORS) or SPYWARE_RE.search(d):
        return "spyware"
    if _in(d, JOB) or JOB_RE.search(d):
        return "job"
    return ""


def is_personal_address(addr):
    a = (addr or "").strip().lower()
    return "@" in a and _in(a.rsplit("@", 1)[1], PERSONAL_MAIL)


def file_kind(name):
    ext = os.path.splitext((name or "").strip().strip('"'))[1].lower()
    return "exe" if ext in EXE else "doc" if ext in DOC else "zip" if ext in ZIP else ""


def new_day():
    return defaultdict(float)


def _first_last(d, t):
    mins = t.hour * 60 + t.minute
    d["first_min"] = mins if "first_min" not in d else min(d["first_min"], mins)
    d["last_min"] = mins if "last_min" not in d else max(d["last_min"], mins)


def add_logon(d, t, activity):
    if (activity or "").strip().lower() in ("logon", "login", "log on", "4624"):
        d["logon_n"] += 1
        d["logon_after"] += after_hours(t)
        d["logon_weekend"] += t.weekday() >= 5
    _first_last(d, t)


def add_usb(d, t, activity):
    if (activity or "").strip().lower() not in ("connect", "connected", "insert", "mount"):
        return False
    d["usb_n"] += 1
    d["usb_after"] += after_hours(t)
    _first_last(d, t)
    return True


def add_file(d, t, filename):
    k = file_kind(filename)
    d["file_n"] += 1
    d["file_after"] += after_hours(t)
    d["file_exe"] += k == "exe"
    d["file_doc"] += k == "doc"
    d["file_zip"] += k == "zip"


def add_email(d, t, recipients, size_bytes, attachments):
    """recipients: list of addresses (to + cc + bcc). 'email_ext' is filled later (needs the company domain)."""
    has_att = str(attachments or "").strip() not in ("", "0")
    personal = any(is_personal_address(r) for r in recipients)
    d["email_n"] += 1
    d["email_attach"] += has_att
    d["email_personal"] += personal
    d["email_personal_attach"] += personal and has_att
    d["email_after"] += after_hours(t)
    try:
        d["email_kb"] += float(size_bytes) / 1024
    except (TypeError, ValueError):
        pass


def add_web(d, t, dom):
    cat = site_category(dom)
    if cat:
        d["web_" + cat] += 1
    return cat


def split_recipients(*fields):
    out = []
    for f in fields:
        out += [r.strip().lower() for r in re.split(r"[;,\s]+", f or "") if "@" in r]
    return out
