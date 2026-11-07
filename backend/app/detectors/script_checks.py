"""
What a SCRIPT would do if someone ran it - read as text, never run (added 30 Oct).

Used by the static file scanner (app/email_pipeline/attachments.py), so it covers e-mail attachments, the Downloads
watcher and the Malware upload card. Script types: PowerShell, batch, VBScript, JScript, Windows Script Files, HTML
applications, shell scripts and Windows shortcuts (.lnk files carry their command line inside).

Each check is a behaviour from MITRE ATT&CK that ordinary scripts rarely need - e.g. download code and run it in
memory, hide the command in Base64, switch off Microsoft Defender, delete backups, inject machine code. Installers
legitimately download and start programs, so that behaviour alone only asks you to check ("medium"). Tested on real
malicious and real ordinary scripts: app/ml/training/test_script_checks.py -> app/ml/models/script_checks.json.

Every check is built so its running time grows only linearly with the file (no open-ended regex backtracking): two
things "close together" are found separately and compared by position, and only the first 1 MB is read.

check(name, data) -> (indicators, floor): floor = the minimum score the strongest finding justifies
(71+ = alert / quarantine, 55 = check carefully, 0 = adds its weight only).
"""
from __future__ import annotations

import base64
import binascii
import bisect
import re
import uuid
from itertools import islice

SCRIPT_EXT = {".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
              ".sh", ".lnk", ".sct"}
MAX_BYTES = 1024 * 1024          # read at most the first 1 MB of a script
MAX_HITS = 2000                  # positions compared per building block
_F = re.I | re.S


# ---- matchers --------------------------------------------------------------------------------------------------
class _Rx:
    """One regex whose repeats are bounded to a single line."""
    def __init__(self, rx):
        self.rx = re.compile(rx, _F)

    def spans(self, text):
        return [(m.start(), m.end(), m.group(0)) for m in islice(self.rx.finditer(text), MAX_HITS)]

    def find(self, text):
        m = self.rx.search(text)
        return m.group(0) if m else None


class _Near:
    """a and b within `gap` characters of each other (b after a when ordered)."""
    def __init__(self, a, b, gap, ordered=False):
        self.a, self.b = (a if isinstance(a, _Rx) else _Rx(a)), (b if isinstance(b, _Rx) else _Rx(b))
        self.gap, self.ordered = gap, ordered

    def spans(self, text):
        a, b = self.a.spans(text), self.b.spans(text)
        if not a or not b:
            return []
        starts = [s for s, _, _ in b]
        out = []
        for s, e, g in a:
            lo = e if self.ordered else s - self.gap
            i = bisect.bisect_left(starts, lo)
            if i < len(b) and b[i][0] <= e + self.gap and (b[i][0] >= e or not self.ordered):
                bs, be, bg = b[i]
                out.append((min(s, bs), max(e, be), f"{g} ... {bg}" if bs >= s else f"{bg} ... {g}"))
                if len(out) >= 5:
                    break
        return out

    def find(self, text):
        sp = self.spans(text)
        return sp[0][2] if sp else None


class _Any:
    def __init__(self, *parts):
        self.parts = parts

    def find(self, text):
        for p in self.parts:
            hit = p.find(text)
            if hit:
                return hit
        return None


class _VarCradle:
    """$x = <download> ... later: iex $x / [scriptblock]::Create($x) - the downloaded text itself is run."""
    def __init__(self, download, run, gap=600):
        self.assign = re.compile(rf"\$(\w+)\s*=\s*[^\n;]{{0,150}}?{download}", _F)
        self.run, self.gap = run, gap

    def find(self, text):
        for m in islice(self.assign.finditer(text), MAX_HITS):
            tail = text[m.end():m.end() + self.gap]
            r = re.search(rf"{self.run}\s*\(?\s*\${re.escape(m.group(1))}\b", tail, _F)
            if r:
                return f"{m.group(0)[:50]} ... {r.group(0)}"
        return None


class _Chain:
    """a, then b within gap, then c within gap (e.g. socket -> its stream -> run what arrives)."""
    def __init__(self, a, b, c, gap):
        self.ab, self.c, self.gap = _Near(a, b, gap, ordered=True), _Rx(c), gap

    def find(self, text):
        cs = self.c.spans(text)
        starts = [s for s, _, _ in cs]
        for s, e, g in self.ab.spans(text):
            i = bisect.bisect_left(starts, e)
            if i < len(cs) and cs[i][0] <= e + self.gap:
                return f"{g} ... {cs[i][2]}"
        return None


# ---- building blocks ----------------------------------------------------------------------------------------------
_DOWNLOAD = (r"(downloadstring|downloaddata|downloadfile|openread|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|"
             r"net\.webclient|webclient|start-bitstransfer|bitsadmin[^\n]{0,80}/transfer|msxml2\.(server)?xmlhttp|"
             r"microsoft\.xmlhttp|winhttp\.winhttprequest|certutil[^\n]{0,60}-urlcache|\bcurl(\.exe)?\s[^\n]{0,120}https?://|"
             r"\bwget(\.exe)?\s[^\n]{0,120}https?://|nslookup[^\n]{0,30}(-q|-type|-querytype)=txt|resolve-dnsname[^\n]{0,80}txt)")
_RUN_IN_MEMORY = r"(\biex\b|invoke-expression|scriptblock\]::create|\[scriptblock\]|reflection\.assembly\]::load|\.invoke\(\))"
_RUN_FILE = (r"(start-process|\bsaps\b|invoke-item|\.shellexecute|\.run\s*\(|\.exec\s*\(|\bstart\s+[\"']?[^\s]+\.(exe|bat|"
             r"cmd|vbs|js|ps1|dll|scr)|cmd(\.exe)?\s+/c\s|rundll32|regsvr32)")
_PUBLIC_IP_URL = r"https?://(?!(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\.)\d{1,3}(\.\d{1,3}){3}"
_ENC_FLAG = r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+"

# (label, matcher, severity, weight, floor, mitre, description)
CHECKS = [
    ("Script hides its command in Base64 (encoded PowerShell)",
     _Any(_Rx(rf"(powershell|pwsh)(\.exe)?[^\n]{{0,200}}{_ENC_FLAG}[a-z0-9+/=]{{40,}}"),
          _Near(r"frombase64string", r"(\biex\b|invoke-expression|scriptblock|\.invoke\(\)|deflatestream|gzipstream)", 600)),
     "critical", 30, 75, "T1027.010",
     "The script hides the code it runs in Base64 / compressed text so a person (or a scanner) cannot read it - a "
     "classic malware trick (MITRE T1027)."),
    ("Script downloads code and runs it in memory",
     _Any(_Rx(rf"{_DOWNLOAD}[^\n;]{{0,250}}\|\s*{_RUN_IN_MEMORY}"),
          _Rx(rf"{_RUN_IN_MEMORY}[^\n;]{{0,40}}\(?\s*[^\n;]{{0,120}}{_DOWNLOAD}"),
          _VarCradle(_DOWNLOAD, _RUN_IN_MEMORY)),
     "critical", 30, 75, "T1105",
     "It fetches code from the internet and runs it straight from memory (a 'download cradle'), so nothing is saved "
     "where an antivirus would look. Some tool installers do this too - only run it if you trust the exact source."),
    ("Script loads machine code into memory (shellcode / injection)",
     _Near(r"virtualalloc(ex)?", r"(createthread|createremotethread|marshal\]::copy|memset|callwindowproc|"
                                 r"getdelegateforfunctionpointer|writeprocessmemory)", 3000),
     "critical", 40, 85, "T1055",
     "It reserves executable memory and starts raw machine code in it - how in-memory malware and remote-access "
     "tools are loaded. Ordinary scripts never need this."),
    ("Script switches off antivirus / security logging",
     _Rx(r"set-mppreference[^\n]{0,120}-disable\w*\s+(\$true|1)|add-mppreference[^\n]{0,80}-exclusion|"
         r"amsi" r"initfailed|amsi" r"utils|amsi" r"scanbuffer|disableantispyware|disablerealtimemonitoring[^\n]{0,40}(\$true|\b1\b)|"
         r"stop-service[^\n]{0,30}windefend|sc(\.exe)?\s+(stop|config)\s+windefend|"
         r"netsh[^\n]{0,30}(advfirewall|firewall)\s+set[^\n]{0,60}(state\s+off|opmode\s+disable)"),
     "critical", 35, 85, "T1562.001",
     "It turns off Microsoft Defender, AMSI or the firewall - malware does this before its real work so nothing "
     "stops it."),
    ("Script bypasses Windows' admin prompt (UAC) or adds a password-stealing module",
     _Rx(r"(hkcu:?|hkey_current_user)\\software\\classes\\(ms-settings|exefile|mscfile|folder|launcher\.systemsettings)"
         r"\\shell\\(open|runas)\\command|\\control\\lsa[^\n]{0,80}security packages"),
     "critical", 35, 85, "T1548.002",
     "It rewrites the registry so a trusted Windows program starts its code with admin rights without asking (UAC "
     "bypass), or loads its own module into the Windows login process to collect passwords."),
    ("Script clears Windows event logs",
     _Rx(r"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog"),
     "high", 20, 55, "T1070.001",
     "It wipes Windows' event logs - attackers do this to hide their tracks; administrators rarely need it."),
    ("Script deletes backups / shadow copies (ransomware sign)",
     _Any(_Rx(r"vssadmin(\.exe)?[^\n]{0,30}delete\s+shadows|wmic(\.exe)?[^\n]{0,20}shadowcopy[^\n]{0,20}delete|"
              r"wbadmin(\.exe)?[^\n]{0,20}delete\s+(catalog|systemstatebackup|backup)|bcdedit[^\n]{0,60}recoveryenabled\s+no|"
              r"get-ciminstance[^\n]{0,40}win32_shadowcopy[^\n]{0,80}remove-ciminstance"),
          _Near(r"win32_shadowcopy", r"\.delete\(\)", 200, ordered=True)),
     "critical", 35, 85, "T1490",
     "It deletes Windows' backup copies so files cannot be restored - what ransomware does right before encrypting."),
    ("Script opens a remote command line for an attacker (reverse shell)",
     _Any(_Chain(r"net\.sockets\.(tcpclient|tcplistener)", r"getstream", r"(\biex\b|invoke-expression|sendback)", 1500),
          _Rx(r"/dev/tcp/[\d.]+/\d+|\bnc(at)?(\.exe)?\s[^\n]{0,60}\s-e\s")),
     "critical", 40, 85, "T1059",
     "It connects out to another computer and runs whatever commands come back - a remote-control backdoor."),
    ("Script contains a known attack tool",
     # (tool names are split in two so an antivirus never mistakes this source file for the tools themselves)
     _Rx(r"invoke-mimi" r"katz|sekur" r"lsa::|lsa" r"dump::|kerberos::(golden|ptt)|invoke-(kerberoast|shellcode|"
         r"reflectivepeinjection|dllinjection|tokenmanipulation|powershelltcp|psinject|bypassuac|wmicommand)|"
         r"get-(gpppassword|keystrokes)|powersploit|invoke-empire"),
     "critical", 40, 85, "T1588.002",
     "It contains a well-known hacking tool (credential dumping, code injection, UAC bypass). Security testers use "
     "these too - but a file like this arriving by download or e-mail is dangerous."),
    ("Script uses a Windows program to run code from the internet",
     _Rx(r"mshta(\.exe)?\s+[\"']?(https?:|javascript:|vbscript:)|regsvr32(\.exe)?[^\n]{0,80}/i:\s*[\"']?https?:|"
         r"scrobj\.dll|rundll32(\.exe)?[^\n]{0,80}(javascript:|https?:)|"
         r"msiexec(\.exe)?[^\n]{0,40}/(q|i)[^\n]{0,40}https?:|certutil(\.exe)?[^\n]{0,60}-decode"),
     "high", 25, 75, "T1218",
     "It makes a trusted Windows program (mshta, regsvr32, rundll32, msiexec, certutil) fetch or unpack and run code - "
     "a way malware slips past application controls (MITRE T1218)."),
    ("Script downloads a program and starts it",
     _Near(_DOWNLOAD, _RUN_FILE, 600),
     "medium", 15, 55, "T1105",
     "It downloads a program and starts it. Installers do this too; malware droppers do exactly the same - check "
     "where the script came from before running it."),
    ("Script downloads a program from a bare IP address and starts it",
     _Near(_DOWNLOAD + r"[^\n]{0,120}" + _PUBLIC_IP_URL, _RUN_FILE, 600),
     "high", 25, 75, "T1105",
     "It downloads a program from a bare internet IP address (no website name) and starts it - real software comes "
     "from named, signed websites; malware droppers often use raw addresses."),
    ("Script pretends to be a web browser while downloading",
     _Near(r"(webclient|invoke-webrequest|xmlhttp)", r"user-agent[^\n]{0,40}mozilla/", 400, ordered=True),
     "medium", 15, 55, "T1071.001",
     "It downloads with a fake web-browser identity (User-Agent), as attack tools do to blend in with normal browsing."),
    ("Script is scrambled with Microsoft's Script Encoder",
     _Rx(r"#@~\^?[a-z0-9+/]{6}=="),
     "critical", 30, 75, "T1027",
     "The script is scrambled with Microsoft's old Script Encoder (.vbe / .jse) so it cannot be read. This tool has "
     "been obsolete for years; today it is used almost only to hide malware."),
    ("Script runs hidden",
     _Any(_Rx(r"(powershell|pwsh)(\.exe)?[^\n]{0,200}\s-w(i|in|ind|indo|indow|indows|indowst\w*)?\s+h(idden)?\b|"
              r"-windowstyle\s+hidden"),
          _Near(r"createobject\([\"']wscript\.shell[\"']\)", r"\.run[^\n]{0,200},\s*0\b", 200, ordered=True)),
     "medium", 15, 0, "T1564.003",
     "It starts PowerShell or a program with an invisible window, so you would not see it working."),
    ("Script hides its text with character codes",
     None, "medium", 15, 0, "T1027",
     "Most of the script's text is written as character codes ([char]123, fromCharCode, chr()) instead of plain "
     "words - a way to hide what it does."),
    ("Script sets itself to start automatically",
     _Rx(r"schtasks(\.exe)?[^\n]{0,20}/create|register-scheduledtask|new-scheduledtask|"
         r"currentversion\\run(once)?\b|start menu\\programs\\startup|\\startup\\|new-service|sc(\.exe)?\s+create\s"),
     "medium", 10, 0, "T1547",
     "It makes something start automatically (scheduled task, Run key, Startup folder or service). Installers do this; "
     "so does malware that wants to survive a restart."),
]
_CHARCODE = re.compile(r"\[char\]\s*\(?\s*0?x?[0-9a-f]+|fromcharcode|\bchrw?\(\s*\d+", re.I)


def _ind(label, severity, weight, mitre, desc, evidence):
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label,
            "description": desc + (f" Evidence: \"{evidence}\"." if evidence else ""),
            "severity": severity, "weight": weight, "triggered": True, "source": "attachment", "mitre": mitre}


def readable_text(data: bytes) -> str:
    """The script as text: UTF-8 / UTF-16 (PowerShell files and .lnk command lines are often UTF-16), with the
    simplest hiding tricks undone (PowerShell backticks, cmd carets, 'str'+'ing' joins, extra spaces)."""
    data = data[:MAX_BYTES]
    parts = [data.decode("utf-8", "ignore")]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or data.count(b"\x00") > len(data) // 8:
        enc = "utf-16-be" if data[:2] == b"\xfe\xff" else "utf-16-le"
        parts.append(data.decode(enc, "ignore"))
        parts.append(data[1:].decode(enc, "ignore"))      # odd offset (strings inside a binary .lnk)
    text = "\n".join(p.replace("\x00", "") for p in parts)
    text = text.replace("`", "").replace("^", "")
    text = re.sub(r"[\"']\s*\+\s*[\"']", "", text)        # 'Down'+'loadString' -> DownloadString
    return re.sub(r"[ \t]+", " ", text)


def _decoded_commands(text: str) -> str:
    """PowerShell -EncodedCommand payloads decoded (UTF-16LE Base64), so the checks also read what is hidden."""
    out = []
    for m in islice(re.finditer(_ENC_FLAG + r"([a-z0-9+/=]{40,})", text, re.I), 5):
        try:
            out.append(base64.b64decode(m.group(m.lastindex) + "===")[:MAX_BYTES].decode("utf-16-le", "ignore"))
        except (binascii.Error, ValueError):
            pass
    return "\n".join(out).replace("`", "")


def check(name: str, data: bytes) -> tuple[list[dict], int]:
    """Indicators (only the ones found) and the score floor they justify."""
    text = readable_text(data)
    hidden = _decoded_commands(text)
    full = text + ("\n" + hidden if hidden else "")
    inds, floor = [], 0
    for label, matcher, sev, weight, fl, mitre, desc in CHECKS:
        if matcher is None:     # character-code obfuscation: many codes, a large share of the script
            n = sum(1 for _ in islice(_CHARCODE.finditer(full), 100000))
            ev = f"{n} character codes" if n >= 40 and n * 8 >= len(full) * 0.2 else None
        else:
            ev = matcher.find(full)
        if ev:
            if hidden and matcher is not None and not matcher.find(text):
                desc = desc + " (found after decoding the hidden Base64 command)"
            inds.append(_ind(label, sev, weight, mitre, desc, re.sub(r"\s+", " ", ev)[:80]))
            floor = max(floor, fl)
    return inds, floor
