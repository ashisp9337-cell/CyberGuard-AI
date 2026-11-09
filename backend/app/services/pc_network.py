"""
Live PC network monitor (6 Nov): this computer's OPEN PORTS (programs waiting for connections) and its LIVE NETWORK
CONNECTIONS, with the suspicious ones explained in plain words.

READ-ONLY by design: nothing is closed, blocked, killed or changed, nothing is sent anywhere, and nothing is stored -
it is a fresh look every time the page asks. Program COMMAND LINES are never read (they can hold passwords / tokens);
only the program's name and the folder it runs from.

What is flagged, and why (facts, not guesses - each one is a thing a security check would tell you to look at):
  * a database / remote-desktop / old clear-text service open to ALL networks (not only this computer): anyone on the
    same Wi-Fi can try to log in to it (RDP and databases are the most attacked services);
  * any traffic on a known backdoor port (4444 = Metasploit, 31337, 1337, 6667 IRC botnets ...) - the same list the
    network-traffic check uses (app/detectors/network_traffic.py);
  * a program running from a Temp / Downloads / Public folder that uses the network - where malware usually starts;
  * a connection to an IP address that one of YOUR earlier scans already marked as dangerous (your IOC list).
Windows' own file-sharing ports (135/139/445 of the System process) are shown as "low": they are open on every
Windows PC and Windows Firewall normally closes them on public networks.
"""
import ipaddress
import os
import re
import sys
import time
from collections import Counter

from app.detectors.network_traffic import BACKDOOR_PORTS, is_internal

MAX_CONNECTIONS = 500          # rows returned (a busy PC can have thousands; the summary counts all of them)

# port: (service, severity when open to ALL networks, why)
EXPOSED = {
    3389: ("Remote Desktop (RDP)", "high", "the most attacked login on Windows: password guessing and ransomware gangs "
                                          "look for it"),
    5900: ("VNC remote desktop", "high", "remote control of this computer; often weak or no password"),
    23: ("Telnet", "high", "an old remote login that sends passwords as plain text"),
    21: ("FTP file transfer", "high", "sends passwords as plain text"),
    5432: ("PostgreSQL database", "high", "a database should only accept connections from this computer"),
    3306: ("MySQL database", "high", "a database should only accept connections from this computer"),
    1433: ("Microsoft SQL Server", "high", "a database should only accept connections from this computer"),
    27017: ("MongoDB database", "high", "a database should only accept connections from this computer"),
    6379: ("Redis database", "high", "Redis has no password by default and is often taken over"),
    9200: ("Elasticsearch", "high", "often left open without a password"),
    11211: ("Memcached", "high", "no password; abused for attacks"),
    22: ("SSH remote login", "medium", "fine if you need it - use keys or a strong password"),
    8000: ("web / API server (CyberGuard's backend uses 8000)", "medium",
           "a development server should only listen on this computer (start it without --host 0.0.0.0)"),
    5173: ("web development server (CyberGuard's frontend uses 5173)", "medium",
           "a development server should only listen on this computer"),
    8080: ("web server", "medium", "check that you meant to share it with the network"),
    445: ("Windows file sharing (SMB)", "medium", "the WannaCry worm spread through it; share only on trusted networks"),
    139: ("Windows file sharing (NetBIOS)", "medium", "share only on trusted networks"),
    135: ("Windows RPC", "medium", "share only on trusted networks"),
}
_WINDOWS_BUILTIN = {135, 139, 445}
_RISKY_DIRS = re.compile(r"[\\/](?:appdata[\\/]local[\\/]temp|windows[\\/]temp|downloads|users[\\/]public)[\\/]|"
                         r"^/(?:tmp|var/tmp|dev/shm)/", re.I)
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        return None


def install_hint() -> str:
    """(7 Nov) The exact install command for the Python that runs CyberGuard: a plain 'pip' can belong to another
    Python (another venv / the system one), which installs psutil where CyberGuard never looks. Relative to the
    backend folder, so no user name is shown."""
    backend = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    exe = sys.executable or "python"
    try:
        exe = os.path.relpath(exe, backend)
    except ValueError:                       # Python on another drive (Windows)
        pass
    run = f'& "{exe}"' if " " in exe else exe
    return f"Install the 'psutil' package - in the backend folder run: {run} -m pip install -r requirements.txt"


def _scope(ip: str) -> str:
    """'this computer only' / 'all networks' / 'your network' for the address a port is bound to."""
    if ip in ("0.0.0.0", "::", ""):
        return "all networks"
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "your network"
    return "this computer only" if a.is_loopback else "your network"


def _proc_info(psutil, pid, cache):
    if pid in cache:
        return cache[pid]
    info = {"pid": pid, "name": "unknown", "path": ""}
    if pid:
        try:
            p = psutil.Process(pid)
            info["name"] = p.name()
            try:
                info["path"] = p.exe() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            pass
    elif pid == 0:
        info["name"] = "System Idle / unknown"
    cache[pid] = info
    return info


def _flag(sev, title, why, **where) -> dict:
    return {"severity": sev, "title": title, "why": why, **where}


# (7 Nov) How to fix each kind of finding - shown on the PC Network page and in the saved finding, instead of the
# generic incident advice ("block the source", "escalate to the incident response team") that does not fit a SETTING
# such as an open port.
_SERVICE_FIX = {
    5432: "PostgreSQL: in postgresql.conf set listen_addresses = 'localhost', then restart the PostgreSQL service "
          "(Win+R > services.msc).",
    3306: "MySQL: in my.ini set bind-address = 127.0.0.1, then restart the MySQL service.",
    1433: "SQL Server: if only this PC uses it, switch TCP/IP off in SQL Server Configuration Manager, then restart "
          "the SQL Server service.",
    27017: "MongoDB: in mongod.cfg set net.bindIp: 127.0.0.1, then restart MongoDB.",
    6379: "Redis: in redis.conf set bind 127.0.0.1 and protected-mode yes, then restart Redis.",
    9200: "Elasticsearch: in elasticsearch.yml set network.host: 127.0.0.1, then restart it.",
    11211: "Memcached: start it with -l 127.0.0.1 so it only listens on this computer.",
    3389: "Remote Desktop: if you do not use it, switch it off (Settings > System > Remote Desktop). If you do, keep "
          "Network Level Authentication on and use a long password.",
    5900: "VNC: close the VNC server if you do not use it; otherwise give it a strong password.",
    23: "Telnet: switch the Telnet server off and use SSH instead (Telnet sends passwords as plain text).",
    21: "FTP: stop the FTP server if you do not need it; use SFTP instead.",
    22: "SSH: use key login or a long password, and switch password login off if you can.",
    8000: "Start the server without --host 0.0.0.0, so it only listens on this computer.",
    5173: "Start the development server without --host, so it only listens on this computer.",
    8080: "If you did not mean to share it, make the server listen on 127.0.0.1 only.",
}
_FIREWALL = ("Keep Windows Firewall on, and set shared Wi-Fi (college, hackathon venue) to 'Public network' in "
             "Settings > Network & internet - Windows then blocks these ports from other computers.")
_SCAN_FILE = ("If you do not recognise it: switch Wi-Fi off, end the process, and scan its file with CyberGuard's "
              "Malware Detection and a Microsoft Defender full scan (Windows Security > Virus & threat protection > "
              "Scan options) before deleting anything.")


def finding_kind(f: dict) -> str:
    """exposed | backdoor_listen | risky_listen | backdoor_conn | flagged_ip | risky_conn (from the finding's title)."""
    t = f.get("title", "")
    if t.startswith("A program is listening on backdoor port"):
        return "backdoor_listen"
    if t.startswith("Connection on backdoor port"):
        return "backdoor_conn"
    if t.startswith("Connected to an address your scans flagged"):
        return "flagged_ip"
    if t.startswith("A program from a temporary / download folder"):
        return "risky_conn" if f.get("remote") else "risky_listen"
    return "exposed"


def advice(f: dict) -> list[str]:
    """Concrete next steps for one finding, most important first."""
    kind = finding_kind(f)
    prog = f.get("program") or "unknown program"
    find = (f"Find the program: Task Manager > Details > process id {f.get('pid')} ({prog}); right-click > "
            "Open file location shows where it runs from." if f.get("pid") else
            f"Find the program ({prog}) in Task Manager > Details.")
    remote = f.get("remote")
    if kind == "exposed":
        port = f.get("port")
        steps = [_SERVICE_FIX.get(port, "If this program does not need other computers, make it listen on this "
                                        "computer only (127.0.0.1) or close it."),
                 _FIREWALL,
                 "Afterwards the PC Network page lists the port as 'this computer only'.",
                 "This is a risky setting, not an attack in progress - nothing was blocked or closed."]
        if port in _WINDOWS_BUILTIN:
            steps = [_FIREWALL, "Share files only on trusted networks; nothing was blocked or closed."]
        return steps
    if kind == "backdoor_listen":
        return [find, "If you started it yourself (a test server), stop it - press Ctrl+C in its window.", _SCAN_FILE]
    if kind == "risky_listen":
        return [find, "Programs that run from Temp / Downloads and wait for connections are how much malware works.",
                _SCAN_FILE]
    if kind == "backdoor_conn":
        return ["If you do not know this program, switch Wi-Fi off now to cut the connection.", find,
                f"Look up {remote} on the Threat Intelligence page.", _SCAN_FILE]
    if kind == "flagged_ip":
        return [f"Look up {remote} on the Threat Intelligence page to see why an earlier scan flagged it.", find,
                _SCAN_FILE]
    return [find, f"Look up {remote} on the Threat Intelligence page." if remote else "Make sure you know this program.",
            _SCAN_FILE]


def raw_connections(psutil) -> list[dict]:
    """(10 Nov) The operating system's connection list as plain rows - exactly what the CyberGuard Agent sends from an
    employee PC, so a PC's own check and the agent's reports are judged by the same code (judge_connections)."""
    conns = psutil.net_connections(kind="inet")
    cache: dict = {}
    rows = []
    for c in conns:
        proto = "TCP" if c.type == 1 else "UDP"
        lip, lport = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
        rip, rport = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
        proc = _proc_info(psutil, c.pid, cache)
        status = c.status if proto == "TCP" else ("LISTEN" if not rip else "UDP")
        rows.append({"protocol": proto, "localAddress": lip, "localPort": lport, "remoteAddress": rip,
                     "remotePort": rport, "status": status, "program": proc["name"], "pid": proc["pid"],
                     "path": proc["path"]})
    return rows


def snapshot(flagged_ips: set[str] | None = None) -> dict:
    """One fresh, read-only look at this computer's open ports and connections."""
    psutil = _psutil()
    if psutil is None:
        return {"available": False, "reason": install_hint()}
    try:
        rows = raw_connections(psutil)
    except psutil.AccessDenied:
        return {"available": False, "reason": "This system only lists network connections to an administrator "
                                              "(macOS needs the backend started with sudo)."}
    return judge_connections(rows, flagged_ips)


def judge_connections(rows: list[dict], flagged_ips: set[str] | None = None) -> dict:
    """The network rules applied to a connection list (from this computer, or reported by an agent)."""
    flagged_ips = flagged_ips or set()
    listening, active, findings = [], [], []
    status_count = Counter()
    seen_listen = set()
    t0 = time.time()
    for r in rows:
        proto = r["protocol"]
        lip, lport = r["localAddress"], r["localPort"]
        rip, rport = r["remoteAddress"], r["remotePort"]
        proc = {"name": r["program"], "pid": r["pid"], "path": r["path"]}
        status = r["status"]
        status_count[status] += 1
        risky_dir = bool(proc["path"] and _RISKY_DIRS.search(proc["path"]))
        if status == "LISTEN" or (proto == "UDP" and not rip):
            key = (proto, lip, lport)
            if key in seen_listen:
                continue
            seen_listen.add(key)
            scope = _scope(lip)
            row = {"protocol": proto, "address": lip, "port": lport, "scope": scope, "program": proc["name"],
                   "pid": proc["pid"], "service": EXPOSED.get(lport, ("", "", ""))[0]}
            listening.append(row)
            if proto == "TCP" and scope != "this computer only" and lport in EXPOSED:
                service, sev, why = EXPOSED[lport]
                if lport in _WINDOWS_BUILTIN and proc["name"].lower() in ("system", "svchost.exe", "unknown"):
                    sev, why = "low", ("built into Windows and open on every Windows PC; Windows Firewall normally "
                                       "closes it on public networks - keep the firewall on")
                findings.append(_flag(sev, f"{service} is open to {scope} (port {lport})",
                                      f"{proc['name']} is waiting for connections from {scope}: {why}.",
                                      port=lport, program=proc["name"], pid=proc["pid"]))
            if lport in BACKDOOR_PORTS:
                findings.append(_flag("high", f"A program is listening on backdoor port {lport}",
                                      f"{proc['name']} accepts connections on port {lport}, a port used by backdoors "
                                      "and attack tools (e.g. 4444 = Metasploit). Check what this program is.",
                                      port=lport, program=proc["name"], pid=proc["pid"]))
            if risky_dir and scope != "this computer only":
                findings.append(_flag("high", "A program from a temporary / download folder is open to the network",
                                      f"{proc['name']} runs from {_short(proc['path'])} and waits for connections on "
                                      f"port {lport}. Malware usually starts from these folders.",
                                      port=lport, program=proc["name"], pid=proc["pid"]))
            continue
        if not rip:
            continue
        row = {"protocol": proto, "local": f"{lip}:{lport}", "remote": rip, "remotePort": rport, "status": status,
               "program": proc["name"], "pid": proc["pid"], "outside": not _is_local(rip)}
        active.append(row)
        if rport in BACKDOOR_PORTS or (lport in BACKDOOR_PORTS and status == "ESTABLISHED"):
            port = rport if rport in BACKDOOR_PORTS else lport
            findings.append(_flag("high", f"Connection on backdoor port {port}",
                                  f"{proc['name']} has a {status.lower().replace('_', ' ')} connection with "
                                  f"{rip}:{rport} on port {port}, a port used by backdoors and attack tools (e.g. 4444 = "
                                  "Metasploit's default). Malware often calls its controller this way.",
                                  port=port, remote=rip, program=proc["name"], pid=proc["pid"]))
        if rip in flagged_ips:
            findings.append(_flag("high", f"Connected to an address your scans flagged ({rip})",
                                  f"{proc['name']} is talking to {rip}:{rport}, which an earlier CyberGuard scan marked as "
                                  "dangerous (see Threat indicators).", remote=rip, program=proc["name"], pid=proc["pid"]))
        if risky_dir and not _is_local(rip):
            findings.append(_flag("medium", "A program from a temporary / download folder is using the internet",
                                  f"{proc['name']} runs from {_short(proc['path'])} and is connected to {rip}:{rport}. "
                                  "Make sure you know this program.", remote=rip, program=proc["name"], pid=proc["pid"]))
    findings = _dedup(findings)
    for f in findings:
        f["fix"] = advice(f)                       # (7 Nov) how to fix it, shown on the PC Network page
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["title"]))
    listening.sort(key=lambda r: (r["scope"] == "this computer only", r["port"]))
    active.sort(key=lambda r: (not r["outside"], r["program"].lower(), r["remote"]))
    remote = Counter(r["remote"] for r in active if r["outside"])
    progs = Counter(r["program"] for r in active)
    return {
        "available": True, "takenAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seconds": round(time.time() - t0, 2),
        "summary": {"openPorts": len(listening),
                    "openToNetwork": sum(1 for r in listening if r["scope"] != "this computer only"),
                    "connections": len(active), "toInternet": sum(1 for r in active if r["outside"]),
                    "programs": len(progs), "byStatus": dict(status_count.most_common()),
                    "high": sum(1 for f in findings if f["severity"] == "high"),
                    "medium": sum(1 for f in findings if f["severity"] == "medium")},
        "findings": findings, "listening": listening[:MAX_CONNECTIONS], "connections": active[:MAX_CONNECTIONS],
        "truncated": len(active) > MAX_CONNECTIONS,
        "topRemote": [{"address": a, "connections": n} for a, n in remote.most_common(8)],
        "topPrograms": [{"program": p, "connections": n} for p, n in progs.most_common(8)],
        "note": "Read-only view: nothing was closed, blocked or changed, and nothing was saved.",
    }


def _is_local(ip: str) -> bool:
    """Inside this computer / home / office network. The network check's definition: Python's is_private would also
    count documentation ranges (203.0.113.x ...) as local."""
    return is_internal(ip.split("%")[0])


def _short(path: str) -> str:
    """The folder a program runs from, without the user name (C:\\Users\\<you>\\Downloads\\x.exe)."""
    return re.sub(r"(?i)([\\/]users[\\/])[^\\/]+", r"\1<you>", path)[-160:]


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        k = (f["title"], f.get("pid"), f.get("remote"))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
