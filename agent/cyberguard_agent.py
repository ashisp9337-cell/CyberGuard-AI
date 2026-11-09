"""
CyberGuard Agent (10 Nov 2026) - runs on an employee PC and reports security facts to the company's CyberGuard server.

What it READS (read-only, nothing is ever blocked, closed, deleted or changed on this PC):
  * network  - open ports and live connections (program names, addresses, ports)            every 60 s, any system
  * logons   - failed / successful Windows sign-ins of the last hour (Security event log)     every 5 min, Windows,
               needs "Run as administrator" (without it this part is skipped, the rest works)
  * dns      - the website NAMES programs on this PC looked up (Windows DNS cache); only names not sent in the last
               7 days are sent; the server judges them and keeps only dangerous ones           every 60 s, Windows
  * downloads- NEW files in the Downloads folder: risky kinds only (programs, scripts, archives, disk images, macro
               documents, web pages, shortcuts - or any file that is really a program) up to the server's size
               limit are sent to be checked; your documents, photos and videos are NEVER sent  every 30 s, any system
It never reads your screen, keystrokes, messages, passwords or the contents of your other files.

Use (Python 3.9+, the only extra package is psutil:  python -m pip install psutil):
    python cyberguard_agent.py --setup        once: enter the server address and the device key (Devices page)
    python cyberguard_agent.py                run (keep the window open; Ctrl+C stops it)
    python cyberguard_agent.py --once         one round of every part, then stop (a quick test)
    python cyberguard_agent.py --dry-run      show what WOULD be sent, send nothing
The key is kept in agent_config.json next to this file - it only lets this PC send reports, nothing else.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.0"
HERE = Path(__file__).resolve().parent
CONFIG = HERE / "agent_config.json"
STATE = HERE / "agent_state.json"
IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
DNS_RESEND_DAYS = 7
PARTIAL = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload")
RISKY = {".exe", ".dll", ".scr", ".sys", ".cpl", ".msi", ".msix", ".appx", ".com", ".pif", ".bat", ".cmd", ".ps1",
         ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct", ".lnk", ".url", ".reg", ".jar", ".apk",
         ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".one", ".chm", ".xll",
         ".xlam", ".docm", ".xlsm", ".pptm", ".dotm", ".ppsm", ".doc", ".xls", ".ppt", ".rtf", ".html", ".htm", ".svg",
         ".mht", ".iqy", ".slk"}
LOCAL_ENDINGS = (".local", ".lan", ".home", ".internal", ".arpa", ".localdomain", ".corp", ".intranet", ".test",
                 ".invalid", ".example", ".localhost", ".home.arpa")
DNS_PS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
          "Get-DnsClientCache | Select-Object -Property Entry,Type,Status | ConvertTo-Json -Compress"]
LOGON_QUERY = "*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"


def say(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---- settings and memory -------------------------------------------------------------------------------------------
def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path: Path, data) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def check_server_url(url: str) -> str:
    """https only - plain http is allowed for this computer itself (testing), never across a network."""
    url = (url or "").strip().rstrip("/")
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    if url.startswith("https://") or (url.startswith("http://") and host in ("localhost", "127.0.0.1", "::1")):
        return url
    raise ValueError("The server address must start with https:// (http:// only for localhost).")


def setup() -> None:
    print("CyberGuard Agent setup. Get a device key on your company's CyberGuard: Devices > Add this PC.")
    server = check_server_url(input("Server address (e.g. https://cyberguard-company.centralindia.cloudapp.azure.com): "))
    key = input("Device key (starts with cga_): ").strip()
    if not key.startswith("cga_"):
        raise SystemExit("That is not a CyberGuard device key (it starts with cga_).")
    save_json(CONFIG, {"server": server, "key": key})
    print(f"Saved to {CONFIG}. Start the agent with:  python {Path(__file__).name}")


# ---- talking to the server ------------------------------------------------------------------------------------------
class Server:
    def __init__(self, url: str, key: str, timeout: int = 60):
        self.url, self.key, self.timeout = check_server_url(url), key, timeout
        self.ctx = ssl.create_default_context()        # certificates are always checked

    def _send(self, path: str, body: bytes, content_type: str) -> dict:
        req = urllib.request.Request(self.url + path, data=body, method="POST", headers={
            "Content-Type": content_type, "X-CyberGuard-Agent": self.key, "User-Agent": f"CyberGuard-Agent/{VERSION}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return json.loads(r.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode("utf-8")).get("error", {}).get("message", "")
            except ValueError:
                msg = ""
            raise RuntimeError(f"server said {e.code}: {msg or e.reason}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RuntimeError(f"cannot reach the server ({getattr(e, 'reason', e)})") from None

    def post_json(self, path: str, data: dict) -> dict:
        return self._send(path, json.dumps(data).encode("utf-8"), "application/json")

    def post_file(self, path: str, name: str, data: bytes) -> dict:
        boundary = "----cyberguard" + uuid.uuid4().hex
        safe = name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode()
        return self._send(path, body, f"multipart/form-data; boundary={boundary}")


# ---- collectors (read-only) -----------------------------------------------------------------------------------------
def collect_network() -> list[dict]:
    """Same list as CyberGuard's own PC Network check (backend/app/services/pc_network.py raw_connections)."""
    import psutil
    rows, cache = [], {}
    for c in psutil.net_connections(kind="inet"):
        proto = "TCP" if c.type == 1 else "UDP"
        lip, lport = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
        rip, rport = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
        pid = c.pid
        if pid not in cache:
            info = {"name": "unknown", "path": ""}
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
        status = c.status if proto == "TCP" else ("LISTEN" if not rip else "UDP")
        rows.append({"protocol": proto, "localAddress": lip[:64], "localPort": lport, "remoteAddress": rip[:64],
                     "remotePort": rport, "status": (status or "")[:20], "program": cache[pid]["name"][:260] or "unknown",
                     "pid": pid if (pid or 0) >= 0 else None, "path": cache[pid]["path"][:520]})
    return rows[:5000]


def read_logons_xml() -> str:
    p = subprocess.run(["wevtutil", "qe", "Security", f"/q:{LOGON_QUERY}", "/f:xml", "/c:500"], capture_output=True,
                       text=True, timeout=30, creationflags=NO_WINDOW)
    if p.returncode != 0:
        err = (p.stderr or p.stdout).strip()
        if "access is denied" in err.lower() or p.returncode == 5:
            raise PermissionError("reading Windows sign-ins needs this window opened with 'Run as administrator'")
        raise RuntimeError(f"wevtutil failed: {err[:200]}")
    return p.stdout


def read_dns_names() -> list[str]:
    p = subprocess.run(DNS_PS, capture_output=True, text=True, timeout=25, creationflags=NO_WINDOW)
    if p.returncode != 0:
        raise RuntimeError(f"PowerShell could not read the DNS cache: {(p.stderr or '').strip()[:200]}")
    return parse_dns_json(p.stdout)


def parse_dns_json(text: str) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    rows = data if isinstance(data, list) else [data]
    names = [str((r or {}).get("Entry") or "").strip().rstrip(".").lower() for r in rows]
    return [n for n in dict.fromkeys(names) if worth_sending(n)]


def worth_sending(name: str) -> bool:
    """Real internet names only (same rule as the server): no local names, IP addresses or reverse lookups."""
    if not name or "." not in name or len(name) > 253 or name.endswith(LOCAL_ENDINGS):
        return False
    if name.replace(".", "").isdigit() or ":" in name:
        return False
    return all(ch.isalnum() or ch in "-._" for ch in name)


def is_risky_file(path: Path) -> bool:
    if path.suffix.lower() in RISKY:
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head[:2] == b"MZ" or head == b"\x7fELF"         # a program, whatever its name says (photo.jpg.exe ...)


def downloads_folder(cfg: dict) -> Path:
    d = (cfg.get("downloadsDir") or "").strip()
    return Path(os.path.expandvars(os.path.expanduser(d))) if d else Path.home() / "Downloads"


# ---- the agent -----------------------------------------------------------------------------------------------------
class Agent:
    def __init__(self, server, cfg: dict, state: dict, dry_run: bool = False):
        self.server, self.cfg, self.state, self.dry = server, cfg, state, dry_run
        self.intervals = {"network": 60, "dns": 60, "logons": 300, "downloads": 30, "hello": 300}
        self.max_file = 15 * 1024 * 1024
        self.next_run: dict[str, float] = {}
        self.disabled: dict[str, str] = {}

    def send(self, kind: str, path: str, data=None, file=None) -> dict:
        if self.dry:
            what = f"file {file[0]} ({len(file[1]):,} bytes)" if file else json.dumps(data)[:300]
            say(f"[dry run] would send {kind}: {what}")
            return {"ok": True, "findings": 0}
        return self.server.post_file(path, *file) if file else self.server.post_json(path, data)

    def hello(self) -> dict:
        parts = ["network", "downloads"] + (["logons", "dns"] if IS_WINDOWS else [])
        r = self.send("hello", "/api/agent/hello", {"hostname": socket.gethostname()[:100],
                                                    "os": f"{platform.system()} {platform.release()}"[:150],
                                                    "agentVersion": VERSION, "collectors": parts})
        if r.get("intervals"):
            self.intervals.update({k: max(15, int(v)) for k, v in r["intervals"].items() if k in self.intervals})
        if r.get("maxFileMb"):
            self.max_file = int(r["maxFileMb"]) * 1024 * 1024
        return r

    def network(self) -> str:
        rows = collect_network()
        r = self.send("network", "/api/agent/network", {"rows": rows})
        return f"{len(rows)} connection(s) sent, {r.get('findings', 0)} new finding(s)"

    def logons(self) -> str:
        xml = read_logons_xml()
        r = self.send("logons", "/api/agent/logons", {"xml": xml})
        return f"{r.get('checked', 0)} new sign-in event(s), {r.get('findings', 0)} finding(s)"

    def dns(self) -> str:
        now = datetime.now(timezone.utc)
        sent = self.state.setdefault("dnsSent", {})
        fresh = [n for n in read_dns_names()
                 if not (sent.get(n) and now - datetime.fromisoformat(sent[n]) < timedelta(days=DNS_RESEND_DAYS))][:1000]
        if not fresh:
            return "no new website names"
        r = self.send("dns", "/api/agent/dns", {"names": fresh})
        for n in fresh:
            sent[n] = now.isoformat()
        cutoff = now - timedelta(days=DNS_RESEND_DAYS)
        self.state["dnsSent"] = {k: v for k, v in sent.items() if datetime.fromisoformat(v) >= cutoff}
        return f"{len(fresh)} new website name(s) sent, {r.get('findings', 0)} dangerous"

    def downloads(self) -> str:
        folder = downloads_folder(self.cfg)
        if not folder.is_dir():
            raise RuntimeError(f"Downloads folder not found: {folder}")
        seen = self.state.setdefault("downloadsSeen", {})
        pending = self.state.setdefault("downloadsPending", {})     # kept in the state file: works across restarts
        current = {}
        for e in os.scandir(folder):
            if e.is_file(follow_symlinks=False) and not e.name.lower().endswith(PARTIAL) and not e.name.startswith("~$"):
                st = e.stat(follow_symlinks=False)
                current[e.name] = [st.st_size, int(st.st_mtime)]
        if not self.state.get("downloadsReady"):            # first run: files already there are left alone
            self.state["downloadsReady"], self.state["downloadsSeen"] = True, current
            return f"watching {folder} ({len(current)} existing file(s) left alone)"
        sent = found = 0
        for name, sig in current.items():
            if seen.get(name) == sig:
                continue
            if pending.get(name) != sig[0]:                   # still downloading? wait one more round
                pending[name] = sig[0]
                continue
            pending.pop(name, None)
            seen[name] = sig
            path = folder / name
            if sig[0] > self.max_file or not is_risky_file(path):
                continue                                       # documents, photos, videos: never sent
            try:
                data = path.read_bytes()
            except OSError:
                continue
            r = self.send("downloads", "/api/agent/file", file=(name, data))
            sent += 1
            found += int(r.get("findings", 0))
        for gone in set(seen) - set(current):
            seen.pop(gone, None)
        for gone in set(pending) - set(current):
            pending.pop(gone, None)
        return f"{sent} risky new file(s) checked, {found} finding(s)" if sent else "no new risky downloads"

    def run_once(self, part: str) -> None:
        try:
            note = getattr(self, part)()
            say(f"{part:9s} {note}")
        except PermissionError as e:
            self.disabled[part] = str(e)
            say(f"{part:9s} skipped: {e}")
        except ModuleNotFoundError:
            self.disabled[part] = "psutil missing"
            say(f"{part:9s} skipped: install psutil first:  {Path(sys.executable).name} -m pip install psutil")
        except Exception as e:  # noqa: BLE001 - one part failing never stops the others
            say(f"{part:9s} problem: {e}")
        finally:
            save_json(STATE, self.state)

    def parts(self) -> list[str]:
        return ["network", "downloads"] + (["logons", "dns"] if IS_WINDOWS else [])

    def loop(self, once: bool = False) -> None:
        info = self.hello()
        if info.get("notice"):
            say(info["notice"])
        say(f"Reporting as '{info.get('name', '?')}' ({info.get('owner', '')}) to {self.server.url}. Ctrl+C stops.")
        if once:
            for p in self.parts():
                self.run_once(p)
            return
        self.next_run = {p: 0.0 for p in self.parts()}
        self.next_run["hello"] = time.time() + self.intervals["hello"]
        while True:
            now = time.time()
            for part, due in sorted(self.next_run.items(), key=lambda kv: kv[1]):
                if due > now or part in self.disabled:
                    continue
                if part == "hello":
                    try:
                        self.hello()
                    except Exception as e:  # noqa: BLE001
                        say(f"hello     problem: {e}")
                else:
                    self.run_once(part)
                self.next_run[part] = time.time() + self.intervals.get(part, 60)
            time.sleep(1)


def main() -> None:
    ap = argparse.ArgumentParser(description="CyberGuard Agent: reports this PC's security facts to the company server.")
    ap.add_argument("--setup", action="store_true", help="enter the server address and device key")
    ap.add_argument("--once", action="store_true", help="one round of every part, then stop")
    ap.add_argument("--dry-run", action="store_true", help="show what would be sent, send nothing")
    a = ap.parse_args()
    if a.setup:
        return setup()
    cfg = load_json(CONFIG, {})
    if not cfg.get("server") or not cfg.get("key"):
        raise SystemExit(f"Not set up yet. Run:  python {Path(__file__).name} --setup")
    agent = Agent(Server(cfg["server"], cfg["key"]), cfg, load_json(STATE, {}), dry_run=a.dry_run)
    try:
        agent.loop(once=a.once)
    except KeyboardInterrupt:
        say("Stopped.")
    except RuntimeError as e:
        raise SystemExit(f"CyberGuard Agent could not start: {e}")


if __name__ == "__main__":
    main()
