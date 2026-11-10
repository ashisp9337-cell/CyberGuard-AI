"""
(10 Nov) PC Network actions - the administrator can, on the computer the backend runs on:

  * BLOCK A PORT     Windows Firewall rule: other computers can no longer connect to that port (inbound).
                     The program keeps running and this computer itself can still use it. Undo: "Unblock".
  * BLOCK AN ADDRESS Windows Firewall rules (in + out): no program on this PC can talk to that address any more.
                     Undo: "Unblock".
  * CLOSE A CONNECTION  ends one live TCP connection (IPv4) right now, like Sysinternals TCPView does. The program may
                     simply connect again - block the address too if it must stop.
  * END A PROGRAM    ends the process (asks it to close, forces it after 3 seconds). Cannot be undone, so Windows'
                     own core processes, the database and CyberGuard itself are refused.

Safety:
  * administrator account only, every action is written to the activity log (who, what, when);
  * never in production (a cloud server must not be changed from a web page) and switchable off with
    PC_ACTIONS_ENABLED=false;
  * only fixed commands with checked values (a real IP address, a port 1-65535, a process id whose name must still
    match) - no shell, nothing the user types is ever run as a command;
  * firewall rules are named "CyberGuard block ..." and listed on the page, so each one can be removed again.
Windows Firewall and closing other programs' connections need the backend to run "as administrator"; the page says so
when it does not.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from app.core.config import get_settings

RULE_PREFIX = "CyberGuard block"
STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                          "pc_blocks.json")              # backend/pc_blocks.json (gitignored)
_LOCK = threading.Lock()

# Programs that must never be ended from a web page: Windows itself, security software, the database and CyberGuard.
PROTECTED = {"system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
             "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "explorer.exe",
             "sihost.exe", "spoolsv.exe", "memory compression", "secure system", "msmpeng.exe", "nissrv.exe",
             "securityhealthservice.exe", "mpdefendercoreservice.exe", "smartscreen.exe", "taskmgr.exe",
             "postgres.exe", "postgres", "pg_ctl.exe", "systemd", "init", "launchd", "kernel_task", "sshd", "dockerd"}


class ActionError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


# --------------------------------------------------------------------------------------------------------------------
def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    try:
        if is_windows():
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def capabilities() -> dict:
    """What this backend may do, shown on the page (buttons are disabled with this reason when not allowed)."""
    settings = get_settings()
    if settings.is_production:
        return {"enabled": False, "reason": "Actions are switched off on a production server: they would change the "
                                            "server, not your PC."}
    if not settings.PC_ACTIONS_ENABLED:
        return {"enabled": False, "reason": "Actions are switched off (PC_ACTIONS_ENABLED=false in backend/.env)."}
    admin = is_admin()
    win = is_windows()
    out = {"enabled": True, "admin": admin, "windows": win,
           "firewall": win and admin, "closeConnection": win and admin, "endProcess": True, "reason": ""}
    if not win:
        out["reason"] = "Blocking and closing connections use Windows Firewall / Windows networking: Windows only."
    elif not admin:
        out["reason"] = ("To block ports / addresses or close connections, start the backend 'as administrator' "
                         "(right-click the terminal > Run as administrator). Ending your own programs works now.")
    return out


def _require(cap: str) -> None:
    c = capabilities()
    if not c["enabled"]:
        raise ActionError(c["reason"], 403)
    if not c.get(cap):
        raise ActionError(c["reason"] or "Not available on this computer.", 409)


# --------------------------------------------------------------------------------------------------------------------
def _ip(value: str) -> str:
    try:
        a = ipaddress.ip_address(str(value).strip().split("%")[0])
    except ValueError:
        raise ActionError("That is not an IP address.")
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        raise ActionError("This computer's own / special addresses cannot be blocked.")
    return str(a)


def _port(value) -> int:
    try:
        p = int(value)
    except (TypeError, ValueError):
        raise ActionError("Port must be a number.")
    if not 1 <= p <= 65535:
        raise ActionError("Port must be between 1 and 65535.")
    return p


def _netsh(args: list[str]) -> subprocess.CompletedProcess:
    kw = {"creationflags": 0x08000000} if is_windows() else {}         # CREATE_NO_WINDOW: no console flashes
    return subprocess.run(["netsh", "advfirewall", "firewall", *args], capture_output=True, text=True, timeout=20,
                          shell=False, **kw)


def _load() -> list[dict]:
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return [b for b in data if isinstance(b, dict) and str(b.get("name", "")).startswith(RULE_PREFIX)]
    except (OSError, ValueError):
        return []


def _save(blocks: list[dict]) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(blocks, f, indent=1)
    os.replace(tmp, STATE_FILE)


def list_blocks() -> list[dict]:
    return _load()


def _add_rules(name: str, rules: list[list[str]], record: dict) -> dict:
    with _LOCK:
        blocks = _load()
        if any(b["name"] == name for b in blocks):
            return {"ok": True, "message": f"Already blocked ({name}).", "rule": name}
        done = []
        for r in rules:
            res = _netsh(["add", "rule", f"name={name}", *r])
            if res.returncode != 0:
                for _ in done:                                   # undo half-made rules
                    _netsh(["delete", "rule", f"name={name}"])
                raise ActionError("Windows Firewall refused the rule: " + (res.stdout or res.stderr).strip()[:200], 502)
            done.append(r)
        blocks.append(record | {"name": name, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        _save(blocks)
    return {"ok": True, "message": f"Blocked with Windows Firewall ({name}). Press Unblock to undo.", "rule": name}


def block_port(port, protocol: str = "TCP") -> dict:
    """Inbound block: other computers can no longer connect to this port."""
    _require("firewall")
    port = _port(port)
    proto = str(protocol).upper()
    if proto not in ("TCP", "UDP"):
        raise ActionError("Protocol must be TCP or UDP.")
    name = f"{RULE_PREFIX} port {proto} {port}"
    return _add_rules(name, [["dir=in", "action=block", f"protocol={proto}", f"localport={port}"]],
                      {"kind": "port", "port": port, "protocol": proto})


def block_address(ip: str) -> dict:
    """Inbound + outbound block of one remote address."""
    _require("firewall")
    ip = _ip(ip)
    name = f"{RULE_PREFIX} address {ip}"
    return _add_rules(name, [["dir=out", "action=block", f"remoteip={ip}"],
                             ["dir=in", "action=block", f"remoteip={ip}"]], {"kind": "address", "address": ip})


def unblock(name: str) -> dict:
    _require("firewall")
    with _LOCK:
        blocks = _load()
        match = [b for b in blocks if b["name"] == name]
        if not match:                    # only rules CyberGuard made itself can be removed from the page
            raise ActionError("No CyberGuard rule with that name.", 404)
        res = _netsh(["delete", "rule", f"name={name}"])
        out = (res.stdout or res.stderr or "").strip()
        if res.returncode != 0 and "no rules match" not in out.lower():
            raise ActionError("Windows Firewall could not remove the rule: " + out[:200], 502)
        _save([b for b in blocks if b["name"] != name])
    return {"ok": True, "message": f"Unblocked ({name})."}


# --------------------------------------------------------------------------------------------------------------------
def close_connection(local_ip: str, local_port, remote_ip: str, remote_port) -> dict:
    """End one IPv4 TCP connection now (Windows SetTcpEntry with DELETE_TCB, as TCPView does)."""
    _require("closeConnection")
    lport, rport = _port(local_port), _port(remote_port)
    try:
        lip = ipaddress.IPv4Address(str(local_ip))
        rip = ipaddress.IPv4Address(str(remote_ip))
    except ValueError:
        raise ActionError("Windows can only close IPv4 connections this way - use 'Block address' for IPv6.")
    import ctypes
    from ctypes import wintypes

    class MIB_TCPROW(ctypes.Structure):
        _fields_ = [("dwState", wintypes.DWORD), ("dwLocalAddr", wintypes.DWORD), ("dwLocalPort", wintypes.DWORD),
                    ("dwRemoteAddr", wintypes.DWORD), ("dwRemotePort", wintypes.DWORD)]

    row = MIB_TCPROW(12,                                              # MIB_TCP_STATE_DELETE_TCB
                     struct.unpack("<I", lip.packed)[0], socket.htons(lport),
                     struct.unpack("<I", rip.packed)[0], socket.htons(rport))
    rc = ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row))
    if rc != 0:
        why = {5: "access denied - start the backend as administrator", 317: "access denied or the connection is gone",
               87: "the connection is no longer there"}.get(rc, f"Windows error {rc}")
        raise ActionError(f"Could not close the connection ({why}).", 409)
    return {"ok": True, "message": f"Closed the connection {lip}:{lport} -> {rip}:{rport}. The program may connect "
                                   "again - block the address if it must stop."}


def _family() -> set[int]:
    """CyberGuard's own process, the reloader that started it and its helpers."""
    me = os.getpid()
    fam = {me}
    try:
        import psutil
        fam |= {a.pid for a in psutil.Process(me).parents()} | {c.pid for c in psutil.Process(me).children(True)}
    except Exception:
        pass
    return fam


def can_end(pid, name: str, family: set[int] | None = None) -> bool:
    """Whether the page offers "End program" for this process (end_process checks the same again)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    fam = _family() if family is None else family
    return pid > 4 and pid not in fam and bool(name) and name.lower() not in PROTECTED and name != "unknown"


def mark_endable(snapshot: dict) -> None:
    """(10 Nov) canEnd on every row of a snapshot, so protected programs never show the button."""
    fam = _family()
    for key in ("listening", "connections", "portStatus", "findings"):
        for r in snapshot.get(key) or []:
            r["canEnd"] = can_end(r.get("pid"), r.get("program") or "", fam)


def end_process(pid, expected_name: str) -> dict:
    """End one program. The name must still match (process ids are reused), and protected programs are refused."""
    _require("endProcess")
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        raise ActionError("Process id must be a number.")
    import psutil
    try:
        p = psutil.Process(pid)
        name = p.name()
    except psutil.NoSuchProcess:
        raise ActionError("That program is not running any more.", 404)
    except psutil.AccessDenied:
        raise ActionError("Windows does not allow reading that program - start the backend as administrator.", 409)
    if not expected_name or name.lower() != str(expected_name).lower():
        raise ActionError(f"Process {pid} is now '{name}', not '{expected_name}' - refresh the page and try again.", 409)
    if pid <= 4 or pid in _family():
        raise ActionError("CyberGuard will not end itself or the system.", 403)
    if name.lower() in PROTECTED:
        raise ActionError(f"{name} is part of Windows, your security software or CyberGuard's database: ending it "
                          "could crash the computer or CyberGuard, so it is refused.", 403)
    try:
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)
    except psutil.NoSuchProcess:
        pass
    except psutil.AccessDenied:
        raise ActionError(f"Windows refused to end {name} - start the backend as administrator.", 409)
    except psutil.TimeoutExpired:
        raise ActionError(f"{name} did not stop.", 409)
    return {"ok": True, "message": f"Ended {name} (process {pid})."}


# --------------------------------------------------------------------------------------------------------------------
# (10 Nov) CUT OFF one program from one server: what "End program" cannot do for browsers. Brave / Chrome / Edge run
# every tab's internet traffic through one "network service" helper; ending it only makes the browser start a new one
# and the tab reconnects. Cutting off = (1) a Windows Firewall rule that blocks THIS program (its .exe, so every one of
# its processes) from THAT address, in and out, and (2) dropping the live connection now, so it has to reconnect - and
# the reconnect is blocked. Other programs can still reach the address; other servers stay reachable for this program.
# Big services spread over many addresses (WhatsApp, YouTube): the tab may come back through another one - then cut
# that one off too (it shows up in the list).
def _program_path(pid: int, expected_name: str) -> tuple[str, "object"]:
    import psutil
    try:
        p = psutil.Process(int(pid))
        name, exe = p.name(), p.exe()
    except psutil.NoSuchProcess:
        raise ActionError("That program is not running any more - refresh the page.", 404)
    except psutil.AccessDenied:
        raise ActionError("Windows does not allow reading that program - start the backend as administrator.", 409)
    if not expected_name or name.lower() != str(expected_name).lower():
        raise ActionError(f"Process {pid} is now '{name}', not '{expected_name}' - refresh the page and try again.", 409)
    if not exe or not os.path.isabs(exe) or any(ch in exe for ch in '"\r\n') or not os.path.isfile(exe):
        raise ActionError("The program's file could not be found, so a rule for it cannot be made.", 409)
    if name.lower() in PROTECTED or int(pid) <= 4:
        raise ActionError(f"{name} is part of Windows or CyberGuard and is not cut off from here - use Block address "
                          "if this address must be blocked for every program.", 403)
    return exe, p


def _is_browser_network_helper(proc) -> bool:
    """Chromium's network-service helper (Brave / Chrome / Edge / Opera / Vivaldi / Electron apps): ending it is safe -
    the browser starts a new one at once and every tab stays open."""
    try:
        cmd = " ".join(proc.cmdline())
    except Exception:
        return False
    return "--type=utility" in cmd and "network.mojom.NetworkService" in cmd


def cut_off(pid, expected_name: str, remote_ip: str, local_ip: str = "", local_port=0, remote_port=0) -> dict:
    _require("firewall")
    ip = _ip(remote_ip)
    exe, proc = _program_path(pid, expected_name)
    prog = os.path.basename(exe)
    name = f"{RULE_PREFIX} {prog} to {ip}"
    res = _add_rules(name, [["dir=out", "action=block", f"program={exe}", f"remoteip={ip}"],
                            ["dir=in", "action=block", f"program={exe}", f"remoteip={ip}"]],
                     {"kind": "program", "program": prog, "path": exe, "address": ip})
    # drop what is connected right now (a firewall rule only stops NEW connections)
    dropped = ""
    try:
        ipaddress.IPv4Address(ip)
        if local_ip and local_port and remote_port:
            close_connection(local_ip, local_port, ip, remote_port)
            dropped = " The live connection was closed; it cannot come back."
    except (ValueError, ActionError):
        pass
    if not dropped and _is_browser_network_helper(proc):
        try:
            proc.terminate()                      # the browser restarts its network helper; the tab stays open
            proc.wait(timeout=3)
            dropped = (" The browser's network helper was restarted (the tab stays open), so the connection was "
                       "dropped and cannot come back.")
        except Exception:
            pass
    if not dropped:
        dropped = (" New connections are blocked now; the one already open ends when the program reconnects "
                   "(Windows cannot close an IPv6 connection directly - closing the tab or app ends it at once).")
    return res | {"message": f"Cut off {prog} from {ip}.{dropped} Press Unblock to undo."}
