"""(6 Nov) Live PC network monitor: open ports + live connections, read-only. The rules are tested on a fake
connection list (same result on every computer), and one real snapshot of the machine running the tests."""
from collections import namedtuple

import pytest

psutil = pytest.importorskip("psutil")

from app.services import pc_network as PC  # noqa: E402

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "fd family type laddr raddr status pid")
TCP, UDP = 1, 2


def conn(lip, lport, rip=None, rport=None, status="ESTABLISHED", pid=100, kind=TCP):
    return Conn(-1, 2, kind, Addr(lip, lport), Addr(rip, rport) if rip else (), status, pid)


class FakeProc:
    PROCS = {4: ("System", ""), 100: ("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"),
             200: ("postgres.exe", r"C:\Program Files\PostgreSQL\16\bin\postgres.exe"),
             300: ("invoice.exe", r"C:\Users\student\Downloads\invoice.exe"),
             400: ("python.exe", r"C:\Users\student\Desktop\cyberguard\backend\venv\Scripts\python.exe")}

    def __init__(self, pid):
        if pid not in self.PROCS:
            raise psutil.NoSuchProcess(pid)
        self.pid = pid

    def name(self):
        return self.PROCS[self.pid][0]

    def exe(self):
        return self.PROCS[self.pid][1]


@pytest.fixture()
def fake(monkeypatch):
    def use(conns):
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
        monkeypatch.setattr(psutil, "Process", FakeProc)
    return use


def titles(s):
    return [(f["severity"], f["title"]) for f in s["findings"]]


def test_safe_setup_has_no_findings(fake):
    fake([conn("127.0.0.1", 5432, status="LISTEN", pid=200), conn("127.0.0.1", 8000, status="LISTEN", pid=400),
          conn("192.168.1.10", 51000, "142.250.183.14", 443, pid=100)])
    s = PC.snapshot()
    assert s["available"] and s["findings"] == []
    assert s["summary"]["openPorts"] == 2 and s["summary"]["openToNetwork"] == 0 and s["summary"]["toInternet"] == 1
    assert {r["scope"] for r in s["listening"]} == {"this computer only"}


def test_database_open_to_all_networks_is_high(fake):
    fake([conn("0.0.0.0", 5432, status="LISTEN", pid=200), conn("::", 8000, status="LISTEN", pid=400)])
    t = titles(PC.snapshot())
    assert ("high", "PostgreSQL database is open to all networks (port 5432)") in t
    assert any(sev == "medium" and "port 8000" in title for sev, title in t)


def test_windows_file_sharing_of_the_system_is_only_low(fake):
    fake([conn("0.0.0.0", 445, status="LISTEN", pid=4), conn("0.0.0.0", 135, status="LISTEN", pid=4)])
    assert {sev for sev, _ in titles(PC.snapshot())} == {"low"}


def test_backdoor_port_and_program_from_downloads(fake):
    fake([conn("192.168.1.10", 50123, "203.0.113.66", 4444, pid=300),
          conn("0.0.0.0", 31337, status="LISTEN", pid=300)])
    s = PC.snapshot()
    t = [title for _, title in titles(s)]
    assert "Connection on backdoor port 4444" in t and "A program is listening on backdoor port 31337" in t
    assert "A program from a temporary / download folder is open to the network" in t
    assert "A program from a temporary / download folder is using the internet" in t
    shown = " ".join(f["why"] for f in s["findings"])
    assert "student" not in shown and r"Users\<you>\Downloads" in shown          # the user name is never shown


def test_connection_to_an_address_flagged_by_an_earlier_scan(fake):
    fake([conn("192.168.1.10", 50200, "45.155.205.10", 443, pid=100)])
    assert ("high", "Connected to an address your scans flagged (45.155.205.10)") in titles(PC.snapshot({"45.155.205.10"}))


def test_refused_process_details_do_not_break_the_view(fake, monkeypatch):
    def denied(pid):
        raise psutil.AccessDenied(pid)
    fake([conn("0.0.0.0", 3389, status="LISTEN", pid=999)])
    monkeypatch.setattr(psutil, "Process", denied)
    s = PC.snapshot()
    assert s["listening"][0]["program"] == "unknown" and s["findings"][0]["severity"] == "high"


def test_when_listing_is_not_allowed_it_says_so(monkeypatch):
    def denied(kind="inet"):
        raise psutil.AccessDenied()
    monkeypatch.setattr(psutil, "net_connections", denied)
    s = PC.snapshot()
    assert s["available"] is False and "administrator" in s["reason"]


def test_real_snapshot_of_this_machine():
    try:
        s = PC.snapshot()
    except Exception as exc:          # noqa: BLE001
        pytest.fail(f"real snapshot raised {exc!r}")
    if s["available"]:
        assert s["summary"]["openPorts"] == len(s["listening"]) or s["truncated"]
        assert "nothing was closed" in s["note"]


# ---- API ---------------------------------------------------------------------------------------------------------
def test_api_is_for_the_administrator_only(client, auth_client, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", "someone-else@example.com")
    assert auth_client.get("/api/pc-network").status_code == 403
    auth_client.post("/api/auth/logout")
    assert client.get("/api/pc-network").status_code == 401


def test_api_snapshot_for_the_admin(admin_client, fake):
    fake([conn("0.0.0.0", 3389, status="LISTEN", pid=4)])
    r = admin_client.get("/api/pc-network")
    assert r.status_code == 200
    j = r.json()
    assert j["available"] and j["findings"][0]["title"].startswith("Remote Desktop (RDP) is open to all networks")
    assert j["findings"][0]["fix"][0].startswith("Remote Desktop: if you do not use it, switch it off")   # (7 Nov)


def test_setup_hint_names_the_python_that_runs_cyberguard(monkeypatch):
    """(7 Nov) a plain 'pip install' went into another Python on the PC: the hint must name CyberGuard's own Python,
    relative to the backend folder (no user name), and quote it when the path has spaces."""
    import os
    backend = os.path.dirname(os.path.dirname(os.path.abspath(PC.__file__)))
    backend = os.path.dirname(backend)
    monkeypatch.setattr(PC.sys, "executable", os.path.join(backend, "venv", "bin", "python"))
    assert PC.install_hint().endswith(f"run: {os.path.join('venv', 'bin', 'python')} -m pip install -r requirements.txt")
    monkeypatch.setattr(PC.sys, "executable", os.path.join(backend, "my venv", "python"))
    assert f'& "{os.path.join("my venv", "python")}" -m pip' in PC.install_hint()
    assert backend not in PC.install_hint()          # relative path only: the user / folder names stay hidden
