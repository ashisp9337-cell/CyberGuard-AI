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


# ---- (10 Nov) open / closed ports, who is on the other side, actions ----------------------------------------------
def test_port_status_lists_open_and_closed_ports(fake):
    fake([conn("0.0.0.0", 3389, status="LISTEN", pid=4), conn("127.0.0.1", 5432, status="LISTEN", pid=200),
          conn("192.168.1.10", 51000, "142.250.183.14", 443, pid=100)])
    s = PC.snapshot()
    st = {p["port"]: p for p in s["portStatus"]}
    assert st[3389]["state"] == "open" and st[3389]["scope"] == "all networks" and st[3389]["risk"] == "high"
    assert st[5432]["state"] == "open" and st[5432]["risk"] == "low"           # this computer only
    assert st[4444]["state"] == "closed" and st[22]["state"] == "closed"
    c = s["connections"][0]
    assert c["remoteService"] == "secure web (HTTPS)" and c["where"] == "the internet"
    assert c["localAddress"] == "192.168.1.10" and c["localPort"] == 51000
    assert "ESTABLISHED" in s["stateMeaning"] and "actions" in s and "blocked" in s


def test_owner_names_come_from_reverse_dns_suffixes():
    assert PC.owner_of("bom12s08-in-f14.1e100.net") == "Google"
    assert PC.owner_of("ec2-3-1-2-3.ap-south-1.compute.amazonaws.com.") == "Amazon Web Services"
    assert PC.owner_of("evil1e100.net") == ""                                   # a suffix, not just text inside


@pytest.fixture()
def actions(monkeypatch, tmp_path):
    """Windows + administrator, with netsh and the state file faked (no firewall is touched)."""
    from app.services import pc_actions as A
    calls = []

    class Done:
        def __init__(self, rc=0, out="Ok."):
            self.returncode, self.stdout, self.stderr = rc, out, ""
    monkeypatch.setattr(A, "is_windows", lambda: True)
    monkeypatch.setattr(A, "is_admin", lambda: True)
    monkeypatch.setattr(A, "STATE_FILE", str(tmp_path / "pc_blocks.json"))
    monkeypatch.setattr(A, "_netsh", lambda args: calls.append(args) or Done())
    return A, calls


def test_block_and_unblock_a_port_and_an_address(actions):
    A, calls = actions
    assert A.block_port(4444)["ok"]
    assert calls[-1] == ["add", "rule", "name=CyberGuard block port TCP 4444", "dir=in", "action=block",
                         "protocol=TCP", "localport=4444"]
    assert A.block_address("45.9.20.1")["ok"]
    assert ["add", "rule", "name=CyberGuard block address 45.9.20.1", "dir=out", "action=block",
            "remoteip=45.9.20.1"] in calls
    assert {b["name"] for b in A.list_blocks()} == {"CyberGuard block port TCP 4444", "CyberGuard block address 45.9.20.1"}
    assert A.block_port(4444)["message"].startswith("Already blocked")
    assert A.unblock("CyberGuard block port TCP 4444")["ok"]
    assert [b["name"] for b in A.list_blocks()] == ["CyberGuard block address 45.9.20.1"]
    with pytest.raises(A.ActionError):
        A.unblock("Core Networking - DNS (UDP-Out)")          # only rules CyberGuard made itself


@pytest.mark.parametrize("bad", ["45.9.20.1; netsh advfirewall reset", "127.0.0.1", "0.0.0.0", "not-an-ip", "::1"])
def test_only_real_outside_addresses_can_be_blocked(actions, bad):
    A, calls = actions
    with pytest.raises(A.ActionError):
        A.block_address(bad)
    assert calls == []


def test_actions_are_off_in_production_and_without_admin(actions, monkeypatch):
    A, calls = actions
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "production")
    with pytest.raises(A.ActionError) as e:
        A.block_port(3389)
    assert e.value.status == 403 and not A.capabilities()["enabled"]
    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "development")
    monkeypatch.setattr(A, "is_admin", lambda: False)
    with pytest.raises(A.ActionError) as e:
        A.block_port(3389)
    assert "as administrator" in e.value.message and calls == []


def test_end_process_refuses_windows_core_cyberguard_and_a_changed_pid(actions, monkeypatch):
    A, _ = actions
    import os

    class P:
        def __init__(self, pid):
            if pid == 999:
                raise psutil.NoSuchProcess(pid)
            self.pid = pid
            self.ended = False

        def name(self):
            return {700: "lsass.exe", 701: "postgres.exe", 702: "nc.exe"}.get(self.pid, "python.exe")

        def parents(self):
            return []

        def children(self, recursive=False):
            return []

        def terminate(self):
            ended.append(self.pid)

        def wait(self, timeout=None):
            return 0
    ended = []
    monkeypatch.setattr(psutil, "Process", P)
    for pid, name in ((700, "lsass.exe"), (701, "postgres.exe"), (os.getpid(), "python.exe"), (4, "System")):
        with pytest.raises(A.ActionError):
            A.end_process(pid, name)
    with pytest.raises(A.ActionError) as e:
        A.end_process(702, "chrome.exe")                     # the id now belongs to another program
    assert "refresh" in e.value.message
    with pytest.raises(A.ActionError):
        A.end_process(999, "nc.exe")
    assert ended == []
    assert A.end_process(702, "nc.exe")["ok"] and ended == [702]


def test_close_connection_needs_ipv4(actions):
    A, _ = actions
    with pytest.raises(A.ActionError) as e:
        A.close_connection("fe80::1", 50000, "2404:6800::1", 443)
    assert "IPv4" in e.value.message


def test_action_api_is_admin_only_and_logged(admin_client, actions, monkeypatch):
    A, calls = actions
    r = admin_client.post("/api/pc-network/block-port", json={"port": 4444, "protocol": "TCP"})
    assert r.status_code == 200 and r.json()["ok"]
    r = admin_client.post("/api/pc-network/block-address", json={"address": "127.0.0.1"})
    assert r.status_code == 400 and "own / special" in r.json()["error"]["message"]
    r = admin_client.post("/api/pc-network/block-port", json={"port": 70000})
    assert r.status_code == 422
    log = admin_client.get("/api/audit").json()
    items = log.get("items", log) if isinstance(log, dict) else log
    acts = [i["action"] for i in items]
    assert "pc.block_port" in acts and "pc.block_address" in acts
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", "someone-else@example.com")


def test_end_button_is_not_offered_for_protected_programs(fake):
    import os
    FakeProc.PROCS[os.getpid()] = ("python.exe", "")
    try:
        fake([conn("0.0.0.0", 5432, status="LISTEN", pid=200), conn("0.0.0.0", 4444, status="LISTEN", pid=300),
              conn("127.0.0.1", 8000, status="LISTEN", pid=os.getpid()), conn("0.0.0.0", 445, status="LISTEN", pid=4)])
        s = PC.snapshot()
        can = {r["program"]: r["canEnd"] for r in s["listening"]}
        assert can == {"postgres.exe": False, "invoice.exe": True, "python.exe": False, "System": False}
    finally:
        FakeProc.PROCS.pop(os.getpid(), None)


# ---- (10 Nov) cut one program off from one server -------------------------------------------------------------------
def _fake_proc(monkeypatch, tmp_path, name="brave.exe", helper=True):
    exe = tmp_path / "Brave Software" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"MZ")
    ended = []

    class Proc:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return name

        def exe(self):
            return str(exe)

        def cmdline(self):
            return [str(exe), "--type=utility", "--utility-sub-type=network.mojom.NetworkService"] if helper else [str(exe)]

        def terminate(self):
            ended.append(self.pid)

        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(psutil, "Process", Proc)
    return str(exe), ended


def test_cut_off_blocks_that_program_from_that_address_and_restarts_the_browser_helper(actions, monkeypatch, tmp_path):
    A, calls = actions
    exe, ended = _fake_proc(monkeypatch, tmp_path)
    r = A.cut_off(27392, "brave.exe", "2a03:2880:f322:120:face:b00c:0:167")
    assert r["ok"] and "network helper was restarted" in r["message"] and ended == [27392]
    assert ["add", "rule", "name=CyberGuard block brave.exe to 2a03:2880:f322:120:face:b00c:0:167", "dir=out",
            "action=block", f"program={exe}", "remoteip=2a03:2880:f322:120:face:b00c:0:167"] in calls
    b = A.list_blocks()[0]
    assert b["kind"] == "program" and b["program"] == "brave.exe"
    assert A.unblock(b["name"])["ok"] and A.list_blocks() == []


def test_cut_off_never_ends_an_ordinary_program(actions, monkeypatch, tmp_path):
    A, _ = actions
    _, ended = _fake_proc(monkeypatch, tmp_path, name="Code.exe", helper=False)
    r = A.cut_off(31012, "Code.exe", "2a03:2880::1")
    assert ended == [] and "New connections are blocked" in r["message"]


@pytest.mark.parametrize("pid,name,ip", [(27392, "chrome.exe", "8.8.8.8"), (27392, "brave.exe", "127.0.0.1"),
                                         (27392, "brave.exe", "8.8.8.8; netsh advfirewall reset")])
def test_cut_off_refuses_a_changed_program_or_a_bad_address(actions, monkeypatch, tmp_path, pid, name, ip):
    A, calls = actions
    _fake_proc(monkeypatch, tmp_path)
    with pytest.raises(A.ActionError):
        A.cut_off(pid, name, ip)
    assert calls == []
