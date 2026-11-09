"""(10 Nov) The CyberGuard Agent program (agent/cyberguard_agent.py) against the real server API: what it collects,
what it sends (and never sends), and the real HTTP path (JSON + file upload) through a live uvicorn server.
Windows-only readers (DNS cache, sign-in events) are replaced by recorded output; the rest runs for real."""
import importlib.util
import socket
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from helpers import register_user

AGENT_FILE = Path(__file__).resolve().parents[2] / "agent" / "cyberguard_agent.py"
pytestmark = pytest.mark.skipif(not AGENT_FILE.exists(), reason="agent/cyberguard_agent.py not next to backend/")


def _load_agent(tmp_path):
    spec = importlib.util.spec_from_file_location("cyberguard_agent_under_test", AGENT_FILE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.STATE = tmp_path / "agent_state.json"            # never the real state / config next to the agent
    mod.CONFIG = tmp_path / "agent_config.json"
    return mod


class FakeServer:
    """Routes the agent's calls into the app in-process (the real HTTP path has its own test below)."""
    url = "http://testserver"

    def __init__(self, key):
        self.c = TestClient(app)
        self.c.headers["X-CyberGuard-Agent"] = key
        self.calls = []

    def post_json(self, path, data):
        self.calls.append(path)
        r = self.c.post(path, json=data)
        assert r.status_code == 200, r.text
        return r.json()

    def post_file(self, path, name, data):
        self.calls.append(f"{path}:{name}")
        r = self.c.post(path, files={"file": (name, data)})
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture()
def paired():
    c = TestClient(app)
    email = f"agentprog_{uuid.uuid4().hex[:8]}@example.com"
    assert register_user(c, {"name": "Emp", "email": email, "password": "TestPass123"}).status_code == 201
    d = c.post("/api/devices", json={"name": "Test PC"}).json()
    return c, d


def _scan_targets(c):
    data = c.get("/api/scans?pageSize=200").json()
    items = data.get("items", data) if isinstance(data, dict) else data
    return [s["target"] for s in items]


def test_server_address_must_be_https_except_this_computer(tmp_path):
    A = _load_agent(tmp_path)
    assert A.check_server_url("https://cg.example.org/") == "https://cg.example.org"
    assert A.check_server_url("http://localhost:8000") == "http://localhost:8000"
    for bad in ("http://cg.example.org", "ftp://x", "cg.example.org", "http://localhost.evil.org"):
        with pytest.raises(ValueError):
            A.check_server_url(bad)


def test_dns_names_are_filtered_like_the_server_and_sent_once(tmp_path, paired, monkeypatch):
    A = _load_agent(tmp_path)
    c, d = paired
    raw = ('[{"Entry":"www.google.com"},{"Entry":"faceb00k-login.com."},{"Entry":"printer.local"},'
           '{"Entry":"10.0.0.5"},{"Entry":"5.0.0.10.in-addr.arpa"},{"Entry":"WWW.GOOGLE.COM"}]')
    assert A.parse_dns_json(raw) == ["www.google.com", "faceb00k-login.com"]
    monkeypatch.setattr(A, "read_dns_names", lambda: A.parse_dns_json(raw))
    srv = FakeServer(d["key"])
    agent = A.Agent(srv, {}, {})
    assert "2 new website name(s) sent, 1 dangerous" == agent.dns()
    assert agent.dns() == "no new website names"                     # already sent this week: not again
    assert "faceb00k-login.com" in _scan_targets(c) and "www.google.com" not in _scan_targets(c)


def test_downloads_only_new_finished_risky_files_are_sent(tmp_path, paired, monkeypatch):
    A = _load_agent(tmp_path)
    c, d = paired
    folder = tmp_path / "Downloads"
    folder.mkdir()
    (folder / "old_setup.exe").write_bytes(b"MZ" + b"\x00" * 100)        # there before the agent: left alone
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "UPLOAD_DIR", str(tmp_path / "uploads"))
    srv = FakeServer(d["key"])
    agent = A.Agent(srv, {"downloadsDir": str(folder)}, {})
    assert "existing file(s) left alone" in agent.downloads()
    (folder / "Invoice_2026.pdf.exe").write_bytes(b"MZ" + b"\x00" * 300)
    (folder / "holiday.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 300)    # a photo: never sent
    (folder / "photo.jpg").write_bytes(b"MZ" + b"\x00" * 50)                 # a program in disguise: sent
    (folder / "big.crdownload").write_bytes(b"MZ")                           # still downloading: ignored
    assert agent.downloads() == "no new risky downloads"                     # first sight: wait one round
    out = agent.downloads()
    assert out.startswith("2 risky new file(s) checked")
    sent = [x for x in srv.calls if x.startswith("/api/agent/file")]
    assert sorted(sent) == ["/api/agent/file:Invoice_2026.pdf.exe", "/api/agent/file:photo.jpg"]
    assert any("Invoice_2026.pdf.exe" in t for t in _scan_targets(c))
    assert agent.downloads() == "no new risky downloads"
    # the agent is restarted between the two looks at a new file: the wait is remembered in its state file
    (folder / "update.msi").write_bytes(b"\xd0\xcf" + b"\x00" * 200)
    first = A.Agent(srv, {"downloadsDir": str(folder)}, agent.state)
    assert first.downloads() == "no new risky downloads"
    again = A.Agent(srv, {"downloadsDir": str(folder)}, first.state)
    assert again.downloads().startswith("1 risky new file(s) checked")


def _event(eid, rec, minute, user, ip, logon_type="3", sub="0xc000006a"):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="2026-10-12T02:{minute:02d}:00.000Z"/><EventRecordID>{rec}</EventRecordID>'
            f'</System><EventData><Data Name="TargetUserName">{user}</Data><Data Name="IpAddress">{ip}</Data>'
            f'<Data Name="LogonType">{logon_type}</Data><Data Name="SubStatus">{sub}</Data></EventData></Event>')


def test_windows_sign_ins_and_missing_admin_rights(tmp_path, paired, monkeypatch):
    A = _load_agent(tmp_path)
    c, d = paired
    xml = "".join(_event(4625, 100 + i, 10 + i, "riya", "45.155.205.10") for i in range(8))
    xml += _event(4624, 120, 20, "riya", "45.155.205.10", logon_type="10")
    monkeypatch.setattr(A, "read_logons_xml", lambda: xml)
    agent = A.Agent(FakeServer(d["key"]), {}, {})
    assert agent.logons() == "9 new sign-in event(s), 1 finding(s)"

    def denied():
        raise PermissionError("needs Run as administrator")
    monkeypatch.setattr(A, "read_logons_xml", denied)
    agent.run_once("logons")
    assert "logons" in agent.disabled                     # skipped from now on; the other parts keep working


def test_network_is_read_for_real_and_dry_run_sends_nothing(tmp_path, paired, capsys):
    pytest.importorskip("psutil")
    A = _load_agent(tmp_path)
    c, d = paired
    rows = A.collect_network()
    assert isinstance(rows, list) and all({"protocol", "localPort", "program", "path"} <= set(r) for r in rows)
    srv = FakeServer(d["key"])
    assert "connection(s) sent" in A.Agent(srv, {}, {}).network()
    dry = FakeServer(d["key"])
    A.Agent(dry, {}, {}, dry_run=True).network()
    assert dry.calls == [] and "[dry run] would send network" in capsys.readouterr().out


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_real_http_path_hello_json_and_file_upload(tmp_path, paired, monkeypatch):
    """The agent's own urllib client (JSON + hand-built multipart upload) against a live server on 127.0.0.1."""
    import uvicorn
    A = _load_agent(tmp_path)
    c, d = paired
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "UPLOAD_DIR", str(tmp_path / "uploads"))
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        srv = A.Server(f"http://127.0.0.1:{port}", d["key"], timeout=30)
        hello = A.Agent(srv, {}, {}).hello()
        assert hello["name"] == "Test PC" and "never" in hello["notice"]
        r = srv.post_file("/api/agent/file", 'Setup "free".exe', b"MZ" + b"\x00" * 200)
        assert r["ok"] and r["riskScore"] >= 26 and r["findings"] == 1      # a program: noted (not called dangerous)
        with pytest.raises(RuntimeError, match="401"):
            A.Server(f"http://127.0.0.1:{port}", "cga_wrong").post_json("/api/agent/hello", {})
    finally:
        server.should_exit = True
        t.join(timeout=10)
    assert any("Setup _free_.exe" in x for x in _scan_targets(c))
