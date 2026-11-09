"""(10 Nov) Company mode: the CyberGuard Agent API (device keys, reports judged by the same code as the laptop's
watchers) and the Devices page (administrators see every PC, employees their own)."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from helpers import register_user

PW = "TestPass123"


def _client(admin=False):
    c = TestClient(app)
    email = f"dev_{uuid.uuid4().hex[:8]}@example.com"
    assert register_user(c, {"name": "Admin" if admin else "Employee", "email": email, "password": PW}).status_code == 201
    from app.db.database import SessionLocal
    from app.db.models import User
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == email).first()
        if admin:
            u.role = "admin"
            db.commit()
        c._uid = u.id
    finally:
        db.close()
    return c


def _agent(key):
    a = TestClient(app)
    a.headers["X-CyberGuard-Agent"] = key
    return a


@pytest.fixture()
def people():
    return _client(admin=True), _client(), _client()


def _pair(c, name="Laptop", user_id=None):
    r = c.post("/api/devices", json={"name": name, **({"userId": user_id} if user_id else {})})
    assert r.status_code == 201, r.text
    return r.json()


def _scans(c):
    return c.get("/api/scans?pageSize=200").json()


def _items(c):
    data = _scans(c)
    return data.get("items", data) if isinstance(data, dict) else data


def test_pairing_and_who_sees_which_pc(people):
    admin, emp, other = people
    d = _pair(emp, "Riya's laptop")
    assert d["key"].startswith("cga_") and "only once" in d["note"]
    mine = emp.get("/api/devices").json()
    assert mine["admin"] is False and [x["name"] for x in mine["devices"]] == ["Riya's laptop"]
    assert mine["devices"][0]["paired"] is False and mine["devices"][0]["online"] is False
    assert other.get("/api/devices").json()["devices"] == []
    assert other.get(f"/api/devices/{d['id']}").status_code == 404
    assert any(x["id"] == d["id"] for x in admin.get("/api/devices").json()["devices"])
    assert emp.post("/api/devices", json={"name": "x", "userId": other._uid}).status_code == 403
    a2 = _pair(admin, "Reception PC", user_id=other._uid)
    assert [x["name"] for x in other.get("/api/devices").json()["devices"]] == ["Reception PC"]
    assert admin.get(f"/api/devices/{a2['id']}").json()["owner"]["id"] == other._uid


def test_agent_needs_a_valid_key_and_stops_when_removed_or_owner_disabled(people):
    admin, emp, _ = people
    assert TestClient(app).post("/api/agent/hello", json={}).status_code == 401
    assert _agent("cga_wrong").post("/api/agent/hello", json={}).status_code == 401
    d = _pair(emp)
    a = _agent(d["key"])
    r = a.post("/api/agent/hello", json={"hostname": "RIYA-PC", "os": "Windows 11", "agentVersion": "1.0",
                                         "collectors": ["network", "dns", "downloads", "logons", "keylogger"]})
    assert r.status_code == 200 and r.json()["intervals"]["network"] == 60 and "never" in r.json()["notice"]
    dev = emp.get(f"/api/devices/{d['id']}").json()
    assert dev["hostname"] == "RIYA-PC" and dev["online"] is True and dev["collectorsAvailable"] == ["network", "dns", "downloads", "logons"]
    from app.db.database import SessionLocal
    from app.db.models import User
    db = SessionLocal()
    try:
        db.get(User, emp._uid).is_active = False
        db.commit()
        assert a.post("/api/agent/hello", json={}).status_code == 403
        db.get(User, emp._uid).is_active = True
        db.commit()
    finally:
        db.close()
    assert emp.delete(f"/api/devices/{d['id']}").json()["removed"] is True
    assert a.post("/api/agent/hello", json={}).status_code == 401


def _row(port, program="nc.exe", addr="0.0.0.0", remote="", rport=0, status="LISTEN", path=""):
    return {"protocol": "TCP", "localAddress": addr, "localPort": port, "remoteAddress": remote, "remotePort": rport,
            "status": status, "program": program, "pid": 4321, "path": path}


def test_network_report_is_judged_like_the_laptop_and_reported_once(people):
    admin, emp, _ = people
    d = _pair(emp, "Riya's laptop")
    a = _agent(d["key"])
    rows = [_row(4444), _row(443, "chrome.exe", "192.168.1.5", "142.250.1.1", 443, "ESTABLISHED"),
            _row(135, "svchost.exe", "127.0.0.1")]
    r = a.post("/api/agent/network", json={"rows": rows}).json()
    assert r["ok"] and r["findings"] == 1 and r["summary"]["openPorts"] == 2
    assert a.post("/api/agent/network", json={"rows": rows}).json()["findings"] == 0      # same setting: not again
    found = [s for s in _items(emp) if "backdoor port 4444" in s["target"]]
    assert found and found[0]["riskScore"] == 88
    det = admin.get(f"/api/devices/{d['id']}").json()
    assert det["findings"][0]["collector"] == "network" and det["networkLast"]["summary"]["openToNetwork"] == 1
    assert det["findings24h"] == 1 and det["collectors"]["network"]["findings"] == 0          # the latest report
    assert "2 open port(s)" in det["collectors"]["network"]["note"]
    assert admin.get("/api/devices").json()["summary"]["findings24h"] >= 1
    bad = a.post("/api/agent/network", json={"rows": [_row(70000)]})
    assert bad.status_code == 422                                                         # impossible port refused


def _event(eid, rec, minute, user, ip, logon_type="3", sub="0xc000006a"):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="2026-10-12T02:{minute:02d}:00.000Z"/><EventRecordID>{rec}</EventRecordID>'
            f'</System><EventData><Data Name="TargetUserName">{user}</Data><Data Name="IpAddress">{ip}</Data>'
            f'<Data Name="LogonType">{logon_type}</Data><Data Name="SubStatus">{sub}</Data></EventData></Event>')


def test_windows_sign_ins_brute_force_is_found_once_and_xml_tricks_are_refused(people):
    _, emp, _ = people
    a = _agent(_pair(emp)["key"])
    xml = "".join(_event(4625, 100 + i, 10 + i, "riya", "45.155.205.10") for i in range(8))
    xml += _event(4624, 120, 20, "riya", "45.155.205.10", logon_type="10")
    r = a.post("/api/agent/logons", json={"xml": xml}).json()
    assert r["findings"] == 1 and r["checked"] == 9
    assert a.post("/api/agent/logons", json={"xml": xml}).json() == {"ok": True, "findings": 0, "checked": 0}
    evil = '<!DOCTYPE x [<!ENTITY a "aaaa">]>' + _event(4625, 200, 1, "&a;", "1.2.3.4")
    assert a.post("/api/agent/logons", json={"xml": evil}).status_code == 422


def test_website_names_only_dangerous_ones_are_kept(people):
    _, emp, _ = people
    d = _pair(emp)
    a = _agent(d["key"])
    r = a.post("/api/agent/dns", json={"names": ["www.google.com", "github.com", "paypal-login-secure-verify.com",
                                                 "printer.local", "10.0.0.5", "PAYPAL-LOGIN-SECURE-VERIFY.COM."]}).json()
    assert r["checked"] == 3 and r["findings"] == 1
    targets = [s["target"] for s in _items(emp)]
    assert "paypal-login-secure-verify.com" in targets and "www.google.com" not in targets
    assert a.post("/api/agent/dns", json={"names": ["paypal-login-secure-verify.com"]}).json()["findings"] == 0
    from app.db.database import SessionLocal
    from app.db.models import Device
    db = SessionLocal()
    try:
        assert "google" not in str(db.get(Device, d["id"]).state)          # no browsing list on the server
    finally:
        db.close()


def test_risky_download_is_checked_and_deleted_harmless_one_not_reported(people, tmp_path, monkeypatch):
    _, emp, _ = people
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "UPLOAD_DIR", str(tmp_path))
    a = _agent(_pair(emp)["key"])
    r = a.post("/api/agent/file", files={"file": ("Invoice_2026.pdf.exe", b"MZ" + b"\x00" * 300)}).json()
    assert r["findings"] == 1 and r["riskScore"] >= 71
    r2 = a.post("/api/agent/file", files={"file": ("notes.txt", b"hello team, lunch at 1")}).json()
    assert r2["findings"] == 0
    assert list(tmp_path.iterdir()) == []                                   # nothing kept on the server
    assert any("Invoice_2026.pdf.exe" in s["target"] for s in _items(emp))
    odd = a.post("/api/agent/file", files={"file": ("..", b"MZ" + b"\x00" * 10)})
    assert odd.status_code == 200 and list(tmp_path.iterdir()) == []


def test_employees_page_counts_devices(people):
    admin, emp, _ = people
    _pair(emp)
    _pair(emp, "Second PC")
    rows = {r["id"]: r for r in admin.get("/api/company/employees").json()["employees"]}
    assert rows[emp._uid]["devices"] == 2
