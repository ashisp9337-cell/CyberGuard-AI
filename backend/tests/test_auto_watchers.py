"""(6 Nov) The three permission-based watchers: this PC's network connections, website names looked up by any
program, and every request to the website. They start OFF, run only after being switched on, and report each
finding once."""
import json
import os
import time
import uuid

import pytest

from helpers import register_user


@pytest.fixture()
def fresh_state(monkeypatch, tmp_path):
    from app.automation import engine
    monkeypatch.setattr(engine, "STATE_FILE", str(tmp_path / "state.json"))
    return tmp_path


@pytest.fixture()
def owner(client, monkeypatch, fresh_state):
    """A fresh account that receives the automatic findings."""
    from app.automation import engine
    from app.db.database import SessionLocal
    from app.db.models import User
    email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
    assert register_user(client, {"name": "Owner", "email": email, "password": "TestPass123"}).status_code == 201
    db = SessionLocal()
    uid = db.query(User).filter(User.email == email).first().id
    db.close()
    monkeypatch.setattr(engine, "owner_user_id", lambda db: uid)
    return uid


def _scans(uid, title):
    from app.db.database import SessionLocal
    from app.db.models import Scan
    db = SessionLocal()
    try:
        return [(s.risk_score, s.target) for s in db.query(Scan).filter(Scan.user_id == uid, Scan.subtopic_title == title)
                .order_by(Scan.created_at).all()]
    finally:
        db.close()


# ---- permission ----------------------------------------------------------------------------------------------------
def test_new_watchers_start_off_and_cannot_run_before_permission(admin_client, fresh_state):
    st = {w["name"]: w for w in admin_client.get("/api/automation/status").json()["watchers"]}
    for name in ("network", "dns", "website"):
        assert st[name]["enabled"] is False and st[name]["askFirst"] is True and st[name]["state"] == "off"
        assert len(st[name]["permission"]) > 40                       # says what is allowed, in words
        r = admin_client.post(f"/api/automation/{name}/run")
        assert r.status_code == 409 and r.json()["error"]["code"] == "NOT_ALLOWED_YET"
    for name in ("email", "downloads"):                                # the old four keep their behaviour
        assert st[name]["askFirst"] is False
    assert admin_client.post("/api/automation/website/toggle", json={"enabled": True}).json()["enabled"] is True
    assert admin_client.post("/api/automation/website/run").status_code == 200


def test_normal_users_cannot_switch_them_on(auth_client, fresh_state, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "ADMIN_EMAILS", "someone-else@example.com")
    assert auth_client.post("/api/automation/network/toggle", json={"enabled": True}).status_code == 403


# ---- network watcher -----------------------------------------------------------------------------------------------
def _snap(findings):
    return {"available": True, "findings": findings,
            "summary": {"connections": 3, "openPorts": 2, "openToNetwork": 1, "high": 1, "medium": 0}}


def test_network_watcher_reports_high_findings_once(owner, monkeypatch):
    from app.automation.network_watcher import NetworkWatcher
    from app.services import pc_network
    found = [{"severity": "high", "title": "Connection on backdoor port 4444", "why": "x has a connection on 4444.",
              "port": 4444, "remote": "203.0.113.66", "program": "invoice.exe", "pid": 300},
             {"severity": "high", "title": "Connection on backdoor port 4444", "why": "other end of the same one.",
              "port": 4444, "remote": "203.0.113.66", "program": "unknown", "pid": None},
             {"severity": "medium", "title": "SSH remote login is open to all networks (port 22)", "why": "w",
              "port": 22, "program": "sshd", "pid": 7}]
    monkeypatch.setattr(pc_network, "snapshot", lambda flagged=None: _snap(found))
    w = NetworkWatcher()
    assert w.check()["threats"] == 1                       # medium: page only; the 2 ends of one connection: once
    assert w.check()["threats"] == 0                       # not again 30 seconds later
    rows = _scans(owner, "Automatic network monitoring (this PC)")
    assert rows == [(88, "Connection on backdoor port 4444")]


def test_network_watcher_says_when_the_list_is_not_available(monkeypatch, fresh_state):
    from app.automation.network_watcher import NetworkWatcher
    from app.services import pc_network
    monkeypatch.setattr(pc_network, "snapshot", lambda flagged=None: {"available": False, "reason": "needs admin"})
    assert "needs admin" in NetworkWatcher().run_once()["lastError"]


# ---- website names looked up by any program -------------------------------------------------------------------------
def test_dns_cache_json_is_read_like_powershell_writes_it():
    from app.automation.dns_watcher import parse_cache_json
    many = json.dumps([{"Entry": "www.google.com", "Type": 1, "Status": 0}, {"Entry": "WWW.Google.com.", "Type": 28},
                       {"Entry": "paypa1-secure-login.com", "Type": 1, "Status": 0}])
    assert parse_cache_json(many) == ["www.google.com", "paypa1-secure-login.com"]
    assert parse_cache_json(json.dumps({"Entry": "one.example.org", "Type": 1})) == ["one.example.org"]   # one row
    assert parse_cache_json("") == []


@pytest.mark.parametrize("name,ok", [("www.google.com", True), ("wpad", False), ("printer.local", False),
                                     ("1.0.168.192.in-addr.arpa", False), ("192.168.1.5", False), ("bad name.com", False)])
def test_only_real_internet_names_are_judged(name, ok):
    from app.automation.dns_watcher import worth_checking
    assert worth_checking(name) is ok


def test_dns_watcher_reports_dangerous_names_once(owner, monkeypatch):
    from app.automation import dns_watcher
    names = ["www.google.com", "login.microsoftonline.com", "paypa1-secure-login.com", "sbi-kyc-update.top",
             "printer.local"]
    monkeypatch.setattr(dns_watcher, "read_dns_cache", lambda: names)
    monkeypatch.setattr(dns_watcher, "IS_WINDOWS", True)
    w = dns_watcher.DnsWatcher()
    assert w.configured()[0]
    out = w.check()
    assert out["checked"] == 4 and out["threats"] == 2
    assert w.check()["checked"] == 0                      # judged once a week, not every minute
    targets = {t for _, t in _scans(owner, "Automatic check of looked-up websites")}
    assert targets == {"paypa1-secure-login.com", "sbi-kyc-update.top"}


def test_dns_watcher_is_windows_only(monkeypatch):
    from app.automation import dns_watcher
    monkeypatch.setattr(dns_watcher, "IS_WINDOWS", False)
    ok, why = dns_watcher.DnsWatcher().configured()
    assert not ok and "Windows" in why
    with pytest.raises(RuntimeError):
        dns_watcher.read_dns_cache()


# ---- every request to the website ----------------------------------------------------------------------------------
def test_requests_are_recorded_without_secrets(client):
    from app.services import request_log
    before = request_log.last_seq()
    client.get("/api/health?token=abc123&q=hello", headers={"User-Agent": "UnitTest/1.0", "Cookie": "s=topsecret"})
    e = [x for x in request_log.since(before) if x["path"] == "/api/health"][-1]
    assert e["query"] == "token=***&q=hello" and e["ua"] == "UnitTest/1.0" and e["status"] == 200
    assert "topsecret" not in json.dumps(e) and set(e) == {"seq", "ts", "ip", "method", "path", "query", "status",
                                                           "ua", "ref"}
    line = request_log.as_access_log([e])
    assert '"GET /api/health?token=***&q=hello HTTP/1.1" 200' in line


def _feed(ip, rows):
    from app.services import request_log
    for method, path, query, status, ua in rows:
        request_log.record(ip, method, path, query, status, ua, "")


SHELLSHOCK = '() { ignored; }; echo Content-Type: text/plain ; echo ; echo "bash_cve_2014_6271_rce Output : $((3+4))"'


def test_website_watcher_reports_real_attack_patterns_once(owner, monkeypatch):
    """Patterns from WRCCDC 2018 red-team requests: Shellshock in the user agent, SQL injection, WPScan."""
    from app.automation.website_watcher import WebsiteWatcher
    w = WebsiteWatcher()
    _feed("203.0.113.50", [("GET", f"/before{i}.php", "id=1' OR '1'='1", 404, "sqlmap/1.7") for i in range(10)])
    w.set_enabled(True)                                             # permission given now: earlier requests not read
    assert w.check()["checked"] == 0
    _feed("10.164.94.120", [("GET", f"/cgi-bin/test{i}.cgi", "", 404, SHELLSHOCK) for i in range(6)] +
          [("GET", "/index.php", f"id=1' UNION SELECT username,password FROM users--{i}", 404, "Mozilla/5.0")
           for i in range(6)] +
          [("GET", f"/wp-content/plugins/p{i}/readme.txt", "", 404, "WPScan v3.8.10 (https://wpscan.com/wordpress-security-scanner)")
           for i in range(40)])
    out = w.check()
    assert out["threats"] >= 2 and "10.164.94.120" in out["finding"]
    labels = {t for _, t in _scans(owner, "Automatic website monitoring")}
    assert labels and all("10.164.94.120" in t for t in labels)
    _feed("10.164.94.120", [("GET", "/index.php", "id=1' OR '1'='1", 404, "Mozilla/5.0") for _ in range(6)])
    assert w.check()["threats"] == 0                                # same attack, same address: not again today


def test_website_watcher_ignores_normal_use(owner):
    from app.automation.website_watcher import WebsiteWatcher
    w = WebsiteWatcher()
    w.check()
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
    rows = []
    for _ in range(30):
        rows += [("GET", "/api/auth/me", "", 200, ua), ("GET", "/api/dashboard/overview", "", 200, ua),
                 ("GET", "/api/scans", "limit=20&page=1", 200, ua), ("OPTIONS", "/api/scans", "", 200, ua)]
    rows += [("POST", "/api/auth/login", "", 401, ua), ("POST", "/api/auth/login", "", 200, ua)]
    _feed("127.0.0.1", rows)
    assert w.check()["threats"] == 0


def test_website_watcher_reads_only_new_lines_of_another_sites_log(owner, monkeypatch, tmp_path):
    from app.automation import website_watcher as WW
    from app.core.config import get_settings
    log = tmp_path / "access.log"
    old = '203.0.113.9 - - [06/Nov/2026:10:00:00 +0000] "GET /old.php?id=1%27%20OR%201=1-- HTTP/1.1" 404 0 "-" "x"\n'
    log.write_text(old * 10)
    monkeypatch.setattr(get_settings(), "WEBSITE_ACCESS_LOGS", str(log))
    w = WW.WebsiteWatcher()
    w.check()                                                      # first round starts at the END: no history
    assert not _scans(owner, "Automatic website monitoring")
    with open(log, "a") as f:
        for i in range(8):
            f.write(f'198.51.100.7 - - [06/Nov/2026:10:05:0{i} +0000] "GET /login.php?user=admin%27--{i} HTTP/1.1" '
                    f'404 0 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"\n')
    out = w.check()
    assert out["threats"] >= 1 and "198.51.100.7" in out["finding"] and "access.log" in out["finding"]
    log.write_text("")                                            # rotated: starts again from the top
    assert w.check()["checked"] == 0


def test_a_missing_log_file_is_an_error_not_a_crash(fresh_state, monkeypatch, tmp_path):
    from app.automation import website_watcher as WW
    from app.core.config import get_settings
    from app.services import request_log
    monkeypatch.setattr(get_settings(), "WEBSITE_ACCESS_LOGS", str(tmp_path / "nope.log"))
    monkeypatch.setattr(request_log, "since", lambda seq: [])
    st = WW.WebsiteWatcher().run_once()
    assert "nope.log" in (st["lastError"] or "")
