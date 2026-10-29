"""Network traffic detection (cyber-threat module): flow CSV / Zeek / firewall readers, packet captures (built here
packet by packet with dpkt - nothing is sent anywhere), behaviour incidents, the supporting model's limited role, and
uploading a capture through the API. No trained file is needed."""
import io
import json
import os
import socket

import pytest

dpkt = pytest.importorskip("dpkt")

from app.detectors import cyber_threat as C          # noqa: E402
from app.detectors import network_traffic as NT      # noqa: E402

CFG = dict(NT.DEFAULTS)
HDR = ("Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Total Fwd Packet,Total Bwd packets,"
       "Total Length of Fwd Packet,Total Length of Bwd Packet,FIN Flag Count,SYN Flag Count,RST Flag Count,Label")


def row(i, src, dst, dport, *, sec, bwd=2, fby=120, bby=900, syn=1, rst=0, fin=2, proto=6):
    return (f"x,{src},{40000 + i},{dst},{dport},{proto},07/07/2017 01:{sec // 60:02d}:{sec % 60:02d} PM,250000,3,{bwd},"
            f"{fby},{bby},{fin},{syn},{rst},BENIGN")


def normal_rows(n=60):
    return [row(i, "192.168.10.9", "192.168.10.3" if i % 3 else "8.8.8.8", (443, 53, 80)[i % 3], sec=i * 5,
                proto=17 if i % 3 == 1 else 6) for i in range(n)]


def csv_text(rows):
    return "\n".join([HDR] + rows)


def cats(text):
    s = NT.analyze_text(text, CFG)
    return {i["category"] for i in s["incidents"]}, s


# ---- flow records -----------------------------------------------------------------------------------------------
def test_flow_csv_normal_traffic_is_quiet_and_read_fully():
    found, s = cats(csv_text(normal_rows()))
    assert found == set() and s["connections"] == 60 and s["format"] == "CSV flow records"
    assert s["timeRange"] == ["2017-07-07 13:00:00", "2017-07-07 13:04:55"]


def test_port_scan_and_failed_flood_from_flow_records():
    scan = [row(1000 + p, "172.16.0.1", "192.168.10.50", p, sec=600 + p // 20, bwd=1, fby=0, bby=0, rst=1, fin=0)
            for p in range(1, 700)]
    found, s = cats(csv_text(normal_rows() + scan))
    assert {"port_scan", "failed_flood"} <= found
    inc = {i["category"]: i for i in s["incidents"]}["port_scan"]
    assert inc["sources"] == ["172.16.0.1"] and "699 different ports on 192.168.10.50" in inc["description"]


def test_login_brute_force_but_not_a_few_admin_sessions():
    ssh = [row(2000 + i, "203.0.113.7", "192.168.10.50", 22, sec=900 + i) for i in range(40)]
    found, _ = cats(csv_text(normal_rows() + ssh))
    assert "brute_force" in found
    admin = [row(3000 + i, "192.168.10.5", "192.168.10.50", 22, sec=900 + i * 60) for i in range(6)]
    assert "brute_force" not in cats(csv_text(normal_rows() + admin))[0]


def test_scan_touching_ssh_is_reported_as_a_scan_only():
    scan = [row(4000 + p, "172.16.0.1", "192.168.10.50", p, sec=600, bwd=1, fby=0, bby=0, rst=1, fin=0)
            for p in range(1, 200)]
    ssh_probes = [row(4500 + i, "172.16.0.1", "192.168.10.50", 22, sec=601) for i in range(15)]
    found, _ = cats(csv_text(scan + ssh_probes))
    assert "port_scan" in found and "brute_force" not in found


def test_dos_flood_and_leftover_tcp_records_without_syn_are_ignored():
    flood = [row(5000 + i, "172.16.0.1", "192.168.10.50", 80, sec=1200 + i // 10) for i in range(2600)]
    assert "dos_flood" in cats(csv_text(flood))[0]
    leftovers = [row(9000 + i, "172.16.0.1", "192.168.10.50", 80, sec=1200 + i // 10, syn=0) for i in range(2600)]
    assert cats(csv_text(leftovers))[0] == set()


def test_backdoor_port_needs_an_answered_connection():
    answered = [row(6000, "192.168.10.8", "205.174.165.73", 4444, sec=10)] + normal_rows(5)
    assert "backdoor_port" in cats(csv_text(answered))[0]
    refused = [row(6001, "192.168.10.8", "205.174.165.73", 4444, sec=10, bwd=1, fby=0, bby=0, rst=1)] + normal_rows(5)
    assert "backdoor_port" not in cats(csv_text(refused))[0]


# ---- Zeek and firewall logs -------------------------------------------------------------------------------------
def test_zeek_conn_log_internal_host_sweep():
    fields = "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state " \
             "local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes".split()
    lines = ["#separator \\x09", "#fields\t" + "\t".join(fields)]
    for i in range(30):
        lines.append("\t".join(map(str, [1700000000 + i, f"C{i}", "10.0.0.66", 50000 + i, f"10.0.0.{100 + i}", 445,
                                         "tcp", "-", "0.001", 0, 0, "S0", "T", "T", 0, "S", 1, 44, 0, 0])))
    found, s = cats("\n".join(lines))
    assert s["format"] == "Zeek conn.log" and "host_sweep" in found


def test_firewall_log_port_scan():
    lines = [f"Oct 24 01:{i // 60:02d}:{i % 60:02d} web kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=192.168.1.5 "
             f"LEN=44 TOS=0x00 PROTO=TCP SPT=51515 DPT={i + 1} WINDOW=1024 RES=0x00 SYN URGP=0" for i in range(150)]
    found, s = cats("\n".join(lines))
    assert s["format"].startswith("Linux firewall") and "port_scan" in found


def test_plain_text_is_not_mistaken_for_flows():
    assert NT.analyze_text("hello, this is, just a, sentence, with commas\nand another, line, here, ok, fine") is None


# ---- packet captures --------------------------------------------------------------------------------------------
def _pkt(src, dst, sport, dport, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=tcp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6, type=0x0800, data=ip))


def _session(c, s, cport, sport, t, request=b""):
    """A full TCP conversation, including the final ACK after both FINs (the 'leftover' packet)."""
    S, A, F, P = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN, dpkt.tcp.TH_PUSH
    return [(t, _pkt(c, s, cport, sport, S)), (t + .001, _pkt(s, c, sport, cport, S | A)),
            (t + .002, _pkt(c, s, cport, sport, A)), (t + .003, _pkt(c, s, cport, sport, P | A, request or b"hi")),
            (t + .004, _pkt(s, c, sport, cport, P | A, b"HTTP/1.1 200 OK\r\n\r\nok")),
            (t + .005, _pkt(c, s, cport, sport, F | A)), (t + .006, _pkt(s, c, sport, cport, F | A)),
            (t + .007, _pkt(c, s, cport, sport, A))]


def _write(path, packets, ng=False):
    with open(path, "wb") as f:
        w = dpkt.pcapng.Writer(f) if ng else dpkt.pcap.Writer(f)
        for ts, buf in packets:
            w.writepkt(buf, ts=ts)


def test_capture_counts_each_tcp_conversation_once(tmp_path):
    pk = []
    for i in range(20):
        pk += _session("192.168.1.10", "93.184.216.34", 50000 + i, 80, 1_700_000_000 + i,
                       b"GET /index.html?page=%d HTTP/1.1\r\nHost: example.com\r\n\r\n" % i)
    _write(tmp_path / "normal.pcap", pk)
    s = NT.analyze_capture(str(tmp_path / "normal.pcap"), CFG)
    assert s["connections"] == 20 and s["httpRequests"] == 20 and s["incidents"] == []


def test_capture_syn_scan_and_web_attack_pcapng(tmp_path):
    S, R, A = dpkt.tcp.TH_SYN, dpkt.tcp.TH_RST, dpkt.tcp.TH_ACK
    pk = []
    for p in range(1, 301):
        pk += [(1_700_000_000 + p / 100, _pkt("10.0.0.66", "10.0.0.5", 61000, p, S)),
               (1_700_000_000 + p / 100 + .0005, _pkt("10.0.0.5", "10.0.0.66", p, 61000, R | A))]
    pk += _session("10.0.0.66", "10.0.0.5", 62000, 80, 1_700_000_010,
                   b"GET /item.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1\r\n\r\n")
    _write(tmp_path / "attack.pcapng", pk, ng=True)
    s = NT.analyze_capture(str(tmp_path / "attack.pcapng"), CFG)
    found = {i["category"] for i in s["incidents"]}
    assert {"port_scan", "web_attack"} <= found and s["connections"] == 301


def test_cut_off_capture_keeps_what_was_read(tmp_path):
    pk = []
    for i in range(5):
        pk += _session("192.168.1.10", "93.184.216.34", 50000 + i, 443, 1_700_000_000 + i)
    _write(tmp_path / "full.pcap", pk)
    data = (tmp_path / "full.pcap").read_bytes()
    (tmp_path / "cut.pcap").write_bytes(data[:-30])
    s = NT.analyze_capture(str(tmp_path / "cut.pcap"), CFG)
    assert s["connections"] == 5            # the cut-off last packet is dropped (dpkt) or flagged; nothing crashes
    assert s["readStats"].get("truncated") == 1 or s["readStats"].get("skipped") == 1


def test_not_a_capture_is_reported_not_crashed(tmp_path):
    p = tmp_path / "fake.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"garbage")
    r = C.analyze_network_capture(str(p), "fake.pcap", "Network Traffic")
    assert r["riskScore"] == 0 and "could not be read" in r["explanation"]


# ---- verdicts, model role, config -------------------------------------------------------------------------------
def test_verdict_from_pasted_flow_records():
    scan = [row(1000 + p, "172.16.0.1", "192.168.10.50", p, sec=600, bwd=1, fby=0, bby=0, rst=1, fin=0)
            for p in range(1, 300)]
    r = C.analyze_event_text(csv_text(normal_rows() + scan), {}, "Network Traffic")
    assert r["riskScore"] >= 71 and r["networkAnalysis"]["connections"] == 359
    assert r["explanation"].startswith("Read 359 network connections (CSV flow records) and found")
    quiet = C.analyze_event_text(csv_text(normal_rows()), {}, "Network Traffic")
    assert quiet["riskScore"] < 51 and "found no attack behaviour" in quiet["explanation"]
    assert "format was not recognised" not in quiet["explanation"]


def test_supporting_model_never_raises_an_alert_alone():
    added = []
    summary = {"incidents": [], "model": {"connections": 1000, "flagged": 900, "share": .9, "topSources": []}}
    floor = C._apply_network(summary, lambda *a: added.append(a))
    assert floor == 0 and added and added[0][4] <= 5 and added[0][3] == "low"


def test_thresholds_file_is_used_and_a_broken_file_is_ignored(tmp_path, monkeypatch):
    path = tmp_path / "network_traffic.json"
    monkeypatch.setattr(NT, "CONFIG_PATH", str(path))
    path.write_text(json.dumps({"thresholds": {**NT.DEFAULTS, "port_scan": 5000}}))
    assert NT.load_config()["port_scan"] == 5000
    path.write_text("not json")
    assert NT.load_config() == NT.DEFAULTS


def test_training_features_match_the_detector():
    pd = pytest.importorskip("pandas")
    from app.ml.training import train_network_traffic as T
    d = pd.DataFrame({"dst_port": [80, 443, 22, 3389, 5000, 60000, 53], "protocol": [6, 6, 6, 6, 17, 6, 17],
                      "duration": [1e6, 2.0, 0, 5, 9, 1, 3], "fwd_packets": [3, 1, 0, 2, 2, 1, 1],
                      "bwd_packets": [2, 0, 0, 1, 1, 1, 1], "fwd_bytes": [100, 0, 0, 5, 9, 1, 40],
                      "bwd_bytes": [900, 0, 0, 7, 1, 1, 80], "syn_flags": [1, 1, 1, 1, 0, 1, 0],
                      "rst_flags": [0, 1, 0, 0, 0, 0, 0], "fin_flags": [2, 0, 0, 1, 0, 0, 0]})
    m = T.feature_matrix(d)
    for i, r in enumerate(d.itertuples()):
        f = NT.Flow(None, "a", 1, "b", r.dst_port, r.protocol, r.duration, r.fwd_packets, r.bwd_packets, r.fwd_bytes,
                    r.bwd_bytes, r.syn_flags, r.rst_flags, r.fin_flags, False, True)
        assert m[i].tolist() == pytest.approx(NT.features(f), abs=1e-5)


# ---- through the API --------------------------------------------------------------------------------------------
def _scan_capture(tmp_path):
    S, R, A = dpkt.tcp.TH_SYN, dpkt.tcp.TH_RST, dpkt.tcp.TH_ACK
    pk = []
    for p in range(1, 401):
        pk += [(1_700_000_000 + p / 100, _pkt("10.0.0.66", "10.0.0.5", 61000, p, S)),
               (1_700_000_000 + p / 100 + .0005, _pkt("10.0.0.5", "10.0.0.66", p, 61000, R | A))]
    _write(tmp_path / "scan.pcap", pk)
    return (tmp_path / "scan.pcap").read_bytes()


def test_uploading_a_capture(auth_client, tmp_path):
    files = {"file": ("scan.pcap", io.BytesIO(_scan_capture(tmp_path)), "application/vnd.tcpdump.pcap")}
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "network-traffic",
                                                      "subtopicTitle": "Suspicious Network Traffic Detection"}, files=files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["riskScore"] >= 71 and body["networkAnalysis"]["connections"] == 400
    assert body["networkAnalysis"]["incidents"][0]["label"] == "Port scan"
    from app.core.config import get_settings
    folder = get_settings().UPLOAD_DIR
    assert not any(n.endswith(".pcap") for n in (os.listdir(folder) if os.path.isdir(folder) else []))   # deleted


def test_capture_with_auto_detect(auth_client, tmp_path):
    files = {"file": ("traffic.pcap", io.BytesIO(_scan_capture(tmp_path)), "application/octet-stream")}
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "auto",
                                                      "subtopicTitle": "Auto-detect"}, files=files)
    assert r.status_code == 200, r.text
    assert r.json()["subtopicId"] == "network-traffic" and r.json()["riskScore"] >= 71


def test_response_actions_block_outside_scanners_and_isolate_inside_ones():
    from app.services import mitre, response_playbook
    result = {"classification": "high_risk", "indicators": [],
              "networkAnalysis": {"incidents": [{"sources": ["203.0.113.9", "192.168.1.66"]}]}}
    titles = [a["title"] for a in response_playbook.build_actions(result, "cyber-threat", "network-traffic", "scan.pcap")]
    assert "Block IP 203.0.113.9" in titles and "Check / isolate 192.168.1.66" in titles
    for t in ("T1046", "T1018", "T1571", "T1190", "T1595.002"):
        assert t in mitre.CATALOGUE
