"""Suspicious network traffic detection (cyber-threat module) - judges a whole capture or flow log at once.

Input -> connections ("flows") -> behaviour per source -> incidents:
  * readers: CICFlowMeter flow CSV, Zeek conn.log (TSV or JSON), Linux firewall logs (iptables / UFW) and packet
    captures (.pcap / .pcapng from Wireshark or tcpdump, read with dpkt: the file is only parsed, never replayed)
  * behaviour, per source in any 10-minute window: ports tried on one machine (port scan), machines that did not
    answer (host sweep), failed / half-open connections (SYN flood, slow DoS), connections to one login service
    (brute force), connections to one web service (DoS flood), connections to well-known backdoor ports, and web
    attack payloads inside unencrypted HTTP requests (captures only; reuses the API-abuse attack patterns)
  * (31 Oct) captures: the FORM BODY of POST requests is read too (SQL injection / XSS sent in a login or search
    form), every request of a keep-alive connection is read (not only the first), and many guesses at one web login
    form from one source (password-guessing tools such as Hydra / Burp Intruder) are reported
  * the alert levels are learned from real normal traffic in CIC-IDS2017 (corrected by KU Leuven) by
    app/ml/training/train_network_traffic.py and saved in app/ml/models/network_traffic.json
  * a per-connection model (network_flow.joblib) adds SUPPORTING evidence only: on attack types it never saw it
    misses most of them and flags ~0.1-1% of normal connections, so it can never raise an alert on its own.
Nothing here opens a network connection.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import math
import os
import re
import struct
import time
from collections import Counter, defaultdict, namedtuple
from datetime import datetime, timezone
from functools import lru_cache

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "..", "ml", "models", "network_traffic.json")
MODEL_PATH = os.path.join(HERE, "..", "ml", "models", "network_flow.joblib")
WINDOW_S = 600
MAX_FLOWS = 300_000             # connections read from one upload
MAX_PACKETS = 3_000_000         # packets read from one capture
MAX_SECONDS = 60                # a capture is read for at most this long
FLOW_TIMEOUT = 120              # a connection idle this long ends (same as CICFlowMeter)
DEFAULTS = {"port_scan": 97, "host_sweep": 5, "failed_flood": 498, "brute_force": 9, "dos_flood": 2553}   # = network_traffic.json
MAX_HTTP = 20_000               # HTTP requests kept from one capture
MAX_BODY = 8_192                # bytes of one request body read (forms / JSON; file uploads are skipped)
MAX_BODIES = 16 * 1024 * 1024   # bytes of request bodies kept from one capture in total (memory limit)
# (31 Oct) requests to one web login form from one source in 10 minutes that count as password guessing: a person
# who mistypes tries a few times; guessing tools send hundreds. The CIC-IDS2017 web brute force sent 1,365 in an hour.
WEB_LOGIN_GUESSES = 20
_PASSWORD_FIELD = re.compile(r"(^|[&?;])[\w.\[\]-]*(pass(word|wd)?|pwd|passcode|pin)[\w\[\]-]*=", re.I)

# interactive login services only: mail clients poll IMAP/POP often and Windows opens many SMB connections to file
# servers, so those ports gave false "brute force" alarms on normal CIC-IDS2017 traffic (tested 24 Oct)
# (6 Nov) An INSIDE machine retrying a refused / unanswered connection to the same address on a backdoor port: malware
# calling its controller (seen on WRCCDC 2018: 342 refused tries to port 4444 in 21 min). Normal traffic of the whole
# CIC-IDS2017 week made 0 connections to these ports, so the level is the minimum 5 (project rule: busiest normal + 1).
CALLBACK_ATTEMPTS = 5
# ICMP messages that are ANSWERS or ERRORS (port / host unreachable, time exceeded, echo reply ...), not probes: a server
# answering a UDP scan sends many of them, and that must not make the server look like the scanner. Type = sport.
ICMP_NOT_PROBE = {1: {3, 4, 5, 11, 12, 14, 16, 18}, 58: {1, 2, 3, 4, 129, 134, 136}}
LOGIN_PORTS = {21, 22, 23, 3389, 5900}
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}
BACKDOOR_PORTS = {1337, 4444, 4445, 6667, 6697, 12345, 31337, 54321}
SERVICE = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 80: "HTTP", 443: "HTTPS", 8000: "HTTP",
           8080: "HTTP", 8443: "HTTPS", 8888: "HTTP"}

# one connection. ts: seconds (None = unknown); dur: microseconds (CICFlowMeter's unit); bytes = payload bytes
Flow = namedtuple("Flow", "ts src sport dst dport proto dur fpk bpk fby bby syn rst fin failed rich")

CATEGORY = {   # label, severity, weight, MITRE, plain explanation
    "dos_flood": ("Denial-of-service flood", "critical", 45, "T1499",
                  "One source opened a flood of connections to one web service - far more than any normal client "
                  "(typical of DoS tools such as Hulk, GoldenEye or LOIC)."),
    "brute_force": ("Login brute-force over the network", "critical", 40, "T1110",
                    "One source kept opening answered connections to a login service - password guessing "
                    "(e.g. Hydra, Patator)."),
    "web_attack": ("Web attack in captured HTTP requests", "critical", 40, "T1190",
                   "Unencrypted HTTP requests in the capture carry attack code (SQL injection, XSS, path traversal ...)."),
    "web_login_guessing": ("Password guessing against a web login", "critical", 40, "T1110.001",
                           "One source sent a long run of logins to the same web login form within minutes - a "
                           "password-guessing tool (e.g. Hydra, Burp Intruder), not a person mistyping."),
    "port_scan": ("Port scan", "high", 35, "T1046",
                  "One source tried many different ports on the same machine - a port scan (e.g. nmap)."),
    "host_sweep": ("Host sweep / network discovery", "high", 35, "T1018",
                   "One source tried many machines of the internal network that never answered - mapping the "
                   "network for targets (e.g. an nmap ping sweep)."),
    "failed_flood": ("Flood of failed / half-open connections", "high", 35, "T1499",
                     "One source left a flood of connections unanswered or reset - a SYN flood, a slow DoS "
                     "(slowloris / slowhttptest) or a noisy scan."),
    "backdoor_callback": ("Repeated attempts to reach a backdoor port", "high", 35, "T1571",
                          "A machine of this network kept trying to reach the same address on a port used by "
                          "backdoors / attack tools (e.g. 4444 = Metasploit's default) and was refused or not "
                          "answered. Either malware on the first machine is trying to call its controller, or someone "
                          "is trying to use a backdoor planted on the second one - check both machines."),
    "backdoor_port": ("Traffic on a known backdoor port", "medium", 20, "T1571",
                      "Answered connections on a port used by backdoors / reverse shells (e.g. 4444 = Metasploit's "
                      "default, 6667 = IRC botnets, 31337)."),
}
_ORDER = list(CATEGORY)

_CACHE = {"cfg": None, "cfg_mtime": None, "model": None, "model_mtime": None}


def _stamp(path: str) -> tuple[int, int]:
    """(modified time in ns, size): a rewritten file is noticed even when Windows gives it the same timestamp."""
    st = os.stat(path)
    return st.st_mtime_ns, st.st_size


def load_config() -> dict:
    """Saved alert levels (falls back to DEFAULTS when the file is missing or broken)."""
    try:
        mtime = _stamp(CONFIG_PATH)
        if _CACHE["cfg_mtime"] != mtime:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                saved = json.load(f).get("thresholds") or {}
            _CACHE["cfg"] = {k: int(saved.get(k, v)) for k, v in DEFAULTS.items()}
            _CACHE["cfg_mtime"] = mtime
        return dict(_CACHE["cfg"])
    except (OSError, ValueError, TypeError, AttributeError):
        return dict(DEFAULTS)


# ---------------------------------------------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------------------------------------------
def _num(s, default=0.0) -> float:
    try:
        v = float(s)
        return v if math.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def _int(s, default=0) -> int:
    return int(_num(s, default))


_TS_FORMATS = ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
               "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f")


def parse_time(s) -> float | None:
    """Seconds since 1970 from an epoch number or a CICFlowMeter / ISO date (CICFlowMeter writes day first)."""
    s = str(s or "").strip().rstrip("Z")
    if not s:
        return None
    if re.fullmatch(r"\d{9,10}(\.\d+)?", s):
        return float(s)
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def failed_tcp(proto, bpk, rst, fby, bby) -> bool:
    """A TCP connection the other side never answered, or that was reset before any data moved."""
    return proto == 6 and (bpk == 0 or (rst > 0 and fby == 0 and bby == 0))


def _norm(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch not in " _/-.﻿")


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                       "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


@lru_cache(maxsize=200_000)
def is_internal(ip: str) -> bool:
    """An address inside an organisation's / home network (RFC 1918, carrier NAT, loopback, link-local, IPv6 local).
    Not Python's is_private, which also counts documentation ranges such as 203.0.113.0/24."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in _INTERNAL_NETS)


_private = is_internal


# ---------------------------------------------------------------------------------------------------------------
# readers (text)
# ---------------------------------------------------------------------------------------------------------------
_CSV_COLS = {
    "ts": ["timestamp", "ts", "starttime", "stime", "firstseen", "flowstart"],
    "src": ["srcip", "sourceip", "srcaddr", "saddr", "sa", "src"],
    "sport": ["srcport", "sourceport", "sport", "sp"],
    "dst": ["dstip", "destinationip", "dstaddr", "daddr", "da", "dst"],
    "dport": ["dstport", "destinationport", "dsport", "dport", "dp"],
    "proto": ["protocol", "proto", "pr"],
    "dur": ["flowduration"],
    "dur_s": ["duration", "dur", "td"],
    "fpk": ["totalfwdpacket", "totalfwdpackets", "spkts", "fwdpackets", "outpkts"],
    "bpk": ["totalbwdpackets", "totalbwdpacket", "totalbackwardpackets", "dpkts", "bwdpackets", "inpkts"],
    "fby": ["totallengthoffwdpacket", "totallengthoffwdpackets", "fwdpacketslengthtotal", "sbytes", "outbytes"],
    "bby": ["totallengthofbwdpacket", "totallengthofbwdpackets", "bwdpacketslengthtotal", "dbytes", "inbytes"],
    "syn": ["synflagcount"], "rst": ["rstflagcount"], "fin": ["finflagcount"],
}
_PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "ipv6-icmp": 58}


def _proto(v) -> int:
    v = str(v or "").strip().lower()
    return _PROTO.get(v, _int(v, 0))


def read_flow_csv(text: str) -> list[Flow] | None:
    """CICFlowMeter-style CSV (also NetFlow / Argus exports with similar column names). None if it is not one."""
    first = text.lstrip("﻿").split("\n", 1)[0]
    if first.count(",") < 4:
        return None
    rows = csv.reader(io.StringIO(text.lstrip("﻿")))
    header = next(rows, [])
    idx = {_norm(h): i for i, h in enumerate(header)}
    col = {k: next((idx[s] for s in spell if s in idx), None) for k, spell in _CSV_COLS.items()}
    if col["src"] is None or col["dst"] is None or col["dport"] is None:
        return None
    rich = all(col[k] is not None for k in ("dur", "fpk", "bpk", "fby", "bby", "syn", "rst", "fin", "proto"))
    out = []
    g = lambda row, k, d=0.0: _num(row[col[k]], d) if col[k] is not None and col[k] < len(row) else d   # noqa: E731
    for row in rows:
        if len(out) >= MAX_FLOWS:
            break
        if len(row) < len(header):
            continue                                   # broken line
        proto = _proto(row[col["proto"]]) if col["proto"] is not None else 6
        dur = g(row, "dur") if col["dur"] is not None else g(row, "dur_s") * 1e6
        fpk, bpk, fby, bby = g(row, "fpk"), g(row, "bpk", 1.0), g(row, "fby"), g(row, "bby")
        syn, rst, fin = g(row, "syn"), g(row, "rst"), g(row, "fin")
        if col["syn"] is None and proto == 6:
            syn = 1.0                                  # no flag columns: each TCP record is an opened connection
        out.append(Flow(parse_time(row[col["ts"]]) if col["ts"] is not None else None,
                        row[col["src"]].strip(), _int(g(row, "sport")), row[col["dst"]].strip(),
                        _int(row[col["dport"]]), proto, dur, fpk, bpk, fby, bby, syn, rst, fin,
                        failed_tcp(proto, bpk, rst, fby, bby), rich))
    return out


_ZEEK_FAILED = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


def _zeek_flow(d: dict) -> Flow | None:
    try:
        src, dst = d["id.orig_h"], d["id.resp_h"]
    except KeyError:
        return None
    proto = _proto(d.get("proto"))
    hist = str(d.get("history") or "")
    state = str(d.get("conn_state") or "")
    bpk = _num(d.get("resp_pkts"), 0.0)
    rst = float(hist.count("R") + hist.count("r"))
    syn = float(("S" in hist) + ("s" in hist)) if hist else (1.0 if proto == 6 else 0.0)
    return Flow(_num(d.get("ts"), None) if d.get("ts") not in (None, "-") else None, src, _int(d.get("id.orig_p")),
                dst, _int(d.get("id.resp_p")), proto, _num(d.get("duration")) * 1e6, _num(d.get("orig_pkts")), bpk,
                _num(d.get("orig_bytes")), _num(d.get("resp_bytes")), syn, rst,
                float(("F" in hist) + ("f" in hist)), proto == 6 and state in _ZEEK_FAILED, False)


def read_zeek(text: str) -> list[Flow] | None:
    """Zeek conn.log, tab-separated (with its #fields line) or one JSON object per line."""
    lines = text.splitlines()
    fields = next((ln.split("\t")[1:] for ln in lines[:50] if ln.startswith("#fields")), None)
    out = []
    if fields and "id.orig_h" in fields:
        for ln in lines:
            if ln.startswith("#") or not ln.strip():
                continue
            parts = ln.split("\t")
            if len(parts) != len(fields):
                continue
            f = _zeek_flow({k: (None if v in ("-", "(empty)") else v) for k, v in zip(fields, parts)})
            if f:
                out.append(f)
            if len(out) >= MAX_FLOWS:
                break
        return out
    if '"id.orig_h"' in text[:5000]:
        for ln in lines:
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                f = _zeek_flow(json.loads(ln))
            except (ValueError, TypeError, AttributeError):
                continue
            if f:
                out.append(f)
            if len(out) >= MAX_FLOWS:
                break
        return out
    return None


_FW = re.compile(r"\bSRC=(?P<src>[0-9a-fA-F:.]+)\s.*?\bDST=(?P<dst>[0-9a-fA-F:.]+)\s.*?\bPROTO=(?P<proto>\w+)"
                 r"(?:.*?\bSPT=(?P<spt>\d+))?(?:.*?\bDPT=(?P<dpt>\d+))?")


def read_firewall(text: str) -> list[Flow] | None:
    """Linux firewall log lines (iptables LOG / UFW): one line = one connection attempt seen by the firewall."""
    if "SRC=" not in text or "DST=" not in text:
        return None
    from app.detectors.log_incidents import timestamp
    out = []
    for ln in text.splitlines():
        m = _FW.search(ln)
        if not m:
            continue
        proto = _proto(m["proto"])
        blocked = bool(re.search(r"BLOCK|DROP|DENY|REJECT", ln, re.I))
        has_flags = re.search(r"\b(SYN|ACK|FIN|RST|PSH)\b", ln)
        syn = 1.0 if re.search(r"\bSYN\b", ln) or (proto == 6 and not has_flags) else 0.0
        sport = _int(m["spt"])
        if proto in (1, 58):                       # ICMP lines carry TYPE= instead of ports
            itype = re.search(r"\bTYPE=(\d{1,3})\b", ln)
            sport = int(itype[1]) if itype else 0
        out.append(Flow(timestamp(ln), m["src"], sport, m["dst"], _int(m["dpt"]), proto, 0.0, 1.0,
                        0.0 if blocked else 1.0, 0.0, 0.0, syn, 0.0, 0.0, proto == 6 and blocked, False))
        if len(out) >= MAX_FLOWS:
            break
    return out


def read_text(text: str) -> tuple[str, list[Flow]] | None:
    """(format name, flows) for pasted / uploaded text, or None when no flow format is recognised."""
    if not text or len(text) < 20:
        return None
    for name, reader in (("Zeek conn.log", read_zeek), ("CSV flow records", read_flow_csv),
                         ("Linux firewall log - iptables / UFW", read_firewall)):
        try:
            flows = reader(text)
        except (csv.Error, ValueError, IndexError):
            flows = None
        if flows:
            return name, flows
    return None


# ---------------------------------------------------------------------------------------------------------------
# reader (packet capture)
# ---------------------------------------------------------------------------------------------------------------
_PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_HTTP_START = re.compile(rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (\S{1,4000}) HTTP/\d")


def is_capture(head: bytes) -> bool:
    return head[:4] in _PCAP_MAGIC or head[:4] == _PCAPNG_MAGIC


def read_capture(path: str) -> dict:
    """Packets -> connections, like CICFlowMeter: a connection is both directions of one address/port pair; it ends
    on FIN from both sides, on a reset, or after FLOW_TIMEOUT seconds of silence. Also returns HTTP request lines.
    Raises ValueError for a file that is not a readable capture."""
    import dpkt
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        try:
            reader = dpkt.pcapng.Reader(fh) if head == _PCAPNG_MAGIC else dpkt.pcap.Reader(fh)
        except (ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as exc:
            raise ValueError(f"not a readable capture: {exc}") from None
        link = reader.datalink()
        live, done, http, stats = {}, [], [], Counter()
        t_start = time.monotonic()

        def close(key):
            c = live.pop(key)
            proto = c["proto"]
            done.append(Flow(c["t0"], c["src"], c.get("itype", c["sport"]), c["dst"], c["dport"], proto,
                             (c["t1"] - c["t0"]) * 1e6, c["fpk"], c["bpk"], c["fby"], c["bby"], c["syn"], c["rst"],
                             c["fin"], failed_tcp(proto, c["bpk"], c["rst"], c["fby"], c["bby"]), True))

        try:
            for ts, buf in reader:
                stats["packets"] += 1
                if stats["packets"] > MAX_PACKETS or time.monotonic() - t_start > MAX_SECONDS:
                    stats["stopped_early"] = 1
                    break
                ip = _ip_layer(dpkt, link, buf)
                if ip is None:
                    stats["skipped"] += 1
                    continue
                src, dst, proto, l4 = ip
                sport = dport = 0
                flags = 0
                payload = b""
                if proto == 6 and isinstance(l4, dpkt.tcp.TCP):
                    sport, dport, flags, payload = l4.sport, l4.dport, l4.flags, bytes(l4.data)
                elif proto == 17 and isinstance(l4, dpkt.udp.UDP):
                    sport, dport, payload = l4.sport, l4.dport, bytes(l4.data)
                elif proto in (1, 58):
                    payload = bytes(getattr(l4, "data", b"") or b"")
                fwd_key = (src, sport, dst, dport, proto)
                rev_key = (dst, dport, src, sport, proto)
                key = fwd_key if fwd_key in live else rev_key if rev_key in live else None
                new_syn = proto == 6 and flags & 0x02 and not flags & 0x10        # SYN without ACK = a new connection
                if key is not None and (ts - live[key]["t1"] > FLOW_TIMEOUT or (live[key]["ended"] and new_syn)):
                    close(key)
                    key = None
                if key is None:
                    if len(live) + len(done) >= MAX_FLOWS:
                        stats["stopped_early"] = 1
                        break
                    key = fwd_key
                    live[key] = {"t0": ts, "t1": ts, "src": src, "sport": sport, "dst": dst, "dport": dport,
                                 "proto": proto, "fpk": 0, "bpk": 0, "fby": 0, "bby": 0, "syn": 0, "rst": 0, "fin": 0,
                                 "fin_f": False, "fin_b": False, "ended": False}
                    if proto in (1, 58):     # ICMP: keep the message type of the first packet (like Zeek's orig_p)
                        live[key]["itype"] = int(getattr(l4, "type", 0) or 0)
                c = live[key]
                forward = (src, sport) == (c["src"], c["sport"])
                c["t1"] = ts
                if forward:
                    c["fpk"] += 1
                    c["fby"] += len(payload)
                else:
                    c["bpk"] += 1
                    c["bby"] += len(payload)
                if proto == 6:
                    c["syn"] += bool(flags & 0x02)
                    c["rst"] += bool(flags & 0x04)
                    if flags & 0x01:
                        c["fin"] += 1
                        c["fin_f" if forward else "fin_b"] = True
                    if forward and payload:
                        _http_payload(c, payload, ts, src, dst, dport, http, stats)
                    if flags & 0x04 or (c["fin_f"] and c["fin_b"]):
                        c["ended"] = True       # the last ACKs still belong to it: it is closed at the next SYN / end
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError, struct.error):
            stats["truncated"] = 1                      # a cut-off capture: keep what was read
        for key in list(live):
            close(key)
    done.sort(key=lambda f: f.ts or 0)
    http = [(ts, src, dst, dport, method, target, bytes(body).decode("latin-1"), head)
            for ts, src, dst, dport, method, target, body, head in http]
    return {"flows": done, "http": http, "stats": dict(stats)}


_CONTENT_LENGTH = re.compile(rb"\r\ncontent-length:\s*(\d{1,9})", re.I)
_MULTIPART = re.compile(rb"\r\ncontent-type:\s*multipart/", re.I)


def _http_payload(c: dict, payload: bytes, ts, src, dst, dport, http: list, stats) -> None:
    """(31 Oct) One forward TCP payload of a connection: a new HTTP request (any request of a keep-alive connection),
    or the next piece of the body of the request before it. Bodies are read up to MAX_BODY bytes; file uploads
    (multipart) are skipped. Nothing is decoded or run here."""
    m = _HTTP_START.match(payload[:4100])
    if m:
        c["req"] = None
        if len(http) >= MAX_HTTP:
            return
        head, sep, body = payload.partition(b"\r\n\r\n")
        entry = [ts, src, dst, dport, m.group(1).decode(), m.group(2).decode("latin-1"), bytearray(),
                 head[:8000].decode("latin-1")]             # (6 Nov) headers: attacks hidden there (Shellshock)
        http.append(entry)
        if m.group(1) in (b"POST", b"PUT", b"PATCH") and not _MULTIPART.search(head) \
                and stats["http_body_bytes"] < MAX_BODIES:
            cl = _CONTENT_LENGTH.search(head)
            want = min(int(cl.group(1)) if cl else MAX_BODY, MAX_BODY)
            if sep:
                entry[6] += body[:want]
                stats["http_body_bytes"] += len(body[:want])
            if len(entry[6]) < want:
                c["req"] = (entry, want, bool(sep))
        return
    pending = c.get("req")
    if pending:                                  # the rest of a request: more headers, or the body
        entry, want, in_body = pending
        if not in_body:
            _, sep, body = payload.partition(b"\r\n\r\n")
            if not sep:
                return
            payload, in_body = body, True
        piece = payload[:want - len(entry[6])]
        entry[6] += piece
        stats["http_body_bytes"] += len(piece)
        c["req"] = (entry, want, in_body) if len(entry[6]) < want else None


def _ip_layer(dpkt, link, buf):
    """(src, dst, protocol, layer-4 object) for Ethernet / Linux-cooked / raw-IP / loopback captures, else None."""
    try:
        if link == 1:                                     # Ethernet
            ip = dpkt.ethernet.Ethernet(buf).data
        elif link == 113:                                 # Linux cooked capture
            ip = dpkt.sll.SLL(buf).data
        elif link in (101, 12, 14, 228, 229):             # raw IP
            ip = dpkt.ip.IP(buf) if buf[:1] and buf[0] >> 4 == 4 else dpkt.ip6.IP6(buf)
        elif link in (0, 108):                            # BSD loopback
            ip = dpkt.loopback.Loopback(buf).data
        else:
            return None
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError, IndexError):
        return None
    if isinstance(ip, dpkt.ip.IP):
        return _ipstr(ip.src), _ipstr(ip.dst), ip.p, ip.data
    if isinstance(ip, dpkt.ip6.IP6):
        return _ipstr(ip.src), _ipstr(ip.dst), ip.nxt, ip.data
    return None


def _ipstr(raw: bytes) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return "?"


# ---------------------------------------------------------------------------------------------------------------
# behaviour
# ---------------------------------------------------------------------------------------------------------------
def _max_count(times) -> tuple[int, float | None, float | None]:
    """Most events inside any WINDOW_S window, and that window's first/last time (no times -> all together)."""
    ts = sorted(t for t in times if t is not None)
    best, bj, bk, j = 0, None, None, 0
    for k in range(len(ts)):
        while ts[k] - ts[j] > WINDOW_S:
            j += 1
        if k - j + 1 > best:
            best, bj, bk = k - j + 1, ts[j], ts[k]
    untimed = sum(1 for t in times if t is None)
    if untimed > best:
        return untimed, None, None
    return best, bj, bk


def _max_distinct(items) -> tuple[int, float | None, float | None]:
    """Most DIFFERENT values inside any WINDOW_S window. items: (time or None, value)."""
    timed = sorted((t, v) for t, v in items if t is not None)
    seen, best, bj, bk, j = Counter(), 0, None, None, 0
    for k, (t, v) in enumerate(timed):
        seen[v] += 1
        while t - timed[j][0] > WINDOW_S:
            u = timed[j][1]
            seen[u] -= 1
            if not seen[u]:
                del seen[u]
            j += 1
        if len(seen) > best:
            best, bj, bk = len(seen), timed[j][0], t
    untimed = len({v for t, v in items if t is None})
    if untimed > best:
        return untimed, None, None
    return best, bj, bk


def measure(flows) -> dict[str, dict[tuple, tuple[int, float | None, float | None, int]]]:
    """For every behaviour and every key (source or source->target): (largest burst in any window, window start,
    window end, number of connections). The training script uses this same function on the real data."""
    groups = {"port_scan": defaultdict(list), "host_sweep": defaultdict(list), "failed_flood": defaultdict(list),
              "brute_force": defaultdict(list), "dos_flood": defaultdict(list)}
    for f in flows:
        if f.proto == 6 and f.syn <= 0:
            continue                     # leftover packets of a connection, not a new one (no SYN seen)
        if f.proto == 6 or f.proto == 17:
            groups["port_scan"][(f.src, f.dst)].append((f.ts, f.dport))
        icmp_probe = f.proto in (1, 58) and f.bpk == 0 and f.sport not in ICMP_NOT_PROBE[f.proto]
        if (f.failed or icmp_probe) and _private(f.dst):                     # unanswered, internal target
            groups["host_sweep"][(f.src,)].append((f.ts, f.dst))
        if f.failed:
            groups["failed_flood"][(f.src,)].append(f.ts)
        if f.proto == 6 and f.dport in LOGIN_PORTS and not f.failed:      # guessing needs answered connections
            groups["brute_force"][(f.src, f.dst, f.dport)].append(f.ts)
        if f.proto == 6 and f.dport in WEB_PORTS:
            groups["dos_flood"][(f.src, f.dst, f.dport)].append(f.ts)
    out = {}
    for cat, g in groups.items():
        fn = _max_distinct if cat in ("port_scan", "host_sweep") else _max_count
        out[cat] = {k: (*fn(v), len(v)) for k, v in g.items()}
    return out


def _when(ts) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _describe(cat, key, burst, t0, t1, n) -> str:
    span = f" between {_when(t0)} and {_when(t1)} UTC" if t0 is not None else ""
    if cat == "port_scan":
        return f"{key[0]} tried {burst:,} different ports on {key[1]} within 10 minutes{span}."
    if cat == "host_sweep":
        return f"{key[0]} contacted {burst:,} different machines that did not answer within 10 minutes{span}."
    if cat == "failed_flood":
        return f"{key[0]} had {burst:,} unanswered or reset connections within 10 minutes{span}."
    if cat == "brute_force":
        return (f"{key[0]} opened {burst:,} connections to the {SERVICE.get(key[2], 'login')} service on "
                f"{key[1]}:{key[2]} within 10 minutes{span} ({n:,} in total).")
    if cat == "dos_flood":
        return (f"{key[0]} opened {burst:,} connections to the {SERVICE.get(key[2], 'web')} service on "
                f"{key[1]}:{key[2]} within 10 minutes{span} ({n:,} in total).")
    return ""


def incidents(flows, cfg: dict | None = None, http=None, measured=None) -> list[dict]:
    cfg = cfg or load_config()
    found = []
    measured = measured or measure(flows)
    scanned = {k for k, v in measured["port_scan"].items() if v[0] >= cfg.get("port_scan", 10**9)}
    for cat, by_key in measured.items():
        need = cfg.get(cat)
        for key, (burst, t0, t1, n) in by_key.items():
            if cat == "brute_force" and key[:2] in scanned:
                continue                 # login-port connections that are part of a port scan of that machine
            if need is not None and burst >= need:
                found.append({"category": cat, "key": key, "source": key[0], "burst": burst, "count": n,
                              "first": t0, "last": t1, "text": _describe(cat, key, burst, t0, t1, n)})
    back = defaultdict(list)
    for f in flows:
        if f.dport in BACKDOOR_PORTS and f.bpk > 0 and not f.failed:      # a refused probe is not a backdoor
            back[(f.src, f.dst, f.dport)].append(f.ts)
    for key, times in back.items():
        ts = [t for t in times if t is not None]
        found.append({"category": "backdoor_port", "key": key, "source": key[0], "burst": len(times),
                      "count": len(times), "first": min(ts) if ts else None, "last": max(ts) if ts else None,
                      "text": f"{key[0]} -> {key[1]}:{key[2]}, {len(times)} answered connection(s)."})
    calls = defaultdict(list)          # (6 Nov) refused / unanswered tries from an inside machine to a backdoor port
    for f in flows:
        if f.proto == 6 and f.syn > 0 and f.failed and f.dport in BACKDOOR_PORTS and _private(f.src) \
                and (f.src, f.dst) not in scanned:   # tries that are part of a port scan of that machine are the scan
            calls[(f.src, f.dst, f.dport)].append(f.ts)
    for key, times in calls.items():
        burst, t0, t1 = _max_count(times)
        if burst >= cfg.get("backdoor_callback", CALLBACK_ATTEMPTS):
            span = f" between {_when(t0)} and {_when(t1)} UTC" if t0 is not None else ""
            found.append({"category": "backdoor_callback", "key": key, "source": key[0], "burst": burst,
                          "count": len(times), "first": t0, "last": t1,
                          "text": f"{key[0]} tried {burst:,} times within 10 minutes{span} to reach {key[1]}:{key[2]} "
                                  f"and was refused or not answered ({len(times):,} tries in total)."})
    if http:
        from app.detectors import api_abuse
        hits = defaultdict(list)
        logins = defaultdict(list)
        for req in http:
            ts, src, dst, dport, method, target = req[:6]
            body = req[6] if len(req) > 6 else ""
            path, _, query = target.partition("?")
            types = api_abuse.attack_types(api_abuse.decode(api_abuse.request_text(path, query, body)).lower()) \
                + api_abuse.header_attack_types(req[7] if len(req) > 7 else "")
            if types:
                shown = target + (f"  [form: {body[:120]}]" if body else "")
                hits[(src, dst, dport)].append((ts, method, shown, [t[0] for t in types]))
            if _PASSWORD_FIELD.search("&" + query) or _PASSWORD_FIELD.search("&" + body):
                logins[(src, dst, dport, path.lower())].append(ts)
        for key, times in logins.items():             # (31 Oct) many guesses at one web login form
            burst, t0, t1 = _max_count(times)
            if burst >= cfg.get("web_login_guessing", WEB_LOGIN_GUESSES):
                found.append({"category": "web_login_guessing", "key": key[:3], "source": key[0], "burst": burst,
                              "count": len(times), "first": t0, "last": t1,
                              "text": f"{key[0]} -> {key[1]}:{key[2]}{key[3]}: {burst} login attempts within 10 "
                                      f"minutes ({len(times)} in total)."})
        for key, rows in hits.items():
            kinds = sorted({k for r in rows for k in r[3]})
            found.append({"category": "web_attack", "key": key, "source": key[0], "burst": len(rows),
                          "count": len(rows), "first": rows[0][0], "last": rows[-1][0],
                          "text": f"{key[0]} -> {key[1]}:{key[2]}: {len(rows)} request(s) with {', '.join(kinds)}, "
                                  f"e.g. {rows[0][1]} {rows[0][2][:150]}"})
    found.sort(key=lambda f: (_ORDER.index(f["category"]), -f["burst"]))
    return found


# ---------------------------------------------------------------------------------------------------------------
# supporting per-connection model
# ---------------------------------------------------------------------------------------------------------------
_SVC = [({80, 8080, 8000, 8888}, 1), ({443}, 2), ({53}, 3), ({22}, 4), ({21}, 5), ({25, 587, 465, 110, 143, 993, 995}, 6),
        ({445, 139, 135, 137, 138}, 7), ({3389}, 8), ({123}, 9)]


def service_class(port: int) -> int:
    for ports, c in _SVC:
        if port in ports:
            return c
    return 10 if port < 1024 else 11 if port < 49152 else 12


def features(f: Flow) -> list[float]:
    """Exactly the columns the model was trained on (train_network_traffic.py builds them with this function)."""
    return [service_class(f.dport), f.proto, math.log1p(max(f.dur, 0)), math.log1p(max(f.fpk, 0)),
            math.log1p(max(f.bpk, 0)), math.log1p(max(f.fby, 0)), math.log1p(max(f.bby, 0)), f.syn, f.rst, f.fin]


def load_model():
    try:
        mtime = _stamp(MODEL_PATH)
    except OSError:
        return None
    if _CACHE["model_mtime"] != mtime:
        try:
            import joblib
            _CACHE["model"] = joblib.load(MODEL_PATH)
        except Exception:                 # noqa: BLE001 - a broken model file never breaks a scan
            _CACHE["model"] = None
        _CACHE["model_mtime"] = mtime
    return _CACHE["model"]


def model_assessment(flows) -> dict | None:
    """Share of connections the supporting model flags (only flows with full CICFlowMeter-style detail)."""
    bundle = load_model()
    rich = [f for f in flows if f.rich]
    if not bundle or not rich:
        return None
    import numpy as np
    X = np.asarray([features(f) for f in rich], dtype=np.float32)
    p = bundle["model"].predict_proba(X)[:, 1]
    flagged = p >= bundle["threshold"]
    by_src = Counter(f.src for f, fl in zip(rich, flagged) if fl)
    return {"connections": len(rich), "flagged": int(flagged.sum()),
            "share": round(float(flagged.mean()), 4), "topSources": by_src.most_common(5)}


# ---------------------------------------------------------------------------------------------------------------
# whole-input summary
# ---------------------------------------------------------------------------------------------------------------
def summarize(fmt: str, flows: list[Flow], http=None, stats=None, cfg=None) -> dict:
    cfg = cfg or load_config()
    inc = incidents(flows, cfg, http=http)
    groups = defaultdict(list)
    for f in inc:
        groups[f["category"]].append(f)
    out = []
    for cat, fs in groups.items():
        label, sev, weight, mitre, desc = CATEGORY[cat]
        sources = list(dict.fromkeys(f["source"] for f in fs))
        examples = " ".join(f["text"] for f in fs[:3]) + (f" (+{len(fs) - 3} more)" if len(fs) > 3 else "")
        out.append({"category": cat, "label": label, "severity": sev, "weight": weight, "mitre": mitre,
                    "description": f"{desc} {examples}", "connections": sum(f["count"] for f in fs),
                    "sources": sources[:20], "targets": list(dict.fromkeys(str(f["key"][1]) for f in fs
                                                                            if len(f["key"]) > 1))[:20]})
    times = [f.ts for f in flows if f.ts is not None]
    talkers = Counter(f.src for f in flows)
    return {"format": fmt, "connections": len(flows), "httpRequests": len(http or []),
            "timeRange": [_when(min(times)), _when(max(times))] if times else None,
            "sources": len(talkers), "targets": len({f.dst for f in flows}),
            "topTalkers": [{"address": a, "connections": n, "internal": _private(a)} for a, n in talkers.most_common(5)],
            "incidents": out, "details": [{k: v for k, v in f.items() if k != "key"} for f in inc[:30]],
            "model": model_assessment(flows), "thresholds": cfg, "readStats": stats or {}}


def analyze_text(text: str, cfg=None) -> dict | None:
    got = read_text(text)
    if not got or len(got[1]) < 3:
        return None
    return summarize(got[0], got[1], cfg=cfg)


def analyze_capture(path: str, cfg=None) -> dict:
    cap = read_capture(path)
    return summarize("packet capture", cap["flows"], http=cap["http"], stats=cap["stats"], cfg=cfg)
