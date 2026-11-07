r"""Test the web-attack checks of the network-capture engine (app/detectors/network_traffic.py) on REAL HTTP requests.

CIC-IDS2017's flow records have no request contents, so they cannot show whether attack code inside HTTP is found.
This test uses the CSIC 2010 HTTP dataset (real requests to an e-commerce site: 36,000 normal + 25,065 anomalous /
attack requests, many of them POST forms) and packs every request into a real TCP conversation in a .pcap file -
the request is split into 1,448-byte TCP segments exactly as it would travel - then reads the file with the same
code as an uploaded Wireshark capture. Each browser session (JSESSIONID) gets its own client address.

It measures, for the anomalous requests: how many are reported as a web attack when only the request line is read
(the engine before 31 Oct) and when the POST form body is read too (now); and for the normal requests: how many are
wrongly reported, and whether normal logins ever look like password guessing. Then one client guessing passwords
at the login form (the CSIC login request with changing passwords) must be reported, and 5 tries must not.
Uses the CSIC files that train_api_abuse.py --download already fetched (SHA-256 checked):
    python -I app\ml\training\test_network_web.py
Writes app/ml/models/network_web.json. Temporary .pcap files are written to a new temporary folder and deleted.
"""
import hashlib
import json
import os
import re
import shutil
import socket
import sys
import tempfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))   # the backend folder (python -I ignores cwd)

import dpkt  # noqa: E402

from app.detectors import network_traffic as NT  # noqa: E402

DATA = os.path.join(HERE, "data", "api_abuse")
OUT = os.path.join(HERE, "..", "models", "network_web.json")
SERVER = "10.10.0.80"
CHUNK = 4000                     # requests per temporary capture file


def read_requests(path):
    """Raw CSIC requests -> [(bytes of the whole request as sent, session id)]: origin-form request line, headers, body."""
    with open(path, "rb") as f:
        raw = f.read().replace(b"\r\n", b"\n")
    out = []
    starts = [m.start() for m in re.finditer(rb"^(GET|POST|PUT) http", raw, re.M)]
    for a, z in zip(starts, starts[1:] + [len(raw)]):
        block = raw[a:z].strip(b"\n")
        if not block:
            continue
        head, _, body = block.partition(b"\n\n")
        lines = head.split(b"\n")
        method, _, rest = lines[0].partition(b" ")
        target, _, version = rest.rpartition(b" ")
        if target.startswith(b"http://"):
            target = b"/" + target.split(b"/", 3)[3] if target.count(b"/") >= 3 else b"/"
        sid = next((ln.split(b"=", 1)[1] for ln in lines if ln.lower().startswith(b"cookie:") and b"=" in ln), b"")
        headers = [ln for ln in lines[1:] if not ln.lower().startswith(b"content-length")]
        body = body.strip(b"\n")
        if body:
            headers.append(b"Content-Length: %d" % len(body))
        req = b"\r\n".join([method + b" " + target + b" " + version] + headers) + b"\r\n\r\n" + body
        out.append((req, sid))
    return out


def _pkt(src, dst, sport, dport, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=tcp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6, type=0x0800, data=ip))


def _client(sid: bytes) -> str:
    h = hashlib.sha1(sid or os.urandom(8)).digest()
    return f"172.20.{h[0]}.{max(h[1], 1)}"


def write_capture(path, requests, t0=1_700_000_000.0, step=2.0):
    S, A, F, P = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN, dpkt.tcp.TH_PUSH
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for i, (req, client) in enumerate(requests):
            t, cport = t0 + i * step, 20000 + i % 40000
            pk = [(t, _pkt(client, SERVER, cport, 80, S)), (t + .001, _pkt(SERVER, client, 80, cport, S | A)),
                  (t + .002, _pkt(client, SERVER, cport, 80, A))]
            for j in range(0, len(req), 1448):              # the request in real-sized TCP segments
                pk.append((t + .003 + j / 1e7, _pkt(client, SERVER, cport, 80, P | A, req[j:j + 1448])))
            pk += [(t + .01, _pkt(SERVER, client, 80, cport, P | A, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
                   (t + .011, _pkt(client, SERVER, cport, 80, F | A)), (t + .012, _pkt(SERVER, client, 80, cport, F | A)),
                   (t + .013, _pkt(client, SERVER, cport, 80, A))]
            for ts, buf in pk:
                w.writepkt(buf, ts=ts)


def judge(requests, tmp, step=2.0):
    """-> (requests read, requests with attack code: line only, line + body, incident categories)."""
    from app.detectors import api_abuse
    read = line_hits = full_hits = 0
    cats = Counter()
    for k in range(0, len(requests), CHUNK):
        path = os.path.join(tmp, f"part{k}.pcap")
        write_capture(path, requests[k:k + CHUNK], t0=1_700_000_000.0 + k * step, step=step)
        cap = NT.read_capture(path)
        os.remove(path)
        read += len(cap["http"])
        for ts, src, dst, dport, method, target, body, _headers in cap["http"]:
            p, _, q = target.partition("?")
            line_hits += bool(api_abuse.attack_types(api_abuse.decode(api_abuse.request_text(p, q)).lower()))
            full_hits += bool(api_abuse.attack_types(api_abuse.decode(api_abuse.request_text(p, q, body)).lower()))
        cats.update(i["category"] for i in NT.incidents(cap["flows"], http=cap["http"]))
    return read, line_hits, full_hits, cats


def main():
    files = {k: os.path.join(DATA, f"csic_{k}TrafficTest.txt") for k in ("anomalous", "normal")}
    if not all(os.path.exists(p) for p in files.values()):
        sys.exit("CSIC files not found: run  python -m app.ml.training.train_api_abuse --download  first.")
    tmp = tempfile.mkdtemp(prefix="cg_netweb_")
    res = {}
    try:
        for kind, path in files.items():
            reqs = [(r, _client(sid)) for r, sid in read_requests(path)]
            posts = sum(r.startswith(b"POST") for r, _ in reqs)
            read, line_hits, full_hits, cats = judge(reqs, tmp)
            res[kind] = {"requests": len(reqs), "post_requests": posts, "read_from_capture": read,
                         "attack_code_found_request_line_only": line_hits,
                         "attack_code_found_with_form_body": full_hits, "incidents": dict(cats)}
            print(f"{kind:9s} {len(reqs):6,} requests ({posts:,} POST): read from the capture {read:,}; attack code "
                  f"found - request line only {line_hits:,}, with the form body {full_hits:,}; incidents {dict(cats)}")
        # password guessing: the CSIC login form, one client, many passwords - and a person who mistypes 5 times
        login = next(r for r, _ in read_requests(files["normal"]) if b"autenticar.jsp" in r and r.startswith(b"POST"))
        head, _, body = login.partition(b"\r\n\r\n")
        guess = []
        for n in (60, 5):
            reqs = []
            for i in range(n):
                b = body.replace(b"pwd=", b"pwd=guess%d" % i, 1)
                h = b"\r\n".join(ln for ln in head.split(b"\r\n") if not ln.lower().startswith(b"content-length"))
                reqs.append((h + b"\r\nContent-Length: %d\r\n\r\n" % len(b) + b, "172.20.99.99"))
            _, _, _, cats = judge(reqs, tmp, step=3.0)
            guess.append({"attempts": n, "reported": cats.get("web_login_guessing", 0) > 0})
            print(f"one client, {n} login attempts in {n * 3} s: password guessing reported = {guess[-1]['reported']}")
        res["login_guessing"] = guess
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    print(f"wrote {os.path.abspath(OUT)}")


if __name__ == "__main__":
    main()
