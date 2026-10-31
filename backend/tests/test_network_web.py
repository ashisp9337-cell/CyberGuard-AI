"""Upgrade #6 (31 Oct): web attacks in packet captures - SQL injection / XSS sent in a POST form body (also when the
body arrives in a later TCP segment), every request of a keep-alive connection, and password guessing against a web
login form. Captures are built here from harmless test packets."""
import pytest

dpkt = pytest.importorskip("dpkt")

from app.detectors import network_traffic as NT  # noqa: E402
from test_network_traffic import CFG, _pkt, _write  # noqa: E402

S, A, F, P = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN, dpkt.tcp.TH_PUSH
C, SRV = "10.0.0.66", "10.0.0.5"


def _conn(t, cport, segments, client=C):
    """One TCP connection that sends the given payload segments, then closes."""
    pk = [(t, _pkt(client, SRV, cport, 80, S)), (t + .001, _pkt(SRV, client, 80, cport, S | A)),
          (t + .002, _pkt(client, SRV, cport, 80, A))]
    for i, seg in enumerate(segments):
        pk.append((t + .003 + i / 1000, _pkt(client, SRV, cport, 80, P | A, seg)))
    pk += [(t + .5, _pkt(SRV, client, 80, cport, P | A, b"HTTP/1.1 200 OK\r\n\r\nok")),
           (t + .6, _pkt(client, SRV, cport, 80, F | A)), (t + .7, _pkt(SRV, client, 80, cport, F | A)),
           (t + .8, _pkt(client, SRV, cport, 80, A))]
    return pk


def _post(path, body, extra=b""):
    return (b"POST %s HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            b"%sContent-Length: %d\r\n\r\n" % (path, extra, len(body)), body)


def _cats(tmp_path, pk, name="c.pcap"):
    _write(tmp_path / name, pk)
    return {i["category"] for i in NT.analyze_capture(str(tmp_path / name), CFG)["incidents"]}


def test_sql_injection_in_a_post_body_split_over_two_segments(tmp_path):
    head, body = _post(b"/search", b"q=shoes%27+UNION+SELECT+username%2Cpassword+FROM+users--")
    assert "web_attack" in _cats(tmp_path, _conn(1_700_000_000, 50000, [head, body]))
    cap = NT.read_capture(str(tmp_path / "c.pcap"))
    assert cap["http"][0][6].startswith("q=shoes")                      # the body was put back together


def test_attack_in_the_third_request_of_a_keep_alive_connection(tmp_path):
    reqs = [b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /item?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: x\r\n\r\n"]
    assert "web_attack" in _cats(tmp_path, _conn(1_700_000_000, 50001, reqs))


def test_normal_form_post_is_quiet(tmp_path):
    head, body = _post(b"/checkout", b"name=Ravi+Kumar&city=Bhubaneswar&qty=2")
    assert _cats(tmp_path, _conn(1_700_000_000, 50002, [head + body])) == set()


def test_file_uploads_are_not_read(tmp_path):
    head = (b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=zz\r\n"
            b"Content-Length: 40\r\n\r\n")
    _write(tmp_path / "u.pcap", _conn(1_700_000_000, 50003, [head + b"--zz\r\n' OR '1'='1 binary stuff\r\n--zz--"]))
    assert NT.read_capture(str(tmp_path / "u.pcap"))["http"][0][6] == ""


def _logins(n, clients=1, step=3.0):
    pk = []
    for i in range(n):
        head, body = _post(b"/login.php", b"user=admin&password=guess%d" % i)
        pk += _conn(1_700_000_000 + i * step, 40000 + i, [head + body], client=f"10.0.1.{1 + i % clients}")
    return pk


def test_password_guessing_at_a_web_login_form(tmp_path):
    assert "web_login_guessing" in _cats(tmp_path, _logins(30), "g.pcap")


def test_a_person_mistyping_or_many_users_logging_in_is_not_guessing(tmp_path):
    assert "web_login_guessing" not in _cats(tmp_path, _logins(5), "few.pcap")
    assert "web_login_guessing" not in _cats(tmp_path, _logins(40, clients=40), "users.pcap")


def test_request_bodies_have_a_memory_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(NT, "MAX_BODIES", 100)
    pk = []
    for i in range(5):
        head, body = _post(b"/f", b"x=" + b"a" * 90)
        pk += _conn(1_700_000_000 + i, 51000 + i, [head + body])
    _write(tmp_path / "m.pcap", pk)
    bodies = [r[6] for r in NT.read_capture(str(tmp_path / "m.pcap"))["http"]]
    assert sum(len(b) for b in bodies) <= 100 + 92 and bodies[-1] == ""
