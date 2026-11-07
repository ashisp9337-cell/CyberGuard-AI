"""
Step 4a - Attachment scanner (feeds the Cyber Threat / malware module).

Static checks only - nothing is ever opened or executed:
  * dangerous file types (.exe, .js, .lnk, .iso, .html ...)
  * double extensions (invoice.pdf.exe) and right-to-left-override tricks
  * file content that does not match its extension (an .exe renamed .pdf)
  * archives: password-protected zips, risky files inside
  * Office macros (OOXML vbaProject.bin, legacy OLE _VBA_PROJECT; oletools if installed)
  * PDFs: JavaScript, auto-open actions, launch actions, embedded files, links
  * HTML/SVG attachments: login forms, scripts, redirects
  * SHA-256 lookup on VirusTotal (only when VIRUSTOTAL_API_KEY is set)
  * (30 Oct) the EICAR antivirus test file (also inside a zip), files inside a zip disguised with a double extension
    (holiday/IMG_001.jpg.exe), and what scripts would do if run (app/detectors/script_checks.py) - also for
    scripts inside a zip

Returns a CYBERGUARD result dict plus "extracted_links" (links found inside
PDFs/HTML attachments, which the orchestrator sends to the URL engine) and
"qr_images" (attachment images to try for QR codes).
"""
import io
import os
import re
import uuid
import zipfile

from app.detectors import container_files, script_checks
from app.detectors.base import build_result
from app.email_pipeline.schemas import Attachment

EXECUTABLE_EXT = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".msp", ".js", ".jse", ".vbs",
                  ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".lnk", ".jar", ".cpl", ".dll", ".reg",
                  ".apk", ".appx", ".msix", ".sh", ".py", ".chm", ".scf", ".url", ".gadget", ".xll"}
CONTAINER_EXT = {".iso", ".img", ".vhd", ".vhdx", ".udf"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace", ".arj"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppsm"}
WEB_EXT = {".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml"}
OFFICE_EXT = {".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".rtf"} | MACRO_EXT
COMPRESSED_EXT = {".gz", ".bz2", ".xz", ".zst"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".csv", ".ppt", ".pptx"}

MAGIC = [
    (b"MZ", "windows-executable"),
    (b"\x7fELF", "linux-executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
]
EXT_FAMILY = {".pdf": "pdf", ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif",
              ".zip": "zip", ".docx": "zip", ".xlsx": "zip", ".pptx": "zip", ".docm": "zip", ".xlsm": "zip",
              ".doc": "ole", ".xls": "ole", ".ppt": "ole", ".msi": "ole", ".exe": "windows-executable",
              ".dll": "windows-executable", ".scr": "windows-executable", ".rar": "rar", ".7z": "7z"}
URL_RE = re.compile(rb"""https?://[^\s<>"'\)\]\\]+""", re.I)
PDF_URI_RE = re.compile(rb"/URI\s*\(([^)]+)\)")
# The harmless EICAR antivirus test string, built from two halves so this source file itself never contains it whole
# (an antivirus such as Windows Defender could otherwise quarantine this file).
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE!$H+H*"
MAX_INNER_SCRIPT = 1024 * 1024        # scripts inside a zip are read (in memory) up to this size
RTLO = "\u202e"   # Right-To-Left Override: makes "invoice\u202efdp.exe" display as "invoiceexe.pdf"


def _magic(data: bytes) -> str:
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    return ""


def _exts(filename: str) -> list[str]:
    name = filename.lower().replace(RTLO, "")
    parts = name.split(".")
    return ["." + p.strip() for p in parts[1:]] if len(parts) > 1 else []


def _ind(triggered, label, description, severity, weight, mitre=None):
    return {"id": f"IND_{uuid.uuid4().hex[:12]}", "label": label, "description": description,
            "severity": severity, "weight": weight, "triggered": bool(triggered),
            "source": "attachment", "mitre": mitre}


def is_eicar(data: bytes) -> bool:
    """The EICAR test file: the 68-character string at the start, optionally followed by whitespace (max 128 bytes)."""
    return data.startswith(EICAR) and len(data) <= 128 and not data[len(EICAR):].strip()


def _disguised(filename: str) -> bool:
    """photo.jpg.exe / invoice\u202efdp.exe: a harmless-looking name hiding a program."""
    exts = _exts(filename.rsplit("/", 1)[-1])
    risky = EXECUTABLE_EXT | CONTAINER_EXT | MACRO_EXT | WEB_EXT
    return RTLO in filename or (len(exts) >= 2 and exts[-2] in DECOY_EXT and exts[-1] in risky)


_SCRIPTISH = re.compile(rb"<hta:application|<script|wscript\.|createobject\(|powershell|@echo off|cmd(\.exe)? /c|"
                        rb"mshta|rundll32|#@~\^", re.I)


def container_members(data: bytes, name: str = "") -> tuple[str, list[tuple[str, bytes]]]:
    """(what it is, [(inner name, bytes)]) for disk images, OneNote notebooks, tar / tar.gz and .gz files - read in
    memory only (zip files are handled separately). ("", []) for anything else."""
    if container_files.is_iso(data):
        return "disk image", container_files.iso_files(data)
    if container_files.is_onenote(data):
        return "OneNote notebook", [(f"embedded file {i + 1}", b)
                                    for i, b in enumerate(container_files.onenote_files(data))]
    if data[257:262] == b"ustar" or data[:2] == b"\x1f\x8b":
        tar = container_files.tar_files(data)
        if tar:
            return "archive", tar
        g = container_files.gzip_inner(data)
        if g:                                  # no stored name: the packed file is the .gz name without ".gz"
            return "archive", [(g[0] or (name[:-3] if name.lower().endswith(".gz") else "packed file"), g[1])]
    return "", []


def _has_macros(name: str, data: bytes) -> bool:
    try:
        from oletools.olevba import VBA_Parser  # optional, more thorough
        vp = VBA_Parser(name, data=data)
        found = vp.detect_vba_macros()
        vp.close()
        return bool(found)
    except Exception:
        pass
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                return any(n.lower().endswith("vbaproject.bin") for n in z.namelist())
        except Exception:
            return False
    return b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data[:500000]


def _vt_hash_lookup(sha256: str) -> dict:
    try:
        from app.core.config import get_settings
        key = get_settings().VIRUSTOTAL_API_KEY
    except Exception:
        key = ""
    if not key:
        return {"status": "unavailable"}
    try:
        import httpx
        r = httpx.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key}, timeout=6.0)
        if r.status_code == 404:
            return {"status": "not_found"}
        r.raise_for_status()
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"status": "ok", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except Exception as e:
        return {"status": "error", "reason": str(e)[:120]}


def scan_attachment(att: Attachment, *, network: bool = True) -> dict:
    """Scan one attachment. Returns {indicators, extracted_links, qr_candidates, details}."""
    name = att.filename or "unnamed"
    data = att.data or b""
    exts = _exts(name)
    last = exts[-1] if exts else ""
    magic = _magic(data)
    ind: list[dict] = []
    links: list[str] = []
    qr_candidates: list[tuple[str, bytes]] = []
    details = {"filename": name, "size": att.size, "sha256": att.sha256, "detected_type": magic or att.content_type}

    # -- file type -------------------------------------------------------------
    ind.append(_ind(last in EXECUTABLE_EXT or magic in ("windows-executable", "linux-executable"),
                    "Executable or script attachment",
                    f"'{name}' is a program/script. Opening it runs code on the computer.", "critical", 45, "T1204.002"))
    ind.append(_ind(last in CONTAINER_EXT, "Disk-image attachment",
                    f"'{name}' is a disk image (.iso/.img/.vhd), used to smuggle malware past email filters.",
                    "high", 30, "T1553.005"))
    # ("report.csv.gz" is the normal name of a compressed file, not a disguise - the file inside is checked below)
    ind.append(_ind(len(exts) >= 2 and exts[-2] in DECOY_EXT and last not in DECOY_EXT | COMPRESSED_EXT,
                    "Double file extension",
                    f"'{name}' pretends to be a {exts[-2] if len(exts) >= 2 else ''} file but is really {last}.",
                    "critical", 35, "T1036.007"))
    ind.append(_ind(RTLO in name, "Hidden reversed filename",
                    "The filename uses an invisible right-to-left character to disguise its real extension.",
                    "critical", 35, "T1036.002"))
    if is_eicar(data):
        ind.append(_ind(True, "EICAR antivirus test file",
                        "This is the standard, harmless EICAR test file that every antivirus is expected to flag. It is "
                        "not real malware - CyberGuard treats it like malware so you can test the alerts and quarantine.",
                        "high", 71, "T1204.002"))
    floor = 0
    if last in script_checks.SCRIPT_EXT:
        found, floor = script_checks.check(name, data)
        ind += found
    expected = EXT_FAMILY.get(last)
    ind.append(_ind(bool(expected and magic and expected != magic and not (expected == "zip" and magic == "zip")),
                    "File content does not match its extension",
                    f"'{name}' is named {last} but its content is {magic}.", "critical", 35, "T1036.008"))

    # -- archives ----------------------------------------------------------------
    if magic == "zip" and last not in OFFICE_EXT:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()
                encrypted = any(i.flag_bits & 0x1 for i in infos)
                inner = [i.filename for i in infos]
                risky_inner = [n for n in inner if os.path.splitext(n.lower())[1] in EXECUTABLE_EXT | CONTAINER_EXT | MACRO_EXT | WEB_EXT]
                details["archive_files"] = inner[:30]
                ind.append(_ind(encrypted, "Password-protected archive",
                                "The archive is encrypted so security scanners cannot look inside — a common malware "
                                "delivery trick (the password is usually in the email body).", "high", 30, "T1027.013"))
                ind.append(_ind(bool(risky_inner), "Dangerous file inside archive",
                                f"Contains {', '.join(risky_inner[:3])}.", "critical", 40, "T1204.002"))
                disguised = [n for n in inner if _disguised(n)]
                ind.append(_ind(bool(disguised), "Disguised file inside archive",
                                f"Contains {', '.join(disguised[:3])}: a program dressed up with a harmless-looking "
                                "name (double extension or reversed text). Real photos and documents never do this.",
                                "critical", 40, "T1036.007"))
                eicar_inner, script_found = [], []
                for i in infos[:200]:
                    if i.is_dir() or i.flag_bits & 0x1:
                        continue
                    ext = os.path.splitext(i.filename.lower())[1]
                    if i.file_size <= 128:
                        with z.open(i) as f:
                            if is_eicar(f.read(129)):
                                eicar_inner.append(i.filename)
                    elif ext in script_checks.SCRIPT_EXT and i.file_size <= MAX_INNER_SCRIPT and len(script_found) < 10:
                        with z.open(i) as f:          # read in memory only - nothing is written to disk
                            found, fl = script_checks.check(i.filename, f.read(MAX_INNER_SCRIPT))
                        for s in found:
                            s["label"] = f"Inside archive: {s['label']}"
                            s["description"] = f"{i.filename}: {s['description']}"
                        script_found += found
                        floor = max(floor, fl)
                ind.append(_ind(bool(eicar_inner), "EICAR antivirus test file",
                                f"The archive contains the harmless EICAR antivirus test file ({', '.join(eicar_inner[:2])})"
                                " - treated like malware so you can test the alerts and quarantine.", "high", 71,
                                "T1204.002"))
                ind += script_found
        except zipfile.BadZipFile:
            ind.append(_ind(True, "Corrupted archive", "The archive could not be opened.", "medium", 10))
    elif magic != "zip":
        # -- (30 Oct) disk images, OneNote notebooks, tar / gz: the files inside, read in memory --------------
        ckind, members = container_members(data, name)
        if ckind:
            names = [n for n, _ in members]
            details["archive_files"] = names[:30]
            details["container"] = ckind
            risky_ext = EXECUTABLE_EXT | CONTAINER_EXT | MACRO_EXT | WEB_EXT
            # a OneNote page normally holds pictures; a program or a script hidden in it is the attack
            dangerous = [n for n, b in members if os.path.splitext(n.lower())[1] in risky_ext
                         or b[:2] == b"MZ" or b[:4] == b"\x7fELF"
                         or (ckind == "OneNote notebook" and _SCRIPTISH.search(b[:200000] or b""))]
            ind.append(_ind(bool(dangerous), "Dangerous file inside archive",
                            f"The {ckind} contains {', '.join(dangerous[:3])} - a program or script. Opening it "
                            "runs code.", "critical", 40, "T1204.002"))
            disguised = [n for n in names if _disguised(n)]
            ind.append(_ind(bool(disguised), "Disguised file inside archive",
                            f"The {ckind} contains {', '.join(disguised[:3])}: a program dressed up with a "
                            "harmless-looking name. Real photos and documents never do this.", "critical", 40,
                            "T1036.007"))
            eicar_inner, script_found = [], []
            for n, b in members:
                ext = os.path.splitext(n.lower())[1]
                if is_eicar(b):
                    eicar_inner.append(n)
                elif len(script_found) < 10 and (ext in script_checks.SCRIPT_EXT or (
                        ckind == "OneNote notebook" and _SCRIPTISH.search(b[:200000]))):
                    found, fl = script_checks.check(n, b[:MAX_INNER_SCRIPT])
                    for s in found:
                        s["label"] = f"Inside archive: {s['label']}"
                        s["description"] = f"{n}: {s['description']}"
                    script_found += found
                    floor = max(floor, fl)
            ind.append(_ind(bool(eicar_inner), "EICAR antivirus test file",
                            f"The {ckind} contains the harmless EICAR antivirus test file - treated like malware so "
                            "you can test the alerts and quarantine.", "high", 71, "T1204.002"))
            ind += script_found
        elif last in ARCHIVE_EXT:
            ind.append(_ind(True, "Archive attachment (not inspected)",
                            f"'{name}' is a {last} archive that this scanner cannot open (RAR / 7-Zip need extra "
                            "tools) - treat with caution and scan the files inside after unpacking.", "medium", 12))

    # -- Office macros -----------------------------------------------------------
    if last in OFFICE_EXT or magic == "ole":
        has_macro = _has_macros(name, data)
        ind.append(_ind(has_macro or last in MACRO_EXT, "Office document with macros",
                        f"'{name}' contains VBA macros, which can download and run malware when enabled.",
                        "critical", 40, "T1204.002"))

    # -- PDF ----------------------------------------------------------------------
    if magic == "pdf" or last == ".pdf":
        js = b"/JavaScript" in data or b"/JS" in data
        auto = b"/OpenAction" in data or b"/AA" in data
        ind.append(_ind(js, "PDF contains JavaScript",
                        "The PDF carries JavaScript, which legitimate documents almost never need.", "high", 25, "T1204.002"))
        ind.append(_ind(b"/Launch" in data, "PDF launch action",
                        "The PDF tries to start another program when opened.", "critical", 35, "T1204.002"))
        ind.append(_ind(b"/EmbeddedFile" in data, "File hidden inside PDF",
                        "Another file is embedded inside this PDF.", "high", 20, "T1027.009"))
        ind.append(_ind(js and auto, "PDF runs code automatically",
                        "JavaScript is set to run as soon as the PDF opens.", "critical", 20, "T1204.002"))
        for u in PDF_URI_RE.findall(data)[:20]:  # clickable link annotations only
            links.append(u.decode("latin-1", errors="ignore"))
        # Render pages to images for QR detection (needs PyMuPDF; skipped if missing)
        try:
            try:
                import pymupdf as fitz  # PyMuPDF >= 1.24
            except ImportError:
                import fitz  # older PyMuPDF
            doc = fitz.open(stream=data, filetype="pdf")
            for i, page in enumerate(doc):
                if i >= 3:
                    break
                qr_candidates.append((f"{name}#page{i + 1}", page.get_pixmap(dpi=150).tobytes("png")))
            doc.close()
        except Exception:
            details["pdf_qr_scan"] = "skipped (install pymupdf to scan QR codes inside PDFs)"

    # -- HTML / SVG -----------------------------------------------------------------
    if last in WEB_EXT or att.content_type in ("text/html", "image/svg+xml"):
        text = data.decode("utf-8", errors="ignore").lower()
        has_pw_form = "<form" in text and ("type=\"password\"" in text or "type='password'" in text or "password" in text)
        has_script = "<script" in text
        obfuscated = any(k in text for k in ("atob(", "unescape(", "eval(", "fromcharcode", "document.write("))
        redirect = any(k in text for k in ("window.location", "location.href", "location.replace", "http-equiv=\"refresh\""))
        # (30 Oct) HTML smuggling: the page builds a file inside the browser from hidden data and "downloads" it,
        # so the file never crosses the e-mail / web filter (MITRE T1027.006)
        smuggling = (any(k in text for k in ("new blob", "mssaveoropenblob", "mssaveblob", "url.createobjecturl"))
                     and any(k in text for k in ("atob(", "base64", "uint8array", "charcodeat"))
                     and any(k in text for k in (".download=", ".download =", " download=", "setattribute(\"download",
                                                 "setattribute('download", "mssaveoropenblob", "mssaveblob")))
        ind.append(_ind(True, "HTML/SVG attachment",
                        f"'{name}' is a web page sent as a file — opens locally in the browser, bypassing URL "
                        "filters. Banks and services do not send these.", "high", 22, "T1566.001"))
        ind.append(_ind(has_pw_form, "Login form inside attachment",
                        "The attached page asks for a password — a credential-harvesting page.", "critical", 35, "T1056.003"))
        ind.append(_ind(has_script and obfuscated, "Obfuscated script in attachment",
                        "Encoded JavaScript is used to hide what the page does (HTML smuggling).", "critical", 30, "T1027.006"))
        ind.append(_ind(smuggling, "Page builds and downloads a hidden file (HTML smuggling)",
                        "The page assembles a file from hidden (Base64) data inside your browser and saves it - a way "
                        "to deliver malware past e-mail and web filters.", "critical", 35, "T1027.006"))
        ind.append(_ind(redirect, "Attachment redirects to a website",
                        "The page forwards the browser to another site as soon as it opens.", "high", 18, "T1566.001"))
        for u in URL_RE.findall(data)[:20]:
            links.append(u.decode("utf-8", errors="ignore"))

    # -- images: candidates for QR codes -------------------------------------------------
    if magic in ("png", "jpeg", "gif") or att.content_type.startswith("image/"):
        qr_candidates.append((name, data))

    # -- hash reputation -------------------------------------------------------------
    if network:
        vt = _vt_hash_lookup(att.sha256)
        details["virustotal"] = vt
        if vt.get("status") == "ok":
            ind.append(_ind(vt["malicious"] >= 3, "Known malware (VirusTotal)",
                            f"{vt['malicious']} antivirus engines flag this file (SHA-256 {att.sha256[:16]}…).",
                            "critical", 60, "T1204.002"))

    return {"indicators": ind, "extracted_links": list(dict.fromkeys(links)), "qr_candidates": qr_candidates,
            "details": details, "floor": floor}


def scan_attachments(attachments: list[Attachment], *, network: bool = True) -> dict:
    """Scan every non-inline attachment and return one CYBERGUARD result."""
    real = [a for a in attachments if not (a.is_inline and a.content_type.startswith("image/"))]
    all_ind, links, qrs, details, floor = [], [], [], [], 0
    for a in attachments:
        if a in real:
            r = scan_attachment(a, network=network)
            for i in r["indicators"]:
                if i["triggered"]:
                    i["label"] = f"{i['label']} — {a.filename}"
            all_ind += r["indicators"]
            links += r["extracted_links"]
            qrs += r["qr_candidates"]
            details.append(r["details"])
            floor = max(floor, r.get("floor", 0))
        elif a.content_type.startswith("image/"):
            qrs.append((a.filename, a.data))

    triggered = [i for i in all_ind if i["triggered"]]
    # a strong script finding (e.g. hidden Base64 command) justifies a minimum score of its own
    score = min(100, max(sum(i["weight"] for i in triggered), floor))
    if not real:
        explanation = "No attachments."
    elif triggered:
        top = sorted(triggered, key=lambda i: -i["weight"])[:3]
        explanation = f"{len(triggered)} attachment risk(s): " + "; ".join(i["label"] for i in top) + "."
    else:
        explanation = f"{len(real)} attachment(s) checked; no dangerous file types, macros or scripts found."
    result = build_result(indicators=all_ind, base_score=score, confidence=85 if real else 0,
                          engine_name="CYBERGUARD Attachment Scanner — Static Analysis",
                          threat_type="Malicious Attachment", explanation=explanation)
    result["extracted_links"] = list(dict.fromkeys(links))
    result["qr_candidates"] = qrs
    result["attachments"] = details
    result["attachment_count"] = len(real)
    return result
