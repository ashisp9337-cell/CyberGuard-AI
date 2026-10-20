"""
Watcher 2 -- Downloads folder (Module 6: malware / dangerous files).

Technology: plain folder polling (os.scandir) + SHA-256 hashing + CyberGuard's static attachment
scanner + VirusTotal hash lookup (free API key, optional).
Every DOWNLOADS_POLL_SECONDS:
   1. list the files in your Downloads folder (only that folder, not sub-folders)
   2. a file that is NEW and has finished downloading (same size on two checks, no .crdownload/.part)
      is READ into memory (max DOWNLOADS_MAX_MB) and checked WITHOUT opening or running it:
        program/script types, fake double extensions (invoice.pdf.exe), content that does not match the
        name (an .exe renamed .pdf), Office macros, PDF JavaScript, password-protected archives,
        HTML login forms, and -- with a VirusTotal key -- the file's SHA-256 against 70+ antivirus engines
   3. risky files are saved as a Cyber Threat scan + alert.
   4. a DANGEROUS file (risk >= FILE_QUARANTINE_MIN_SCORE) is MOVED -- never deleted -- into CyberGuard's
      quarantine folder and renamed so it cannot be run by a double-click (see file_quarantine.py).
      "Restore" in CyberGuard puts it back. FILE_QUARANTINE=false leaves every file where it is.
On first start, files already in the folder are remembered but not scanned (only new downloads are).
"""
import hashlib
import mimetypes
import os
from pathlib import Path

from app.automation import file_quarantine
from app.automation.engine import Watcher, get_state, save_and_alert, update_state
from app.core.config import get_settings

PARTIAL = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload")


def downloads_dir() -> Path:
    s = get_settings().DOWNLOADS_DIR.strip()
    return Path(os.path.expandvars(os.path.expanduser(s))) if s else Path.home() / "Downloads"


def scan_file(path: Path, *, network: bool = True) -> dict:
    """Static check of one file, as a CYBERGUARD result (reuses the email attachment scanner)."""
    from app.email_pipeline.attachments import scan_attachments
    from app.email_pipeline.schemas import Attachment
    data = path.read_bytes()
    att = Attachment(filename=path.name, content_type=mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                     size=len(data), sha256=hashlib.sha256(data).hexdigest(), data=data)
    result = scan_attachments([att], network=network)
    result.pop("qr_candidates", None)              # raw image bytes, not storable
    result["threatType"] = "Malware Detection (Downloads folder)"
    result["sha256"] = att.sha256
    return result


class DownloadsWatcher(Watcher):
    name = "downloads"
    title = "Downloads folder"
    what = "Every new file you download is checked for malware signs (fake extensions, macros, scripts, known-bad hashes)."
    modules = ["Cyber threat (malware)"]
    technology = "Folder polling (os.scandir) + SHA-256 + static file analysis + VirusTotal hash lookup (optional)"

    def __init__(self):
        super().__init__()
        self.interval_seconds = max(10, get_settings().DOWNLOADS_POLL_SECONDS)
        self._pending: dict[str, int] = {}        # file -> size seen last round (wait until it stops growing)

    def configured(self):
        d = downloads_dir()
        if not d.is_dir():
            return False, f"Folder {d} not found. Set DOWNLOADS_DIR in backend/.env."
        return True, ""

    @staticmethod
    def _quarantine(path: Path, result: dict) -> dict | None:
        """Move a dangerous download into quarantine; the result tells the user where it went and how to undo it."""
        reason = f"Risk {result['riskScore']}/100: " + ", ".join(
            i.get("label", "") for i in result.get("indicators", []) if i.get("triggered"))[:300]
        try:
            q = file_quarantine.quarantine_file(path, sha256=result.get("sha256", ""), score=result["riskScore"],
                                                reason=reason, scan_id=None)
        except file_quarantine.QuarantineError as exc:
            result["quarantine"] = {"status": "failed", "error": str(exc)}
            file_quarantine.audit("quarantine.file", "CYBERGUARD (automatic)", path.name,
                                  {"error": str(exc)[:200]}, success=False)
            return None
        result["quarantine"] = {"status": "quarantined", "id": q["id"]}
        result["explanation"] = (str(result.get("explanation", "")) + " CyberGuard MOVED this file out of your "
                                 "Downloads folder into its quarantine folder (it was not deleted). If you trust it, "
                                 "use Restore in Settings -> Quarantined Downloads to put it back.").strip()
        file_quarantine.audit("quarantine.file", "CYBERGUARD (automatic)", path.name,
                              {"quarantineId": q["id"], "sha256": q["sha256"], "score": q["score"]})
        return q

    def check(self) -> dict:
        s = get_settings()
        folder = downloads_dir()
        st = get_state(self.name)
        seen: dict = st.get("seen", {})
        first_run = not st.get("initialised")
        current = {}
        for entry in os.scandir(folder):
            if entry.is_file(follow_symlinks=False) and not entry.name.lower().endswith(PARTIAL) \
                    and not entry.name.startswith("~$"):
                stat = entry.stat(follow_symlinks=False)
                current[entry.name] = (stat.st_size, int(stat.st_mtime))
        if first_run:
            update_state(self.name, initialised=True, folder=str(folder),
                         seen={n: list(v) for n, v in current.items()})
            return {"checked": 0, "threats": 0, "note": f"Watching {folder} ({len(current)} existing files left alone)"}

        checked = threats = 0
        finding = None
        for name, (size, mtime) in current.items():
            if list(seen.get(name, [])) == [size, mtime]:
                continue                                   # already checked this exact file
            if self._pending.get(name) != size:            # still downloading? wait one more round
                self._pending[name] = size
                continue
            self._pending.pop(name, None)
            seen[name] = [size, mtime]
            if size > s.DOWNLOADS_MAX_MB * 1024 * 1024:
                continue
            try:
                result = scan_file(folder / name)
            except OSError:
                continue                                   # locked / removed meanwhile: skip
            if file_quarantine.was_restored(result.get("sha256", "")):
                continue                                   # you restored this exact file from quarantine
            checked += 1
            quarantined = self._quarantine(folder / name, result) \
                if s.FILE_QUARANTINE and result["riskScore"] >= s.FILE_QUARANTINE_MIN_SCORE else None
            self.record(name + (" (moved to quarantine)" if quarantined else ""), result["riskScore"],
                        result["classification"])
            scan_id = save_and_alert(module_id="cyber-threat", subtopic_id="malware-detection",
                                     subtopic_title="Malware Detection", result=result, target=name,
                                     target_type="file", source="downloads",
                                     metadata={"folder": str(folder),
                                               "quarantineId": quarantined["id"] if quarantined else None})
            if quarantined and scan_id:
                file_quarantine.set_scan_id(quarantined["id"], scan_id)
            if scan_id:
                threats += 1
                finding = f"{name} (score {result['riskScore']})"
        for gone in set(seen) - set(current):
            seen.pop(gone, None)
        update_state(self.name, seen=seen)
        return {"checked": checked, "threats": threats, "finding": finding,
                "note": f"{checked} new file(s) checked" if checked else "No new downloads"}
