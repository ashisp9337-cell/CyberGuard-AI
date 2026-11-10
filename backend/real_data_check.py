"""
Real-data false-alarm check (10 Nov 2026).

Point it at a folder of REAL, harmless files you own (phone photos, selfies, voice notes, genuine e-mails saved as
.eml, normal SMS / chat text in .txt files - one message per line) and it scans every one with auto-detect, exactly
like the website does, and lists everything that scores 51 or more (a false alarm, because all of them are real).

Nothing is uploaded, saved to the database or changed: it only reads the files and writes real_data_check.txt next to
this script (gitignored). Your files never leave the PC.

    venv\\Scripts\\python.exe real_data_check.py "C:\\Users\\ashis\\Pictures\\real_test"

Which module each file goes to:
  .jpg .jpeg .png .webp .heic .bmp      -> Deepfake (image)        .mp4 .mov .mkv .webm .3gp -> Deepfake (video)
  .mp3 .wav .m4a .ogg .opus .aac .amr   -> Deepfake (voice)        .eml .msg                 -> Phishing (e-mail)
  .txt  -> Phishing, one message per line (a line that starts with http is checked as a link)
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

IMAGE = {".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif", ".bmp"}
VIDEO = {".mp4", ".mov", ".mkv", ".webm", ".3gp", ".m4v", ".avi"}
AUDIO = {".mp3", ".wav", ".m4a", ".ogg", ".opus", ".aac", ".amr", ".flac"}
MAIL = {".eml", ".msg"}
FLAG = 51
OUT: list[str] = []


def say(s: str = "") -> None:
    print(s)
    OUT.append(s)


def main(folder: str) -> int:
    import logging
    logging.disable(logging.WARNING)
    from app.services import subtopic_router as R
    if not os.path.isdir(folder):
        say(f"Folder not found: {folder}")
        return 2
    jobs = []
    for root, _dirs, files in os.walk(folder):
        for name in sorted(files):
            p = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            if ext in IMAGE | VIDEO | AUDIO:
                jobs.append(("deepfake", p, None, name))
            elif ext in MAIL:
                jobs.append(("phishing", p, None, name))
            elif ext == ".txt":
                with open(p, encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        if line.strip():
                            jobs.append(("phishing", None, line.strip(), f"{name} line {i}"))
    if not jobs:
        say("No supported files found.")
        return 2
    say(f"Real-data check - {time.strftime('%Y-%m-%d %H:%M:%S')} - {len(jobs)} item(s) from {folder}")
    flagged, errors = [], 0
    for module, path, text, label in jobs:
        t = time.time()
        try:
            res, c = R.route(module_id=module, text_input=text if text and not text.lower().startswith("http") else None,
                             url_input=text if text and text.lower().startswith("http") else None, file_path=path,
                             file_name=os.path.basename(path) if path else None, extra_field_values={})
        except R.RoutingError as e:
            say(f"  SKIP  {label[:60]:60s} {e.message[:80]}")
            continue
        except Exception as e:  # noqa: BLE001
            errors += 1
            say(f"  ERROR {label[:60]:60s} {type(e).__name__}: {str(e)[:80]}")
            continue
        s = int(res.get("riskScore", 0))
        mark = "FLAG " if s >= FLAG else "ok   "
        say(f"  {mark} {label[:60]:60s} {c.subtopic_id:22s} {s:3d}  ({time.time() - t:.1f}s)")
        if s >= FLAG:
            why = "; ".join(i["label"] for i in res.get("indicators", []) if i.get("triggered"))[:200]
            flagged.append((label, c.subtopic_id, s, why))
    say("")
    say(f"{len(jobs) - errors} scanned, {len(flagged)} flagged (score {FLAG}+), {errors} error(s).")
    for label, sub, s, why in flagged:
        say(f"  {s:3d} {sub:22s} {label}\n        why: {why}")
    say("All of these files are real, so every flagged one is a false alarm: send real_data_check.txt to Claude.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    try:
        code = main(sys.argv[1])
    finally:
        with open(os.path.join(HERE, "real_data_check.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(OUT) + "\n")
    sys.exit(code)
