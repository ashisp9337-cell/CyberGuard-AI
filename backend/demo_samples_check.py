"""(11 Nov) Scan EVERY file in backend/demo_samples/ and print each result - photos, videos, voice recordings and
network captures, whatever their names are.

    venv\\Scripts\\python.exe demo_samples_check.py

For each file: what kind it is, which check ran, the score (0-100), the verdict and the reasons that counted.
"Expected" is only a guess from the file name (ai / fake / gemini / clone / generated -> scam, real -> safe); other
names show "?" - you know what each file really is.

Runs on THIS computer only: nothing is uploaded, nothing is saved to the database. The full result is written to
demo_samples/demo_samples_check.txt (the folder is git-ignored, so file names of your photos never reach GitHub).
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
SDIR = os.path.join(HERE, "demo_samples")

IMAGE = {".jpg", ".jpeg", ".jfif", ".png", ".webp", ".heic", ".heif", ".avif", ".tif", ".tiff", ".gif", ".bmp"}
VIDEO = {".mp4", ".mov", ".webm", ".mkv", ".m4v", ".3gp", ".avi"}
AUDIO = {".ogg", ".opus", ".m4a", ".mp3", ".wav", ".aac", ".flac"}
CAPTURE = {".pcap", ".pcapng"}
SCAM_WORDS = ("ai_", "ai-", "fake", "gemini", "clone", "generated", "deepfake", "swap", "nmap")
OUT = []


def say(s=""):
    print(s, flush=True)
    OUT.append(s)


def expected(name: str) -> str:
    n = name.lower()
    if n.startswith("ai") or any(w in n for w in SCAM_WORDS):
        return "scam"
    if "real" in n or "normal" in n:
        return "safe"
    return "?"


def main():
    if not os.path.isdir(SDIR):
        say(f"No folder {SDIR}")
        return
    files = sorted(f for f in os.listdir(SDIR) if os.path.isfile(os.path.join(SDIR, f)))
    files = [f for f in files if os.path.splitext(f)[1].lower() in IMAGE | VIDEO | AUDIO | CAPTURE]
    say("=" * 100)
    say(f"CyberGuard - every demo sample  -  {time.strftime('%Y-%m-%d %H:%M:%S')}  -  {len(files)} file(s)")
    say("=" * 100)
    try:
        from app.services.analysis_service import free_ram_gb
        free = free_ram_gb()
        if free is not None and free < 3:
            say(f"NOTE: only {free:.1f} GB of memory free - close Edge / other apps; the first media file loads the "
                "models and is slow.")
    except Exception:
        pass
    from app.services import subtopic_router as R
    from app.services.analysis_service import run_scan

    rows = []
    for name in files:
        fp = os.path.join(SDIR, name)
        ext = os.path.splitext(name)[1].lower()
        kind = "photo" if ext in IMAGE else "video" if ext in VIDEO else "voice" if ext in AUDIO else "capture"
        exp = expected(name)
        mb = os.path.getsize(fp) / 1e6
        say(f"\n--- {name}  ({kind}, {mb:.1f} MB)  expected: {exp}")
        t = time.time()
        try:
            if kind == "capture":
                res = run_scan(module_id="cyber-threat", subtopic_id="network-traffic", subtopic_title="Network Traffic",
                               text_input=None, url_input=None, file_path=fp, file_name=name, extra_field_values={})
                sub = "network-traffic"
            else:
                res, cl = R.route(module_id="deepfake", text_input=None, url_input=None, file_path=fp, file_name=name,
                                  extra_field_values={})
                sub = cl.subtopic_id
        except Exception as e:  # noqa: BLE001 - one bad file must not stop the rest
            say(f"    ERROR  {type(e).__name__}: {str(e)[:200]}")
            rows.append((name, kind, exp, None, "error", time.time() - t))
            continue
        secs = time.time() - t
        score, verdict = res.get("riskScore", 0), res.get("classification", "?")
        say(f"    check: {sub}   score: {score}/100   verdict: {verdict.upper()}   ({secs:.1f} s)")
        hits = [i for i in (res.get("indicators") or []) if i.get("triggered")]
        for i in hits[:6]:
            say(f"    * {i.get('label', '')}: {str(i.get('description', ''))[:220]}")
        if not hits:
            say("    * no warning signs found")
        info = [i for i in (res.get("indicators") or []) if not i.get("triggered") and "info only" in str(i.get("label", ""))]
        for i in info[:1]:
            say(f"    (metadata) {str(i.get('description', ''))[:220]}")
        rows.append((name, kind, exp, score, verdict, secs))

    say("\n" + "=" * 100)
    say("SUMMARY   (scam = score 51 or more)")
    say(f"  {'file':44s} {'kind':8s} {'score':>5s}  {'verdict':10s} {'expected':9s} match")
    for name, kind, exp, score, verdict, secs in rows:
        got = None if score is None else ("scam" if score >= 51 else "safe")
        match = "-" if exp == "?" or got is None else ("YES" if got == exp else "NO <-- check")
        sc = "  -" if score is None else f"{score:5d}"
        say(f"  {name[:44]:44s} {kind:8s} {sc}  {verdict:10s} {exp:9s} {match}")
    try:
        with open(os.path.join(SDIR, "demo_samples_check.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(OUT) + "\n")
        say("\nSaved to backend\\demo_samples\\demo_samples_check.txt")
    except OSError:
        pass


if __name__ == "__main__":
    main()
