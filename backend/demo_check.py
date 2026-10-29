"""
CyberGuard - DEMO-DAY PRE-FLIGHT CHECK. Run it on the demo laptop before going on stage (and once on the venue's Wi-Fi).

    cd backend   (venv active)
    python demo_check.py              # everything, no Gemini request
    python demo_check.py --gemini     # also sends ONE tiny question to Gemini (uses 1 of the free daily requests)

What it checks:
  1. every model file the scans need is present
  2. PostgreSQL works and the database is on the newest migration
  3. internet: DNS works (if not, scans still work - they just skip registry / live-page checks)
  4. the backend server answers on http://127.0.0.1:8000 (start it first in another terminal)
  5. the chat assistant: key set, backup answers work when Gemini is down (no request), optionally one real request
  6. EVERY demo input from demo_cases.py gets the verdict the demo script promises (PASS / FAIL)
  7. your own deepfake demo files, network captures and voice recordings in backend/demo_samples/ (if you put them there)
  8. the Insider Risk demo files made by make_insider_demo.py (real CERT r4.2 activity)

It saves NOTHING to the database and sends no alerts. Report: backend/demo_check.txt (git ignores it).
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT, PROBLEMS = [], []


def say(s=""):
    print(s, flush=True)
    OUT.append(s)


def row(name, ok, detail="", warn=False):
    tag = "OK  " if ok else ("WARN" if warn else "FAIL")
    if not ok and not warn:
        PROBLEMS.append(name)
    say(f"  {tag}  {name:46s} {detail}")


MODEL_FILES = [
    "phishing_sms.joblib", "phishing_social.joblib", "phishing_email.joblib", "url_domain_model.joblib",
    "lookalike_domain.joblib", "domain_spoofing.joblib", "url_manipulation.joblib", "domain_age.joblib",
    "fake_login.joblib", "brand_impersonation.joblib", "financial_impersonation.joblib",
    "government_official_impersonation.joblib", "senior_management_impersonation.joblib",
    "teacher_university_impersonation.joblib", "impersonation_router.joblib", "ato_rba_model.joblib",
    "cred_failed-logins.joblib", "cred_password-spraying.joblib", "cred_unusual-location.joblib",
    "cred_unknown-device.joblib", "cred_session-activity.joblib", "cred_behavior-changes.joblib", "api_abuse.joblib",
    "network_traffic.json", "network_flow.joblib", "voice_ai.onnx", "voice_ai.json", "voiceprint.onnx",
    "voiceprint.json", os.path.join("whisper-small", "model.bin"), "insider_risk.joblib", "insider_risk.json", "EMBER2024_all.model", "malware_model.json",
    "face_detection_yunet_2023mar.onnx", "deepfake_video.onnx", "deepfake_video.json",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gemini", action="store_true", help="send one real question to Gemini")
    a = ap.parse_args()
    say("=" * 100)
    say(f"CyberGuard demo-day pre-flight check  -  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    say("=" * 100)

    say("\n1. Model files (backend/app/ml/models)")
    mdir = os.path.join(HERE, "app", "ml", "models")
    missing = [f for f in MODEL_FILES if not os.path.exists(os.path.join(mdir, f))]
    row("all model files present", not missing, f"{len(MODEL_FILES) - len(missing)}/{len(MODEL_FILES)}"
        + (f"  missing: {', '.join(missing)}" if missing else ""))

    say("\n2. Database")
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        from sqlalchemy import text
        from app.db.database import engine
        with engine.connect() as c:
            cur = c.execute(text("select version_num from alembic_version")).scalar()
            n = c.execute(text("select count(*) from users")).scalar()
        head = ScriptDirectory.from_config(Config(os.path.join(HERE, "alembic.ini"))).get_current_head()
        row("PostgreSQL connection", True, f"{n} account(s)")
        row("database on the newest migration", cur == head,
            "" if cur == head else f"database {cur}, code {head}: run  alembic upgrade head")
        if not n:
            row("at least one account to log in with", False, "sign up in the app first")
    except Exception as e:
        row("PostgreSQL connection", False, f"{type(e).__name__}: {str(e)[:120]}  (is PostgreSQL running?)")

    say("\n3. Internet")
    import socket
    t = time.time()
    try:
        socket.getaddrinfo("www.google.com", 443)
        row("DNS / internet", True, f"{(time.time() - t) * 1000:.0f} ms")
        online = True
    except OSError:
        row("DNS / internet", False, "OFFLINE - scans still work; registry / live-page checks and Gemini are skipped",
            warn=True)
        online = False

    say("\n4. Backend server")
    try:
        import requests
        r = requests.get("http://127.0.0.1:8000/api/health", timeout=3)
        row("backend answers on port 8000", r.status_code == 200, f"HTTP {r.status_code}")
    except Exception:
        row("backend answers on port 8000", False, "not running - start it: uvicorn app.main:app --port 8000", warn=True)

    say("\n5. Chat assistant (Threatora)")
    from app.core.config import get_settings
    from app.services import chat_service as C
    row("GEMINI_API_KEY set", bool(get_settings().GEMINI_API_KEY), "" if get_settings().GEMINI_API_KEY else
        "empty: the chat answers with its built-in backup answers only", warn=True)
    from app.services import chat_fallback
    try:
        reply, _ = chat_fallback.answer(None, "demo-check", "what is phishing?", "busy", None, "en")
        row("backup answers work without Gemini", bool(reply), reply[:60].replace("\n", " "))
    except Exception as e:
        row("backup answers work without Gemini", False, f"{type(e).__name__}: {str(e)[:100]}")
    from app.services import screenshot_reader
    row("screenshot text reading (OCR) installed", screenshot_reader.ocr_available(),
        "" if screenshot_reader.ocr_available() else "install: pip install --no-deps -r requirements-ocr.txt", warn=True)
    from app.services.telegram_inbox import TelegramInbox
    row("Telegram forwarding (forward a message to the bot)", TelegramInbox.configured(),
        "on - only TELEGRAM_CHAT_ID is answered" if TelegramInbox.configured() else
        "off: needs TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID (and TELEGRAM_INBOX=true)", warn=True)
    if a.gemini and online and get_settings().GEMINI_API_KEY:
        t = time.time()
        try:
            client = C._get_client()
            from google.genai import types
            resp = client.models.generate_content(model=C.MODEL_CHAIN[0],
                                                  contents="Reply with the single word OK.",
                                                  config=types.GenerateContentConfig(max_output_tokens=10))
            row("Gemini answers (1 request used)", bool(resp.text), f"{time.time() - t:.1f} s")
        except Exception as e:
            msg = str(e)[:110]
            row("Gemini answers (1 request used)", False, ("daily free limit used up - the chat uses backup answers "
                "until it resets: " if "429" in msg or "RESOURCE_EXHAUSTED" in msg else "") + msg, warn=True)

    say("\n6. Demo inputs (docs/DEMO_SCRIPT.md) - each must get the promised verdict")
    import demo_cases as DC
    from app.services import subtopic_router as R
    from app.services.analysis_service import run_scan
    root = os.path.dirname(HERE)
    for c in DC.CASES:
        fp = os.path.join(root, c["file"]) if c.get("file") else None
        t = time.time()
        try:
            if c.get("subtopic"):
                res = run_scan(module_id=c["module"], subtopic_id=c["subtopic"], subtopic_title=c["title"],
                               text_input=c.get("text"), url_input=c.get("url"), file_path=fp,
                               file_name=os.path.basename(fp) if fp else None, extra_field_values={})
                sub = c["subtopic"]
            else:
                res, cl = R.route(module_id=c["module"], text_input=c.get("text"), url_input=c.get("url"),
                                  file_path=fp, file_name=os.path.basename(fp) if fp else None, extra_field_values={})
                sub = cl.subtopic_id
            score = res["riskScore"]
            ok = (score >= 51) == (c["expect"] == "scam")
            row(f"{c['id']} {c['title'][:42]}", ok, f"score {score:3d}  (expect {c['expect']})  {sub}  "
                f"{time.time() - t:.1f} s")
        except Exception as e:
            row(f"{c['id']} {c['title'][:42]}", False, f"{type(e).__name__}: {str(e)[:100]}")

    say("\n7. Your deepfake demo files (backend/demo_samples/)")
    sdir = os.path.join(HERE, "demo_samples")
    any_file = False
    for cid, name, expect in DC.DEEPFAKE_FILES:
        fp = os.path.join(sdir, name)
        if not os.path.exists(fp):
            continue
        any_file = True
        t = time.time()
        try:
            res, cl = R.route(module_id="deepfake", text_input=None, url_input=None, file_path=fp, file_name=name,
                              extra_field_values={})
            score = res["riskScore"]
            ok = (score >= 51) == (expect == "scam")
            row(f"{cid} {name}", ok, f"score {score:3d}  (expect {expect})  {res.get('classification')}  "
                f"{time.time() - t:.1f} s")
        except Exception as e:
            row(f"{cid} {name}", False, f"{type(e).__name__}: {str(e)[:100]}")
    if not any_file:
        row("no files yet", False, "add real_photo.jpg / ai_image.png / fake_video.mp4 / real_video.mp4 "
            "(see demo_cases.py)", warn=True)

    say("\n8. Your network captures (backend/demo_samples/)")
    any_cap = False
    for cid, base, expect in DC.NETWORK_FILES:
        fp = next((os.path.join(sdir, base + ext) for ext in (".pcapng", ".pcap")
                   if os.path.exists(os.path.join(sdir, base + ext))), None)
        if not fp:
            continue
        any_cap = True
        t = time.time()
        try:
            res = run_scan(module_id="cyber-threat", subtopic_id="network-traffic", subtopic_title="Network Traffic",
                           text_input=None, url_input=None, file_path=fp, file_name=os.path.basename(fp),
                           extra_field_values={})
            score = res["riskScore"]
            ok = (score >= 51) == (expect == "scam")
            na = res.get("networkAnalysis") or {}
            row(f"{cid} {os.path.basename(fp)}", ok, f"score {score:3d}  (expect {expect})  "
                f"{na.get('connections', 0):,} connections  {time.time() - t:.1f} s")
        except Exception as e:
            row(f"{cid} {os.path.basename(fp)}", False, f"{type(e).__name__}: {str(e)[:100]}")
    if not any_cap:
        row("no captures yet", False, "add nmap_scan.pcapng / normal_traffic.pcapng (see demo_cases.py)", warn=True)

    say("\n9. Your voice recordings (backend/demo_samples/)")
    any_voice = False
    for cid, base, expect in DC.VOICE_FILES:
        fp = next((os.path.join(sdir, base + ext) for ext in (".ogg", ".opus", ".m4a", ".mp3", ".wav", ".aac", ".flac")
                   if os.path.exists(os.path.join(sdir, base + ext))), None)
        if not fp:
            continue
        any_voice = True
        t = time.time()
        try:
            res = run_scan(module_id="deepfake", subtopic_id="audio-analysis", subtopic_title="Voice & Audio Analysis",
                           text_input=None, url_input=None, file_path=fp, file_name=os.path.basename(fp),
                           extra_field_values={})
            score = res["riskScore"]
            ok = (score >= 51) == (expect == "scam")
            ai = (res.get("voiceAnalysis") or {}).get("aiVoice") or {}
            row(f"{cid} {os.path.basename(fp)}", ok, f"score {score:3d}  (expect {expect})  voice model "
                f"{ai.get('score', float('nan')):.2f}  {time.time() - t:.1f} s")
        except Exception as e:
            row(f"{cid} {os.path.basename(fp)}", False, f"{type(e).__name__}: {str(e)[:100]}")
    if not any_voice:
        row("no voice recordings yet", False, "add my_voice_clone.* / my_real_voice.* (see demo_cases.py)", warn=True)

    say("\n10. Insider Risk demo files (app/ml/training/data/insider/demo/)")
    ddir = os.path.join(HERE, "app", "ml", "training", "data", "insider", "demo")
    answers = {}
    try:
        with open(os.path.join(ddir, "insider_demo_answers.txt"), encoding="utf-8") as f:
            for line in f:
                name, _, rest = line.partition(":")
                if " insider " in rest:
                    answers[name.strip()] = rest.split(" insider ", 1)[1].split()[0]
    except OSError:
        pass
    any_ins = False
    for cid, base, expect in DC.INSIDER_FILES:
        fp = os.path.join(ddir, base + ".csv")
        if not os.path.exists(fp):
            continue
        any_ins = True
        t = time.time()
        try:
            res = run_scan(module_id="cyber-threat", subtopic_id="insider-risk", subtopic_title="Insider Risk",
                           text_input=None, url_input=None, file_path=fp, file_name=os.path.basename(fp),
                           extra_field_values={})
            ir = res.get("insiderRisk") or {}
            q = ir.get("queue") or []
            top = q[0] if q else {}
            if expect == "insider":
                want = answers.get(base + ".csv", "?")
                ok = bool(top) and top.get("user") == want and top.get("level") == "alert"
                detail = (f"score {res['riskScore']:3d}  first in queue: {top.get('user', '-')} "
                          f"({top.get('level', '-')}), CERT insider {want}")
            else:
                strong = [x for x in q if x.get("level") == "alert" and (x.get("pattern") or {}).get("strength") == "high"]
                ok = not strong
                detail = (f"score {res['riskScore']:3d}  alerts {ir.get('alerts', 0)}, reviews {ir.get('reviews', 0)}, "
                          f"strong-pattern alerts {len(strong)}")
            row(f"{cid} {base}.csv", ok, f"{detail}  {ir.get('people', 0)} people  {time.time() - t:.1f} s")
        except Exception as e:
            row(f"{cid} {base}.csv", False, f"{type(e).__name__}: {str(e)[:100]}")
    if not any_ins:
        row("no insider demo files yet", False, "python -I app\\ml\\training\\make_insider_demo.py", warn=True)

    say("\n" + ("READY FOR THE DEMO - no failures." if not PROBLEMS else
                f"NOT READY - {len(PROBLEMS)} failure(s): " + "; ".join(PROBLEMS)))


if __name__ == "__main__":
    try:
        main()
    finally:
        with open(os.path.join(HERE, "demo_check.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(OUT) + "\n")
        print("\nSaved to backend\\demo_check.txt")
