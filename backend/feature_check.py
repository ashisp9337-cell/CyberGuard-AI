"""
CyberGuard - EVERY MODULE, EVERY SUBTOPIC check (10 Nov 2026). Runs one real scan on each of the 33 subtopics plus the
auto-detect of every module, on THIS computer, with the real models - and saves NOTHING (no database, no alerts).

    cd backend
    venv\\Scripts\\python.exe feature_check.py

Inputs are built in: made-up messages, sign-in logs, attack logs, links on the reserved .example domain (they never
exist - no real website is opened), a QR code with a UPI payment request, a picture, a short video, 3 seconds of quiet
sound, a small network capture, a harmless Windows launcher that ships with Python, an activity log and an e-mail.
Every row shows the verdict and which engine judged it:
  OK    the scan ran with its models
  WARN  the scan ran but a part was missing (e.g. a model file) - read the note
  FAIL  the scan crashed
The voice / image / video scans need about 3 GB of free memory; with less they are skipped (WARN): close other
programs (or stop the backend) and run again. Report: backend/feature_check.txt (git ignores it).
"""
import io
import os
import sys
import tempfile
import time
import wave

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT, PROBLEMS, WARNINGS = [], [], []
# words in a result that mean a MODEL was missing (not e.g. "sender authentication not available", which is normal for
# a pasted e-mail)
DEGRADED = ("not installed", "model is not available", "could not be loaded", "model is missing", "models are missing",
            "not in app/ml/models", "modelunavailable", "model unavailable")
# models whose name must appear in the engine line - their absence is otherwise silent
EXPECT_ENGINE = {"image-analysis": ("AI-image model", "Face-swap model"), "ai-multimedia": ("AI-image model",),
                 "audio-analysis": ("AI-voice model",), "malware-detection": ("EMBER2024",)}


def say(s=""):
    print(s, flush=True)
    OUT.append(s)


def make_inputs(d: str) -> dict:
    """Every sample file, written to the temporary folder d (deleted at the end)."""
    import numpy as np
    from PIL import Image
    files = {}
    p = os.path.join(d, "photo.png")
    Image.new("RGB", (320, 240), (120, 140, 160)).save(p)
    files["image"] = p
    try:
        import zxingcpp
        try:
            qr = zxingcpp.write_barcode_to_image(zxingcpp.create_barcode(
                "upi://pay?pa=refund-desk@ybl&pn=Refund%20Desk&am=4999&tn=refund", zxingcpp.BarcodeFormat.QRCode))
        except AttributeError:                                   # older zxing-cpp
            qr = zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode,
                                        "upi://pay?pa=refund-desk@ybl&pn=Refund%20Desk&am=4999&tn=refund")
        p = os.path.join(d, "qr.png")
        Image.fromarray(np.asarray(qr)).resize((300, 300), Image.NEAREST).save(p)
        files["qr"] = p
    except Exception as e:  # noqa: BLE001
        files["qr_error"] = f"{type(e).__name__}: {e}"
    p = os.path.join(d, "voice.wav")
    with wave.open(p, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(16000)
        w.writeframes(np.random.default_rng(1).normal(0, 300, 16000 * 3).astype("<i2").tobytes())
    files["audio"] = p
    try:
        import av
        p = os.path.join(d, "clip.mp4")
        with av.open(p, "w") as c:
            st = c.add_stream("mpeg4", rate=10)
            st.width, st.height, st.pix_fmt = 160, 120, "yuv420p"
            for i in range(20):
                fr = av.VideoFrame.from_ndarray(np.full((120, 160, 3), (i * 10) % 255, np.uint8), format="rgb24")
                for pk in st.encode(fr):
                    c.mux(pk)
            for pk in st.encode():
                c.mux(pk)
        files["video"] = p
    except Exception as e:  # noqa: BLE001
        files["video_error"] = f"{type(e).__name__}: {e}"
    try:
        import dpkt
        buf = io.BytesIO()
        wr = dpkt.pcap.Writer(buf)
        for i, port in enumerate([22, 23, 80, 443, 445, 3389, 8080, 21, 25, 110] * 3):
            tcp = dpkt.tcp.TCP(sport=40000 + i, dport=port, flags=dpkt.tcp.TH_SYN, seq=i)
            ip = dpkt.ip.IP(src=bytes([192, 168, 1, 50]), dst=bytes([192, 168, 1, 10]), p=dpkt.ip.IP_PROTO_TCP, data=tcp)
            ip.len = len(bytes(ip))
            wr.writepkt(bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, data=ip)), ts=1767225600 + i * 0.05)
        p = os.path.join(d, "capture.pcap")
        with open(p, "wb") as f:
            f.write(buf.getvalue())
        files["pcap"] = p
    except Exception as e:  # noqa: BLE001
        files["pcap_error"] = f"{type(e).__name__}: {e}"
    import pip
    launcher = os.path.join(os.path.dirname(pip.__file__), "_vendor", "distlib", "t64.exe")
    if os.path.exists(launcher):
        p = os.path.join(d, "setup_tool.exe")
        with open(launcher, "rb") as src, open(p, "wb") as dst:
            dst.write(src.read())
        files["program"] = p
    p = os.path.join(d, "activity.csv")
    rows = [f"2026-10-{day:02d} 09:00:00,ravi,PC-1,logon," for day in range(1, 20)]
    rows += ["2026-10-20 02:10:00,ravi,PC-1,logon,", "2026-10-20 02:12:00,ravi,PC-1,usb_connect,",
             "2026-10-20 02:15:00,ravi,PC-1,file_copy,customer_database.xlsx", "2026-10-20 02:20:00,ravi,PC-1,http,wikileaks.org"]
    with open(p, "w", encoding="utf-8") as f:
        f.write("date,user,pc,activity,details\n" + "\n".join(rows) + "\n")
    files["insider"] = p
    p = os.path.join(d, "mail.eml")
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write("From: \"SBI Alerts\" <alerts@sbi-kyc-update.example>\r\nTo: you@college.example\r\n"
                "Subject: Urgent: KYC pending\r\nContent-Type: text/plain\r\n\r\n"
                "Your account is suspended. Verify now: http://sbi-kyc-update.example/verify\r\n")
    files["email"] = p
    return files


SMS = "Dear customer your SBI account will be blocked today. Update KYC now at http://sbi-kyc-update.example/login"
URL = "http://sbi-kyc-update.example/login"
LOGINS = "\n".join([f"2026-11-0{1 + i // 6} 0{i % 6}:1{i % 10}:00 sign-in failed user=ravi ip=185.220.101.{i} country=RU"
                    for i in range(12)] + ["2026-11-03 03:30:00 sign-in success user=ravi ip=185.220.101.7 country=RU "
                                           "device=new mfa=off"])
API = "\n".join(f'203.0.113.9 - - [09/Nov/2026:10:0{i}:00 +0000] "GET /api/users?id=1%27%20OR%201=1-- HTTP/1.1" 200 512 '
                f'"-" "sqlmap/1.8"' for i in range(8))
SSHLOG = "\n".join(f"Nov  9 10:{i // 6:02d}:{(i % 6) * 10:02d} server sshd[12{i:02d}]: Failed password for root from "
                   f"45.155.205.233 port 5{i:03d} ssh2" for i in range(30))

# (module, subtopic, title, input kind, input)   input kind: text / url / file:<key>
CASES = [
    ("phishing", "email-analysis", "Email Analysis", "file:email", None),
    ("phishing", "sms-analysis", "SMS Analysis", "text", SMS),
    ("phishing", "social-media-analysis", "Social Media Analysis", "text",
     "Congrats! You won the Instagram blue tick giveaway. Pay Rs 499 at http://bluetick.example"),
    ("phishing", "qr-phishing", "QR Code Phishing", "file:qr", None),
    ("phishing", "fraudulent-website", "Fraudulent Website", "url", URL),
    ("phishing", "malicious-url", "Malicious URL", "url", URL),
    ("deepfake", "image-analysis", "Image Analysis", "file:image", None),
    ("deepfake", "video-analysis", "Video Analysis", "file:video", None),
    ("deepfake", "audio-analysis", "Voice & Audio Analysis", "file:audio", None),
    ("deepfake", "ai-multimedia", "AI-Generated Multimedia", "file:image", None),
    ("impersonation", "government-impersonation", "Government Impersonation", "text",
     "This is CBI officer. You are under digital arrest. Transfer Rs 50000 now to clear your name."),
    ("impersonation", "management-impersonation", "Senior Management Impersonation", "text",
     "Hi, it's the CEO. I'm in a meeting, buy 5 Amazon gift cards urgently and send me the codes."),
    ("impersonation", "teacher-impersonation", "Teacher / University Impersonation", "text",
     "Dear student, this is your HOD. Pay the exam fine of Rs 2000 to this UPI today or you cannot sit the exam."),
    ("impersonation", "financial-impersonation", "Financial Institution Impersonation", "text", SMS),
    ("impersonation", "brand-impersonation", "Brand Impersonation", "text",
     "Amazon: your order is on hold. Confirm your card at http://amazon-verify.example"),
    ("impersonation", "contact-impersonation", "Friend / Relative Impersonation", "text",
     "Hi it's your cousin, new number. Send Rs 10000 urgently, I'll return tomorrow."),
] + [("credential", s, t, "text", LOGINS) for s, t in (
    ("failed-logins", "Failed Logins"), ("password-spraying", "Password Spraying"),
    ("unusual-location", "Unusual Location"), ("unknown-device", "Unknown Device"),
    ("session-activity", "Session Activity"), ("behavior-changes", "Behavior Changes"))] + [
    ("url-security", s, t, "url", URL) for s, t in (
        ("domain-spoofing", "Domain Spoofing"), ("lookalike-domain", "Lookalike Domain"),
        ("url-manipulation", "URL Manipulation"), ("redirect-analysis", "Redirect Analysis"),
        ("ssl-domain-analysis", "SSL / Domain Analysis"), ("fake-login-page", "Fake Login Page"))] + [
    ("cyber-threat", "malware-detection", "Malware Detection", "file:program", None),
    ("cyber-threat", "network-traffic", "Network Traffic", "file:pcap", None),
    ("cyber-threat", "api-abuse", "API Abuse", "text", API),
    ("cyber-threat", "insider-risk", "Insider Risk", "file:insider", None),
    ("cyber-threat", "log-analysis", "Log Analysis", "text", SSHLOG),
]
AUTO = [("phishing", "text", SMS), ("impersonation", "text", "This is your bank manager, share the OTP now to stop the "
                                                                  "account freeze."),
        ("credential", "text", LOGINS), ("url-security", "url", URL), ("cyber-threat", "text", SSHLOG),
        ("deepfake", "file:image", None)]
MEDIA = {"image-analysis", "video-analysis", "audio-analysis", "ai-multimedia"}


def judge_row(label: str, res: dict, seconds: float, sub: str = "") -> None:
    text = (res.get("explanation", "") + " " + res.get("analysisEngine", "")).lower()
    missing = next((d for d in DEGRADED if d in text), None)
    absent = [m for m in EXPECT_ENGINE.get(sub, ()) if m not in res.get("analysisEngine", "")]
    if absent and not missing:
        missing = "did not run: " + ", ".join(absent)
    detail = (f"score {res['riskScore']:3d}  {res.get('classification', ''):10s} {seconds:5.1f} s  "
              f"{res.get('analysisEngine', '')[:70]}")
    if missing:
        WARNINGS.append(label)
        say(f"  WARN  {label:44s} {detail}")
        say(f"        part missing: '{missing}' - {res.get('explanation', '')[:160]}")
    else:
        say(f"  OK    {label:44s} {detail}")


def main():
    from app.services import analysis_service as A
    from app.services import subtopic_router as R
    say("=" * 110)
    say(f"CyberGuard - every module, every subtopic  -  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    say("=" * 110)
    free = A.free_ram_gb()
    media_ok = free is None or free >= 3.0
    with tempfile.TemporaryDirectory() as d:
        files = make_inputs(d)
        for k in ("qr_error", "video_error", "pcap_error"):
            if k in files:
                say(f"  note: sample {k.split('_')[0]} could not be made: {files[k]}")
        module = None
        for mod, sub, title, kind, value in CASES:
            if mod != module:
                module = mod
                say(f"\n{mod}")
            label = f"{sub}"
            if sub in MEDIA and not media_ok:
                WARNINGS.append(label)
                say(f"  WARN  {label:44s} skipped: only {free:.1f} GB memory free (needs 3 GB) - close programs, run again")
                continue
            fp = files.get(kind.split(":", 1)[1]) if kind.startswith("file:") else None
            if kind.startswith("file:") and not fp:
                PROBLEMS.append(label)
                say(f"  FAIL  {label:44s} the sample input could not be made (see note above)")
                continue
            t = time.time()
            try:
                res = A.run_scan(module_id=mod, subtopic_id=sub, subtopic_title=title,
                                 text_input=value if kind == "text" else None, url_input=value if kind == "url" else None,
                                 file_path=fp, file_name=os.path.basename(fp) if fp else None, extra_field_values={})
                judge_row(label, res, time.time() - t, sub)
            except Exception as e:  # noqa: BLE001
                PROBLEMS.append(label)
                say(f"  FAIL  {label:44s} {type(e).__name__}: {str(e)[:120]}")
        say("\nauto-detect (each module picks the subtopic itself)")
        for mod, kind, value in AUTO:
            label = f"{mod} / auto"
            if mod == "deepfake" and not media_ok:
                WARNINGS.append(label)
                say(f"  WARN  {label:44s} skipped: not enough free memory")
                continue
            fp = files.get(kind.split(":", 1)[1]) if kind.startswith("file:") else None
            t = time.time()
            try:
                res, c = R.route(module_id=mod, text_input=value if kind == "text" else None,
                                 url_input=value if kind == "url" else None, file_path=fp,
                                 file_name=os.path.basename(fp) if fp else None, extra_field_values={})
                judge_row(f"{label} -> {c.subtopic_id}", res, time.time() - t, c.subtopic_id)
            except Exception as e:  # noqa: BLE001
                PROBLEMS.append(label)
                say(f"  FAIL  {label:44s} {type(e).__name__}: {str(e)[:120]}")
    total = len(CASES) + len(AUTO)
    say("\n" + (f"ALL {total} SCANS RAN - no failures" + (f", {len(WARNINGS)} warning(s): " + "; ".join(WARNINGS)
                                                           if WARNINGS else ".")
                if not PROBLEMS else f"{len(PROBLEMS)} FAILURE(S): " + "; ".join(PROBLEMS)))
    say("Scores are the verdicts on made-up samples; a plain picture / quiet sound / harmless program is expected to "
        "score low. What matters here: every scan ran with its models.")


if __name__ == "__main__":
    try:
        main()
    finally:
        with open(os.path.join(HERE, "feature_check.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(OUT) + "\n")
        print("\nSaved to backend\\feature_check.txt")
