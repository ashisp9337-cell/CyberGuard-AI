"""
Routes a scan request to the correct detector based on moduleId, mirroring
the six CyberGuard modules and their subtopics defined in the frontend's
src/data/modules.ts. This is the single place that decides "what kind of
analysis does this input need" — detectors themselves stay generic.
"""
import os

from app.detectors import phishing, malicious_url, deepfake, impersonation, account_takeover, cyber_threat, email_parser, qr_analyzer, brand_impersonation, teacher_university_impersonation, senior_management_impersonation, government_impersonation, financial_impersonation, known_contact_impersonation


def _impersonation_category_unknown(text: str, extra: dict, subtopic_title: str) -> dict:
    """The message's claimed identity is unclear: run EVERY impersonation detector (five trained models, the
    known-contact scam-script check and the general rule set) and report the strongest verdict, so an unclear category never turns a scam
    into "safe"."""
    checks = [
        ("Government official", lambda: government_impersonation.analyze_government_impersonation(text, extra, subtopic_title)),
        ("Senior management", lambda: senior_management_impersonation.analyze_senior_management_impersonation(text, extra, subtopic_title)),
        ("Teacher / university", lambda: teacher_university_impersonation.analyze_teacher_university_impersonation(text, extra, subtopic_title)),
        ("Financial institution", lambda: financial_impersonation.analyze_financial_impersonation(text, extra, subtopic_title)),
        ("Brand", lambda: brand_impersonation.analyze_brand_impersonation(text, extra, subtopic_title)),
        ("Friend / relative / known contact",
         lambda: known_contact_impersonation.analyze_known_contact_message(text, extra, subtopic_title)),
        ("General impersonation rules", lambda: impersonation.analyze_identity(text, extra, subtopic_title)),
    ]
    results = []
    for name, fn in checks:
        try:
            results.append((name, fn()))
        except Exception:          # one broken detector never breaks the scan
            continue
    if not results:
        return impersonation.analyze_identity(text, extra, subtopic_title)
    name, best = max(results, key=lambda nr: nr[1].get("riskScore", 0))
    best = dict(best)
    others = ", ".join(f"{n} {r.get('riskScore', 0)}" for n, r in results if n != name)
    best["analysisEngine"] = f"Impersonation (category unclear) - strongest of {len(results)} detectors: {name}; " \
                             + str(best.get("analysisEngine", ""))
    best["explanation"] = (f"The sender's claimed identity was unclear, so every impersonation detector checked the "
                           f"message; the {name.lower()} detector scored it highest. Other scores: {others}. "
                           + str(best.get("explanation", "")))
    best["checkedDetectors"] = [{"detector": n, "riskScore": r.get("riskScore", 0)} for n, r in results]
    return best


def run_scan(
    *, module_id: str, subtopic_id: str, subtopic_title: str,
    text_input: str | None, url_input: str | None,
    file_path: str | None, file_name: str | None,
    extra_field_values: dict | None,
    db=None, user_id: str | None = None, reference_path: str | None = None,
) -> dict:
    extra_field_values = extra_field_values or {}

    if module_id == "phishing":
        if subtopic_id == "qr-phishing" and file_path:
            return qr_analyzer.analyze_qr(file_path, file_name, subtopic_title, subtopic_id)
        if subtopic_id in ("fraudulent-website", "malicious-url") or url_input:
            target = url_input or text_input or ""
            result = malicious_url.analyze_url(target, subtopic_title, subtopic_id=subtopic_id)
            return result | {"_target": target, "_target_type": "url"}
        sender = extra_field_values.get("sender")
        reply_to = None
        target_text = text_input or ""

        # Email Analysis -> full Email Intelligence Pipeline: headers/SPF/DKIM/DMARC,
        # every link, attachment and QR image, all 6 impersonation detectors,
        # account-takeover signals, fused into one verdict.
        if subtopic_id == "email-analysis":
            from app.email_pipeline import analyze_email
            from app.email_pipeline.store import record_email
            raw = target_text
            if file_path and not target_text:
                with open(file_path, "rb") as f:
                    raw = f.read()
            result = analyze_email(raw, db=db, user_id=user_id, sender=sender or "")
            if db is not None and user_id:
                try:
                    record_email(db, user_id, result, source="upload" if file_path else "paste")
                except Exception:
                    pass  # history is best-effort; never fail the scan over it
            return result

        if not target_text and file_path:
            try:
                with open(file_path, "rb") as f:
                    raw = f.read()
                parsed = email_parser.parse_email_file(raw)
                target_text = parsed["body"]
                if not sender and parsed.get("from_address"):
                    sender = parsed["from_address"]
                reply_to = parsed.get("reply_to_address") or None
            except Exception:
                pass

        result = phishing.analyze_text(target_text, sender=sender, subtopic_title=subtopic_title, subtopic_id=subtopic_id, reply_to=reply_to)
        return result | {"_target": target_text[:80] or (file_name or "submission"), "_target_type": "email" if subtopic_id == "email-analysis" else "text"}

    if module_id == "deepfake":
        result = deepfake.analyze_media(file_path, file_name or "media file", subtopic_title,
                                        reference_path=reference_path)
        return result | {"_target": file_name or "uploaded media", "_target_type": "file"}

    if module_id == "impersonation":
        target = (text_input or "")[:80] or "identity submission"
        if subtopic_id == "contact-impersonation":
            # Personal to the user (their own saved contacts) — not a generic
            # trained model. See known_contact_impersonation.py for why.
            result = known_contact_impersonation.analyze_known_contact_message(
                text_input or "", extra_field_values, subtopic_title, db=db, user_id=user_id,
            )
        elif subtopic_id == "financial-impersonation":
            result = financial_impersonation.analyze_financial_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "brand-impersonation":
            result = brand_impersonation.analyze_brand_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "teacher-impersonation":
            result = teacher_university_impersonation.analyze_teacher_university_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "management-impersonation":
            result = senior_management_impersonation.analyze_senior_management_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        elif subtopic_id == "government-impersonation":
            result = government_impersonation.analyze_government_impersonation(
                text_input or "", extra_field_values, subtopic_title,
            )
        else:
            result = _impersonation_category_unknown(text_input or "", extra_field_values, subtopic_title)
        return result | {"_target": target, "_target_type": "identity"}

    if module_id == "credential":
        fields = dict(extra_field_values)
        result = account_takeover.analyze_event(fields, subtopic_title, text=text_input or "", subtopic_id=subtopic_id)
        target = text_input[:80] if text_input else "account security event"
        return result | {"_target": target, "_target_type": "identity" if subtopic_id != "password-spraying" and subtopic_id != "session-activity" and subtopic_id != "behavior-changes" else "text"}

    if module_id == "url-security":
        target = url_input or text_input or ""
        result = malicious_url.analyze_url(target, subtopic_title, subtopic_id=subtopic_id)
        return result | {"_target": target, "_target_type": "url"}

    if module_id == "cyber-threat":
        text = text_input or ""
        if file_path and os.path.exists(file_path):
            # an uploaded log / text file is read WHOLE (the upload is already limited to MAX_UPLOAD_MB); it is only
            # read as text, never run (added 23 Oct - before, uploaded files were ignored by this module)
            from app.services.subtopic_router import cyber_file_kind
            kind = cyber_file_kind(file_path, file_name)     # (30 Oct) 'script' = scripts, web pages, shortcuts, EICAR
            if kind == "capture":         # Wireshark / tcpdump capture: parsed, never replayed (added 24 Oct)
                result = cyber_threat.analyze_network_capture(file_path, file_name or "capture", subtopic_title)
                return result | {"_target": file_name or "packet capture", "_target_type": "file"}
            if kind == "evtx":            # Windows Event Viewer file: read by a separate process, never run
                from app.detectors import windows_events
                xml, note = windows_events.evtx_to_xml(file_path)
                if not xml:               # unreadable: say so - never a clean verdict for a file that was not read
                    from app.detectors.base import build_unverified_result
                    result = build_unverified_result(engine_name="CYBERGUARD Windows Event Engine",
                                                     threat_type=subtopic_title,
                                                     explanation=note or "The .evtx file could not be read.")
                    result["recommendations"] = ["Save the log again from Event Viewer (Save All Events As... .evtx) "
                                                 "or export it as XML, then upload it again."]
                    return result | {"_target": file_name or "event log", "_target_type": "file"}
                result = cyber_threat.analyze_event_text(xml, extra_field_values, subtopic_title)
                if note:
                    result["explanation"] = note + " " + result["explanation"]
                return result | {"_target": file_name or "event log", "_target_type": "file"}
            # (26 Oct) Malware Detection: never run. (30 Oct) also scripts / web pages / shortcuts, and on the Malware
            # Detection card every uploaded file (e.g. the EICAR test file saved as .txt) - never read as log lines there
            if kind in ("executable", "archive", "pdf", "unknown", "script") or subtopic_id == "malware-detection":
                from app.detectors import malware
                result = malware.analyze_file(file_path, file_name or "file", subtopic_title)
                return result | {"_target": file_name or "uploaded file", "_target_type": "file"}
            if kind == "text":
                with open(file_path, "rb") as f:
                    text = (text + "\n" if text else "") + f.read().decode("utf-8", errors="replace")
        result = cyber_threat.analyze_event_text(text, extra_field_values, subtopic_title)
        target = (text_input or "")[:80] or (file_name or "event submission")
        return result | {"_target": target, "_target_type": "file" if file_name else "text"}

    return {
        "riskScore": 0, "classification": "safe", "severity": "info", "confidenceScore": 0,
        "analysisEngine": "CYBERGUARD Engine", "threatType": subtopic_title, "indicators": [],
        "recommendations": [], "explanation": f"Unknown module '{module_id}'.",
        "_target": "unknown", "_target_type": "text",
    }


def warm_up() -> dict:
    """Load every text / URL / login model into memory once (they otherwise load on their first scan, which made the
    first scan of each kind slow). Runs in a background thread at startup; uses tiny local inputs, makes NO network
    calls and saves nothing. Returns {what: milliseconds or error}."""
    import time
    from app.detectors import malicious_url
    from app.services import subtopic_router
    out = {}
    sms = "Your parcel is on hold, pay the redelivery fee now"     # no link: warm-up must never go online
    log = "2026-10-01 09:00:00 sign-in success user=a ip=49.37.12.1 country=IN"
    jobs = [("phishing", s_, sms) for s_ in ("sms-analysis", "social-media-analysis")] + \
           [("impersonation", s_, sms) for s_ in ("government-impersonation", "management-impersonation",
                                                   "teacher-impersonation", "financial-impersonation",
                                                   "brand-impersonation", "contact-impersonation")] + \
           [("credential", s_, log) for s_ in ("failed-logins", "password-spraying", "unusual-location", "unknown-device",
                                                "session-activity", "behavior-changes")]
    for mod, sub, text in jobs:
        t = time.perf_counter()
        try:
            run_scan(module_id=mod, subtopic_id=sub, subtopic_title=sub, text_input=text, url_input=None,
                     file_path=None, file_name=None, extra_field_values={})
            out[sub] = round((time.perf_counter() - t) * 1000)
        except Exception as exc:  # noqa: BLE001 -- warm-up must never break startup
            out[sub] = f"error: {type(exc).__name__}"
    for sub in ("malicious-url", "domain-spoofing", "lookalike-domain", "url-manipulation"):
        t = time.perf_counter()
        try:
            malicious_url.analyze_url("http://example-login-verify.top/a", sub, subtopic_id=sub, network=False)
            out[sub] = round((time.perf_counter() - t) * 1000)
        except Exception as exc:  # noqa: BLE001
            out[sub] = f"error: {type(exc).__name__}"
    t = time.perf_counter()
    try:
        subtopic_router.router_probabilities(sms)
        out["auto-detect router"] = round((time.perf_counter() - t) * 1000)
    except Exception as exc:  # noqa: BLE001
        out["auto-detect router"] = f"error: {type(exc).__name__}"
    try:
        from app.email_pipeline import analyze_email
        t = time.perf_counter()
        analyze_email(b"From: a@example.com\r\nSubject: test\r\n\r\nhello", network=False)
        out["email-analysis"] = round((time.perf_counter() - t) * 1000)
    except Exception as exc:  # noqa: BLE001
        out["email-analysis"] = f"error: {type(exc).__name__}"
    return out


def free_ram_gb() -> float | None:
    """Memory the computer has free right now, in GB (None if it cannot be read). Standard library only."""
    try:
        if os.name == "nt":
            import ctypes

            class _Mem(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = _Mem()
            m.dwLength = ctypes.sizeof(_Mem)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return None
            return m.ullAvailPhys / 1024 ** 3
        with open("/proc/meminfo", encoding="ascii") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024 ** 2
    except Exception:  # noqa: BLE001
        return None
    return None


def warm_up_media(min_free_gb: float = 3.0) -> dict:
    """(30 Oct) Load the voice, speech-to-text, image and video models before the first scan needs them - the first
    voice scan took about 30 s because every model was read from disk then. Runs in the same background thread after
    warm_up(); uses only made-up input (a second of quiet noise, a grey picture), makes no network calls and saves
    nothing. Skipped when the computer has less than `min_free_gb` of free memory, so it never pushes the PC into
    swapping - the models then load on their first scan, as before. Returns {what: milliseconds or note}."""
    import time
    import numpy as np
    free = free_ram_gb()
    if free is not None and free < min_free_gb:
        return {"skipped": f"only {free:.1f} GB of memory free (needs {min_free_gb:g} GB) - models load on first scan"}
    out = {}

    def step(name, fn):
        t = time.perf_counter()
        try:
            note = fn()
            out[name] = note if isinstance(note, str) else round((time.perf_counter() - t) * 1000)
        except Exception as exc:  # noqa: BLE001 -- warm-up must never break startup
            out[name] = f"not loaded: {type(exc).__name__}"

    from app.detectors import voice
    noise = (np.random.default_rng(0).normal(0, 0.01, 16_000 * 4)).astype(np.float32)

    def ai_voice():
        if voice.ai_model()[0] is None:
            return "model not installed"
        voice.ai_voice_score([noise])                  # the first run also prepares the model's maths

    def voiceprint():
        if voice.voiceprint_model()[0] is None:
            return "model not installed"
        voice.voiceprint(noise)

    def speech_to_text():
        if not voice.whisper_available():
            return "not installed"
        voice.transcribe(np.zeros(16_000, np.float32))

    def image_models():
        from app.detectors import ai_image, deepfake_image
        loaded = []
        for name, mod in (("AI-image", ai_image), ("face-swap image", deepfake_image)):
            try:
                mod.load()
                loaded.append(name)
            except Exception:  # noqa: BLE001 - e.g. ModelUnavailable: loads (or reports) on first scan
                pass
        return None if loaded else "models not installed"

    def video_model():
        from app.detectors import deepfake_video
        deepfake_video.load()

    for name, fn in (("voice: AI-voice model", ai_voice), ("voice: voiceprint", voiceprint),
                     ("voice: speech-to-text", speech_to_text), ("image models", image_models),
                     ("video model", video_model)):
        step(name, fn)
    return out

