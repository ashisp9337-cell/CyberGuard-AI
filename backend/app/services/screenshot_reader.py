"""
Reads a screenshot sent to the chat (added 21 Oct): the text in it (OCR) and any QR code.

Everything runs ON THIS COMPUTER - the image is never sent to Google or anywhere else:
  * text : RapidOCR (ONNX models bundled in the pip package, CPU). English letters, digits and links; Hindi / Odia
           script is not read (the chat says so).
  * QR   : the same decoder as the QR-phishing scanner (app/detectors/qr_decoder.py).
Only the TEXT that was read goes on to the AI - masked like any chat message (phone numbers, OTPs ... hidden).

Install the OCR once (without dependencies: CyberGuard already has opencv-python-headless):
    pip install --no-deps -r requirements-ocr.txt
Without it, QR codes are still read and the chat says text reading is not installed.
"""
from __future__ import annotations

import logging
import threading

logger = logging.getLogger("cyberguard.chat")
_engine = None
_lock = threading.Lock()
INSTALL_HINT = "pip install --no-deps -r requirements-ocr.txt"


def _ocr_engine():
    global _engine
    if _engine is None:
        from rapidocr_onnxruntime import RapidOCR      # ImportError -> OCR not installed
        _engine = RapidOCR()
    return _engine


def ocr_available() -> bool:
    try:
        import rapidocr_onnxruntime  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _lines_in_reading_order(result) -> list[str]:
    """RapidOCR returns boxes; sort them top-to-bottom, then left-to-right, and join boxes on the same line."""
    boxes = []
    for box, text, conf in result or []:
        if not text or float(conf) < 0.5:
            continue
        ys = [p[1] for p in box]
        xs = [p[0] for p in box]
        boxes.append((min(ys), max(ys), min(xs), text.strip()))
    boxes.sort(key=lambda b: (b[0], b[2]))
    lines: list[list] = []
    for top, bottom, left, text in boxes:
        if lines and top < lines[-1][1] - (lines[-1][1] - lines[-1][0]) * 0.5:   # overlaps the previous line
            lines[-1][3].append((left, text))
            lines[-1][1] = max(lines[-1][1], bottom)
        else:
            lines.append([top, bottom, left, [(left, text)]])
    return [" ".join(t for _, t in sorted(parts)) for _, _, _, parts in lines]


def read(path: str) -> dict:
    """-> {"text": str, "qr": [payloads], "ocr": "ok" | "not_installed" | "failed"}"""
    out = {"text": "", "qr": [], "ocr": "ok"}
    try:
        from app.detectors.qr_decoder import decode_qr_image
        res = decode_qr_image(path)
        out["qr"] = [c.text for c in res.codes][:3]
    except Exception:  # noqa: BLE001
        logger.exception("QR reading of a chat screenshot failed")
    try:
        with _lock:                                    # one OCR at a time (shared ONNX sessions)
            result, _ = _ocr_engine()(path)
        out["text"] = "\n".join(_lines_in_reading_order(result))[:6000]
    except ImportError:
        out["ocr"] = "not_installed"
    except Exception:  # noqa: BLE001
        logger.exception("OCR of a chat screenshot failed")
        out["ocr"] = "failed"
    return out


MIN_TEXT_TO_SCAN = 12


def scan(db, user_id: str, path: str, name: str, source: str = "chat", alert: bool = True) -> dict:
    """Read the screenshot, then run CyberGuard's detectors on what it contains (saved to Scan History):
    the QR code(s) with the QR-phishing detector, the text like a pasted message.
    -> {"text", "qr", "ocr", "scans": [chat_scan summaries]}"""
    from app.services import chat_scan
    info = read(path)
    scans = []
    if info["qr"]:
        s = chat_scan.run_qr_image(db, user_id, path, name, source=source, alert=alert)
        if "scan_id" in s:
            scans.append(s)
    if len(info["text"].strip()) >= MIN_TEXT_TO_SCAN:
        s = chat_scan.run(db, user_id, info["text"][:4000], source=source, alert=alert)
        if "scan_id" in s:
            scans.append(s)
    return info | {"scans": scans}


def describe_for_ai(question: str, info: dict) -> str:
    """The chat message the AI gets for a screenshot (the image itself is never sent)."""
    parts = [question.strip() or "Is this screenshot safe? What is it and what should I do?",
             "", "[The user sent a screenshot. CyberGuard read it on this computer; the image itself is not shared.]"]
    if info["ocr"] == "not_installed":
        parts.append("[Text reading (OCR) is not installed on this CyberGuard server, so only QR codes were read.]")
    elif info["text"].strip():
        parts.append("[Text read from the screenshot (OCR, may contain small reading errors; Hindi / Odia script is "
                     "not read):]\n" + info["text"].strip())
    else:
        parts.append("[No readable English text was found in the screenshot.]")
    if info["qr"]:
        parts.append("[QR code(s) in the screenshot:]\n" + "\n".join(info["qr"]))
    return "\n".join(parts)
