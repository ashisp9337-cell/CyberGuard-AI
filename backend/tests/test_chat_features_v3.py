"""Chat features approved 21 Oct: history in PostgreSQL, actions that run only after the user confirms, screenshot
scanning on this computer, Telegram forwarding (owner chat only) and streamed replies. Gemini and Telegram are
simulated - nothing is sent anywhere."""
import io
import json

import numpy as np
import pytest

from app.db.database import SessionLocal
from app.db.models import IOC, EmailRecord, Scan, User
from app.services import chat_actions
from app.services import chat_service as C
from app.services.chat_safety import Masker

SCAM = ("Dear customer your SBI account is blocked. Share the OTP 482913 and call 9876543210 immediately to "
        "unblock, else account will be closed today.")


class Fake:
    """Simulated Gemini: records what would be sent, can call one tool, can stream."""

    def __init__(self, reply="All good.", tool=None, tool_args=None, chunks=None, break_after=None):
        self.sent, outer = [], self
        self.reply, self.tool, self.tool_args, self.chunks, self.break_after = reply, tool, tool_args or {}, chunks, break_after

        class Models:
            def generate_content(self, model, contents, config):
                outer.sent.append(repr(contents))
                if outer.tool:
                    tools = {t.__name__: t for t in config.tools}
                    outer.sent.append(repr(tools[outer.tool](**outer.tool_args)))
                return type("R", (), {"text": outer.reply})()

            def generate_content_stream(self, model, contents, config):
                outer.sent.append(repr(contents))
                for i, c in enumerate(outer.chunks or [outer.reply]):
                    if outer.break_after is not None and i == outer.break_after:
                        raise ConnectionResetError("connection lost")
                    yield type("Ch", (), {"text": c})()
        self.models = Models()


@pytest.fixture()
def fake(monkeypatch):
    def use(**kw):
        g = Fake(**kw)
        monkeypatch.setattr(C, "_get_client", lambda: g)
        C._histories.clear(); C._maskers.clear()
        chat_actions.reset_for_tests()
        return g
    return use


def scan_sources(client) -> list[str]:
    db = SessionLocal()
    try:
        uid = user_id(client)
        return [(s.input_metadata or {}).get("via", "") for s in db.query(Scan).filter(Scan.user_id == uid).all()]
    finally:
        db.close()


def user_id(client) -> str:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.email == client._test_email).first().id
    finally:
        db.close()


# ----------------------------------------------------------------- history -----------------------------------
def test_history_is_saved_shown_again_and_cleared(auth_client, fake):
    fake(reply="Phishing is a fake message that tries to steal details.")
    assert auth_client.post("/api/chat", json={"message": "what is phishing?"}).status_code == 200
    hist = auth_client.get("/api/chat/history").json()
    assert [h["role"] for h in hist] == ["user", "assistant"]
    assert hist[0]["text"] == "what is phishing?" and "fake message" in hist[1]["text"]
    assert auth_client.post("/api/chat/reset").status_code == 200
    assert auth_client.get("/api/chat/history").json() == []


def test_after_a_restart_the_saved_turns_go_back_to_the_ai_still_masked(auth_client, fake):
    g = fake(reply="Noted.")
    auth_client.post("/api/chat", json={"message": "my number is 9876543210, remember it"})
    C._histories.clear(); C._maskers.clear()                      # = backend restart
    g.sent.clear()
    auth_client.post("/api/chat", json={"message": "what did I tell you?"})
    sent = " ".join(g.sent)
    assert "remember it" in sent and "9876543210" not in sent and "[PHONE_" in sent


def test_history_belongs_to_one_user(auth_client, fake, client):
    fake(reply="ok")
    auth_client.post("/api/chat", json={"message": "secret question"})
    from helpers import register_user
    register_user(client, {"name": "Other", "email": "other_hist_user@example.com", "password": "TestPass123"})
    assert all("secret question" not in h["text"] for h in client.get("/api/chat/history").json())


# ----------------------------------------------------------------- actions -----------------------------------
def _ioc(uid, value="45.155.205.11"):
    db = SessionLocal()
    try:
        row = IOC(user_id=uid, ioc_type="ip", value=value, times_seen=2, max_risk=88, modules=["credential"])
        db.add(row); db.commit()
        return row.id
    finally:
        db.close()


def test_allowlist_is_only_prepared_and_runs_after_confirm(auth_client, fake):
    uid = user_id(auth_client)
    ioc_id = _ioc(uid)
    fake(reply="Press Confirm to allowlist it.", tool="prepare_allowlist_indicator",
         tool_args={"value": "45.155.205.11", "reason": "our office VPN"})
    out = auth_client.post("/api/chat", json={"message": "45.155.205.11 is our VPN, stop flagging it"}).json()
    assert len(out["actions"]) == 1 and out["actions"][0]["kind"] == "allowlist_indicator"
    db = SessionLocal()
    assert db.get(IOC, ioc_id).status == "active"                  # nothing changed yet
    db.close()
    aid = out["actions"][0]["id"]
    r = auth_client.post(f"/api/chat/actions/{aid}/confirm")
    assert r.status_code == 200, r.text and "Allowlisted" in r.json()["message"]
    db = SessionLocal()
    assert db.get(IOC, ioc_id).status == "allowlisted"
    db.close()
    assert auth_client.post(f"/api/chat/actions/{aid}/confirm").status_code == 409     # runs only once
    assert "Allowlisted" in auth_client.get("/api/chat/history").json()[-1]["text"]


def test_another_user_cannot_confirm_my_action(auth_client, fake, client):
    uid = user_id(auth_client)
    _ioc(uid, "203.0.113.9")
    fake(tool="prepare_allowlist_indicator", tool_args={"value": "203.0.113.9"})
    aid = auth_client.post("/api/chat", json={"message": "allowlist 203.0.113.9"}).json()["actions"][0]["id"]
    from helpers import register_user
    register_user(client, {"name": "Intruder", "email": "intruder_act@example.com", "password": "TestPass123"})
    assert client.post(f"/api/chat/actions/{aid}/confirm").status_code == 404


def test_cancel_changes_nothing(auth_client, fake):
    ioc_id = _ioc(user_id(auth_client), "198.51.100.4")
    fake(tool="prepare_allowlist_indicator", tool_args={"value": "198.51.100.4"})
    aid = auth_client.post("/api/chat", json={"message": "allowlist it"}).json()["actions"][0]["id"]
    assert auth_client.post(f"/api/chat/actions/{aid}/cancel").status_code == 200
    db = SessionLocal()
    assert db.get(IOC, ioc_id).status == "active"
    db.close()
    assert auth_client.post(f"/api/chat/actions/{aid}/confirm").status_code == 409


def test_release_quarantined_email_after_confirm(auth_client, fake):
    uid = user_id(auth_client)
    db = SessionLocal()
    rec = EmailRecord(user_id=uid, from_address="hr@college.example", subject="Exam schedule", risk_score=72,
                      classification="high_risk", action_taken="quarantined", details={})
    db.add(rec); db.commit(); rid = rec.id; db.close()
    fake(tool="prepare_release_quarantined_email", tool_args={"email_id": rid})
    aid = auth_client.post("/api/chat", json={"message": "release the exam schedule mail"}).json()["actions"][0]["id"]
    r = auth_client.post(f"/api/chat/actions/{aid}/confirm")
    assert r.status_code == 200, r.text
    db = SessionLocal()
    assert db.get(EmailRecord, rid).action_taken == "released"
    db.close()


def test_report_after_confirm(auth_client, fake):
    fake(tool="prepare_report", tool_args={"report_format": "csv", "title": "Chat report"})
    aid = auth_client.post("/api/chat", json={"message": "make me a csv report"}).json()["actions"][0]["id"]
    r = auth_client.post(f"/api/chat/actions/{aid}/confirm")
    assert r.status_code == 200, r.text
    assert any(x["title"] == "Chat report" and x["format"] == "CSV" for x in auth_client.get("/api/reports").json())


# ----------------------------------------------------------------- streaming ---------------------------------
def _events(resp_text: str) -> list[dict]:
    return [json.loads(line[6:]) for line in resp_text.splitlines() if line.startswith("data: ")]


def test_stream_puts_back_a_placeholder_split_across_pieces(auth_client, fake):
    fake(chunks=["Never call [PHO", "NE_1] back. ", "It is a scam."])
    r = auth_client.post("/api/chat/stream", json={"message": "call 9876543210 to unblock your account"})
    ev = _events(r.text)
    text = "".join(e["text"] for e in ev if e["type"] == "delta")
    assert "Never call 9876543210 back." in text and "[PHO" not in text
    assert ev[-1]["type"] == "done" and ev[-1]["reply"].startswith("Never call 9876543210 back.")
    assert auth_client.get("/api/chat/history").json()[-1]["text"].startswith("Never call 9876543210")


def test_stream_cut_off_keeps_the_answer_so_far(auth_client, fake):
    fake(chunks=["First part. ", "second part"], break_after=1)
    ev = _events(auth_client.post("/api/chat/stream", json={"message": "explain smishing"}).text)
    assert ev[-1]["type"] == "done" and "First part." in ev[-1]["reply"] and "cut off" in ev[-1]["reply"]


def test_stream_without_gemini_gives_the_backup_answer(auth_client, monkeypatch):
    monkeypatch.setattr(C, "_get_client", lambda: None)
    ev = _events(auth_client.post("/api/chat/stream", json={"message": "show my alerts"}).text)
    assert ev[-1]["type"] == "done" and ev[-1]["reply"]


def test_unmasker_holds_back_only_unfinished_placeholders():
    m = Masker()
    m.mask("call 9876543210")
    u = C._StreamUnmasker(m)
    assert u.feed("a [PHO") == "a " and u.feed("NE_1] b [x") == "9876543210 b " and u.flush() == "[x"


# ----------------------------------------------------------------- screenshots -------------------------------
def _sms_screenshot() -> bytes:
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (760, 300), (250, 250, 250))
    d = ImageDraw.Draw(img)
    try:
        f = ImageFont.truetype("DejaVuSans.ttf", 22)
    except OSError:
        f = ImageFont.load_default(size=22)
    for i, line in enumerate(["India Post: Your parcel is on hold due to an", "incomplete address. Pay Rs 25 redelivery fee",
                              "within 12 hours at http://indiapost-redeliver.top/pay"]):
        d.text((20, 30 + 60 * i), line, fill=(20, 20, 20), font=f)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def test_screenshot_is_read_here_scanned_and_explained(auth_client, fake):
    from app.services import screenshot_reader
    if not screenshot_reader.ocr_available():
        pytest.skip("OCR not installed")
    g = fake(reply="This is the India Post parcel-fee scam.")
    r = auth_client.post("/api/chat/image", files={"file": ("sms.png", _sms_screenshot(), "image/png")},
                         data={"message": "is this real?", "language": "en"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["textFound"] and "CyberGuard verdict" in body["reply"]
    sent = " ".join(g.sent)
    assert "redeliver" in sent and "PNG" not in sent                 # the TEXT goes to the AI, never the image
    assert "chat" in scan_sources(auth_client)
    assert auth_client.get("/api/chat/history").json()[-2]["text"].startswith("📷 sms.png")


def test_qr_in_a_screenshot_uses_the_qr_detector(auth_client, fake):
    import cv2
    qr = cv2.QRCodeEncoder.create().encode("upi://pay?pa=refund.helpdesk9@ybl&pn=SBI%20Refund&am=4999&cu=INR")
    qr = cv2.resize(qr, (qr.shape[1] * 8, qr.shape[0] * 8), interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, png = cv2.imencode(".png", qr)
    fake(reply="A UPI collect request disguised as a refund.")
    r = auth_client.post("/api/chat/image", files={"file": ("qr.png", png.tobytes(), "image/png")})
    assert r.status_code == 200, r.text
    assert r.json()["qrFound"] == 1 and "CyberGuard verdict" in r.json()["reply"]


def test_a_renamed_non_image_is_refused(auth_client, fake):
    fake()
    r = auth_client.post("/api/chat/image", files={"file": ("x.png", b"not really an image", "image/png")})
    assert r.status_code == 422


# ----------------------------------------------------------------- Telegram ----------------------------------
@pytest.fixture()
def tg(monkeypatch):
    from app.core.config import get_settings
    from app.services import telegram_inbox as T
    s = get_settings()
    monkeypatch.setattr(s, "TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setattr(s, "TELEGRAM_CHAT_ID", "4242")
    sent = []
    box = T.TelegramInbox()
    monkeypatch.setattr(box, "reply", lambda chat_id, text, reply_to=None: sent.append((chat_id, text)))
    box._started = 1e12 - 10                              # "now"; messages below use date=now
    return box, sent


def test_telegram_message_from_a_stranger_is_ignored(auth_client, tg):
    box, sent = tg
    assert box.handle({"chat": {"id": 999}, "date": 1e12, "text": SCAM, "message_id": 1}) is None
    assert sent == []


def test_telegram_forwarded_scam_gets_a_verdict_and_is_saved(auth_client, tg, monkeypatch):
    box, sent = tg
    import app.automation.engine as E
    monkeypatch.setattr(E, "owner_user_id", lambda db: user_id(auth_client))
    text = box.handle({"chat": {"id": 4242}, "date": 1e12, "text": SCAM, "message_id": 7})
    assert text and "CyberGuard:" in text and sent and sent[0][0] == "4242"
    assert "telegram" in scan_sources(auth_client)


def test_telegram_polling_sends_both_timeouts_correctly(monkeypatch):
    """The real getUpdates call: Telegram's long-poll 'timeout' goes in the request, our wait is the HTTP timeout
    (both are called timeout - this once made every poll fail with 'multiple values for keyword argument')."""
    from app.core.config import get_settings
    from app.services import telegram_inbox as T
    monkeypatch.setattr(get_settings(), "TELEGRAM_BOT_TOKEN", "test-token")
    seen = []

    class Resp:
        status_code, headers = 200, {"content-type": "application/json"}

        def json(self):
            return {"ok": True, "result": []}

    def fake_post(url, json=None, timeout=None):
        seen.append((url.rsplit("/", 1)[-1], json, timeout))
        box._stop.set()                                    # one poll is enough
        return Resp()
    monkeypatch.setattr(T.requests, "post", fake_post)
    box = T.TelegramInbox()
    monkeypatch.setattr(box._stop, "wait", lambda s: box._stop.set())   # an error ends the test instead of retrying
    box._loop()
    assert "lastError" not in box.status or not box.status["lastError"]
    assert seen == [("getUpdates", {"timeout": 25, "allowed_updates": ["message"]}, 35)]
    assert box.status["state"] != "error"


def test_telegram_help(auth_client, tg):
    box, sent = tg
    assert "Forward me" in box.handle({"chat": {"id": 4242}, "date": 1e12, "text": "/start", "message_id": 2})


def test_screenshot_is_scanned_once_even_in_backup_mode(auth_client, monkeypatch):
    from app.services import screenshot_reader
    if not screenshot_reader.ocr_available():
        pytest.skip("OCR not installed")
    monkeypatch.setattr(C, "_get_client", lambda: None)            # no Gemini: backup answer
    before = len(scan_sources(auth_client))
    r = auth_client.post("/api/chat/image", files={"file": ("sms.png", _sms_screenshot(), "image/png")})
    assert r.status_code == 200, r.text
    assert r.json()["reply"].count("CyberGuard verdict") == 1
    assert len(scan_sources(auth_client)) == before + 1


def test_the_ai_cannot_scan_the_screenshot_text_a_second_time(auth_client, fake):
    from app.services import screenshot_reader
    if not screenshot_reader.ocr_available():
        pytest.skip("OCR not installed")
    fake(reply="Explained.", tool="check_message_or_link", tool_args={"content": "India Post parcel on hold"})
    before = len(scan_sources(auth_client))
    r = auth_client.post("/api/chat/image", files={"file": ("sms.png", _sms_screenshot(), "image/png")})
    assert r.json()["reply"].count("CyberGuard verdict") == 1
    assert len(scan_sources(auth_client)) == before + 1


def test_history_shows_whether_an_action_was_done(auth_client, fake):
    ioc_id = _ioc(user_id(auth_client), "192.0.2.77")
    fake(tool="prepare_allowlist_indicator", tool_args={"value": "192.0.2.77"})
    aid = auth_client.post("/api/chat", json={"message": "allowlist 192.0.2.77"}).json()["actions"][0]["id"]
    acts = [a for h in auth_client.get("/api/chat/history").json() for a in h.get("actions", [])]
    assert acts[-1]["status"] == "pending"
    auth_client.post(f"/api/chat/actions/{aid}/confirm")
    acts = [a for h in auth_client.get("/api/chat/history").json() for a in h.get("actions", [])]
    assert acts[-1]["status"] == "done"
    chat_actions.reset_for_tests()                                  # = backend restart: still shown as done
    acts = [a for h in auth_client.get("/api/chat/history").json() for a in h.get("actions", [])]
    assert acts[-1]["status"] == "done"


def test_an_unconfirmed_action_expires_after_a_restart(auth_client, fake):
    _ioc(user_id(auth_client), "192.0.2.78")
    fake(tool="prepare_allowlist_indicator", tool_args={"value": "192.0.2.78"})
    auth_client.post("/api/chat", json={"message": "allowlist 192.0.2.78"})
    chat_actions.reset_for_tests()
    acts = [a for h in auth_client.get("/api/chat/history").json() for a in h.get("actions", [])]
    assert acts[-1]["status"] == "expired"
