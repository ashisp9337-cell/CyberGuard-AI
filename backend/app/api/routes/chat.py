import json
import os
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.core.rate_limit import limiter
from app.db.database import SessionLocal, get_db
from app.db.models import User
from app.schemas.chat import ChatMessageRequest, ChatMessageResponse
from app.services import chat_actions, chat_history
from app.services.chat_service import (ChatUnavailableError, reset_session, send_message_full, stream_message)

router = APIRouter(prefix="/api/chat", tags=["chat"])
IMAGE_TYPES = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
MAX_IMAGE_MB = 10


def _err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


@router.post("", response_model=ChatMessageResponse)
@limiter.limit("20/minute")
def chat(request: Request, body: ChatMessageRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        out = send_message_full(user.id, body.message, db, language=body.language)
    except ChatUnavailableError as e:
        raise HTTPException(status_code=503, detail={"error": {"code": "CHAT_UNAVAILABLE", "message": str(e)}})
    return ChatMessageResponse(reply=out["reply"], actions=out["actions"])


@router.post("/stream")
@limiter.limit("20/minute")
def chat_stream(request: Request, body: ChatMessageRequest, user: User = Depends(get_current_user)):
    """Server-Sent Events: `data: {"type": "delta", "text": ...}` while the reply is written, then
    `data: {"type": "done", "reply": ..., "actions": [...]}`."""
    user_id = user.id

    def events():
        db = SessionLocal()                         # own session: it must live as long as the stream
        try:
            for ev in stream_message(user_id, body.message, db, language=body.language):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
        except Exception:  # noqa: BLE001 - the browser gets a clean end instead of a broken stream
            import logging
            logging.getLogger("cyberguard.chat").exception("chat stream failed")
            yield "data: " + json.dumps({"type": "error", "message": "Threatora hit an error. Please try again."}) + "\n\n"
        finally:
            db.close()

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/image")
@limiter.limit("10/minute")
async def chat_image(request: Request, file: UploadFile = File(...), message: str = Form(""),
                     language: str = Form("en"), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A screenshot in the chat: read on THIS computer (QR + OCR), scanned by the detectors, then explained.
    The image itself is never sent to the AI."""
    from starlette.concurrency import run_in_threadpool
    from app.services import screenshot_reader

    name = os.path.basename(file.filename or "screenshot.png")[:120]
    ext = os.path.splitext(name)[1].lower()
    if ext not in IMAGE_TYPES:
        raise _err(422, "UNSUPPORTED_IMAGE", "Send a PNG, JPG, WEBP or BMP screenshot.")
    data = await file.read(MAX_IMAGE_MB * 1024 * 1024 + 1)
    if len(data) > MAX_IMAGE_MB * 1024 * 1024:
        raise _err(413, "IMAGE_TOO_LARGE", f"The screenshot is larger than {MAX_IMAGE_MB} MB.")
    if len(message) > get_settings().MAX_CHAT_CHARS:
        raise _err(422, "MESSAGE_TOO_LONG", "The question is too long.")
    lang = language if language in ("en", "hi", "or") else "en"
    try:                                                # must really be an image (not a renamed file)
        import io
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            im.verify()
    except Exception:  # noqa: BLE001
        raise _err(422, "NOT_AN_IMAGE", "That file is not a readable image.")
    folder = os.path.join(get_settings().UPLOAD_DIR, "chat_tmp")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{uuid.uuid4().hex}{ext}")
    try:
        with open(path, "wb") as f:
            f.write(data)

        def work():
            info = screenshot_reader.scan(db, user.id, path, name, source="chat")
            shown = f"📷 {name}" + (f"\n{message.strip()}" if message.strip() else "")
            out = send_message_full(user.id, screenshot_reader.describe_for_ai(message, info), db, language=lang,
                                    display_text=shown, pre_scans=info["scans"], attachment=name)
            return out | {"ocr": info["ocr"], "textFound": bool(info["text"].strip()), "qrFound": len(info["qr"])}
        return await run_in_threadpool(work)
    finally:
        try:
            os.remove(path)                             # the screenshot is not kept
        except OSError:
            pass


@router.get("/history")
def chat_history_list(limit: int = 50, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    items = [chat_history.to_dict(r) for r in chat_history.recent(db, user.id, limit)]
    for it in items:                                    # a prepared action can only be confirmed while it is live
        for a in it.get("actions") or []:
            if a.get("status") in ("pending", "running"):
                a["status"] = chat_actions.current_status(user.id, a["id"])
    return items


@router.post("/reset")
def chat_reset(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    reset_session(user.id, db)
    return {"success": True}


@router.post("/actions/{action_id}/confirm")
@limiter.limit("20/minute")
def confirm_action(request: Request, action_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        out = chat_actions.confirm(db, user, action_id, request)
    except chat_actions.ActionError as e:
        if e.code == "ACTION_FAILED":                  # a real failure is worth keeping in the conversation
            chat_history.set_action_status(db, user.id, action_id, "failed")
            chat_history.save(db, user.id, "assistant", f"⚠️ {e.message}")
        raise _err(e.status, e.code, e.message)
    chat_history.set_action_status(db, user.id, action_id, "done")
    chat_history.save(db, user.id, "assistant", f"✅ {out['message']}")
    return out


@router.post("/actions/{action_id}/cancel")
def cancel_action(action_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        out = chat_actions.cancel(user.id, action_id)
    except chat_actions.ActionError as e:
        raise _err(e.status, e.code, e.message)
    chat_history.set_action_status(db, user.id, action_id, "cancelled")
    chat_history.save(db, user.id, "assistant", out["message"])
    return out
