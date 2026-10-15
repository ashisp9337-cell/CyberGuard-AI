from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.core.rate_limit import limiter
from app.db.database import get_db
from app.db.models import User
from app.schemas.chat import ChatMessageRequest, ChatMessageResponse
from app.services.chat_service import send_message, reset_session, ChatUnavailableError

router = APIRouter(prefix="/api/chat", tags=["chat"])


@router.post("", response_model=ChatMessageResponse)
@limiter.limit("20/minute")
def chat(request: Request, body: ChatMessageRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        reply = send_message(user.id, body.message, db)
    except ChatUnavailableError as e:
        raise HTTPException(status_code=503, detail={"error": {"code": "CHAT_UNAVAILABLE", "message": str(e)}})
    return ChatMessageResponse(reply=reply)


@router.post("/reset")
def chat_reset(user: User = Depends(get_current_user)):
    reset_session(user.id)
    return {"success": True}