from pydantic import BaseModel, Field

from app.core.config import get_settings


class ChatMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=get_settings().MAX_CHAT_CHARS)


class ChatMessageResponse(BaseModel):
    reply: str