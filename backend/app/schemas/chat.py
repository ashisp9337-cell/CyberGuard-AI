from typing import Literal

from pydantic import BaseModel, Field

from app.core.config import get_settings


class ChatMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=get_settings().MAX_CHAT_CHARS)
    language: Literal["en", "hi", "or"] | None = None      # reply language: English, Hindi, Odia


class ChatAction(BaseModel):
    id: str
    kind: str
    summary: str
    status: str


class ChatMessageResponse(BaseModel):
    reply: str
    actions: list[ChatAction] = []        # actions the AI prepared; they run only when the user presses Confirm