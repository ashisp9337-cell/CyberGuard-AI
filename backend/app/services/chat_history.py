"""
Threatora conversation history in PostgreSQL (table chat_messages, added 21 Oct).

- Every user message and every reply is saved, so the chat is still there after the backend restarts or the page
  is reloaded. "Clear conversation" deletes the user's rows.
- The text is stored as the USER saw it (their own data, in their own database). What goes to Google is still
  masked: after a restart, chat_service re-masks the stored turns before sending them as context.
- Saving never breaks the chat: a database problem is logged and the reply is still returned.
"""
from __future__ import annotations

import logging

from app.db.models import ChatMessage

logger = logging.getLogger("cyberguard.chat")
KEEP_PER_USER = 300            # older rows are deleted
CONTEXT_TURNS = 20             # how many stored messages are replayed to the AI after a restart


def save(db, user_id: str, role: str, text: str, language: str | None = None, meta: dict | None = None) -> str | None:
    if db is None or not user_id:
        return None
    try:
        row = ChatMessage(user_id=user_id, role=role, text=(text or "")[:20000], language=language, meta=meta or {})
        db.add(row)
        db.commit()
        _trim(db, user_id)
        return row.id
    except Exception:  # noqa: BLE001 - history is best-effort
        logger.exception("could not save a chat message")
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None


def _trim(db, user_id: str) -> None:
    ids = [r[0] for r in db.query(ChatMessage.id).filter(ChatMessage.user_id == user_id)
           .order_by(ChatMessage.created_at.desc()).offset(KEEP_PER_USER).all()]
    if ids:
        db.query(ChatMessage).filter(ChatMessage.id.in_(ids)).delete(synchronize_session=False)
        db.commit()


def recent(db, user_id: str, limit: int = 50) -> list[ChatMessage]:
    """Oldest first, the last `limit` messages."""
    if db is None:
        return []
    try:
        rows = (db.query(ChatMessage).filter(ChatMessage.user_id == user_id)
                .order_by(ChatMessage.created_at.desc()).limit(max(1, min(limit, 200))).all())
        return list(reversed(rows))
    except Exception:  # noqa: BLE001
        logger.exception("could not read the chat history")
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return []


def clear(db, user_id: str) -> int:
    if db is None:
        return 0
    n = db.query(ChatMessage).filter(ChatMessage.user_id == user_id).delete(synchronize_session=False)
    db.commit()
    return n


def set_action_status(db, user_id: str, action_id: str, status: str) -> None:
    """Remember in the saved history that an action was confirmed / cancelled (so a reload shows it)."""
    try:
        for row in recent(db, user_id, 100):
            acts = (row.meta or {}).get("actions") or []
            if any(a.get("id") == action_id for a in acts):
                row.meta = {**row.meta, "actions": [a | {"status": status} if a.get("id") == action_id else a
                                                    for a in acts]}
                db.commit()
                return
    except Exception:  # noqa: BLE001
        logger.exception("could not update an action in the chat history")
        db.rollback()


def to_dict(row: ChatMessage) -> dict:
    return {"id": row.id, "role": row.role, "text": row.text, "language": row.language,
            "createdAt": row.created_at.isoformat() if row.created_at else None, **(row.meta or {})}
