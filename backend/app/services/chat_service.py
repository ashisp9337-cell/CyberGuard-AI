"""
Real AI chat assistant, backed by Google's Gemini API — genuinely
generates answers, not a keyword-matched or canned-response bot.

Built to be resilient to the two real failure modes seen in production:
  1. Transient server overload (503/429) -> automatic retry with backoff.
  2. A specific model being deprecated/unavailable -> automatic fallback
     to a second model alias.
Both are handled server-side so the user just sees a normal reply, or a
clean, human-readable error only if every attempt genuinely fails.

Keeps per-user conversation history in memory (process-local; resets on
backend restart).
"""
import time
import logging

from google import genai
from google.genai import types, errors
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.services.chat_tools import build_tools

settings = get_settings()
logger = logging.getLogger("cyberguard.chat")

SYSTEM_PROMPT = """You are Threatora, the AI Security Assistant built into the CyberGuard AI \
platform — a cybersecurity education and threat-detection tool.

Your job:
1. Explain cybersecurity concepts clearly: phishing, deepfakes, digital impersonation, \
credential theft / account takeover, malicious URLs, and general cyber threats.
2. Explain WHY specific attacks work (social engineering tactics, urgency, authority, \
brand impersonation) and HOW to recognize and avoid them.
3. Answer questions about this specific platform: it has 6 detection modules \
(Phishing Detection, Deepfake Detection, Digital Impersonation, Credential Theft & \
Account Takeover, Malicious URL & Website Detection, Intelligent Cyber Threat \
Detection), each with real trained ML models and rule-based detectors, real scan \
history, dashboard, reports, and live monitoring.
4. You have tools to look up the CURRENT USER'S OWN real data across the whole \
platform: recent scans and their full details, overall security summary, threat \
distribution by module, recent alerts/notifications, generated reports, current \
settings, and basic account info. ALWAYS call the relevant tool when asked about \
"my scans", "my alerts", "my reports", "my settings", "my account", or similar — \
never guess, invent, or approximate this data from general knowledge. If a tool \
returns no data (e.g. no scans yet), say so plainly rather than making something up.
5. Keep answers concise and practical by default; go deeper only if asked.
6. Never ask for or store passwords, API keys, or other credentials in this chat.
7. If asked something outside cybersecurity/this platform, answer briefly if you \
can, but gently steer back to what you're here for.

You are talking to a real person who may be a student, developer, or security \
learner. Be direct, accurate, and avoid unnecessary hedging or filler."""

# Tried in order. The first is Google's auto-updating "always current fast
# model" alias; the second is a distinct alias as a fallback in case the
# first is ever degraded/unavailable specifically (not just transiently busy).
MODEL_CHAIN = ["gemini-flash-latest", "gemini-flash-lite-latest"]

RETRYABLE_CODES = {429, 503}
RETRYABLE_STATUSES = {"UNAVAILABLE", "RESOURCE_EXHAUSTED", "DEADLINE_EXCEEDED"}
MAX_RETRIES_PER_MODEL = 2
BACKOFF_SECONDS = [0.6, 1.8]

_client: genai.Client | None = None


def _get_client() -> genai.Client | None:
    global _client
    if not settings.GEMINI_API_KEY:
        return None
    if _client is None:
        _client = genai.Client(api_key=settings.GEMINI_API_KEY)
    return _client


class ChatUnavailableError(Exception):
    pass


def _is_retryable(e: "errors.APIError") -> bool:
    return getattr(e, "code", None) in RETRYABLE_CODES or getattr(e, "status", None) in RETRYABLE_STATUSES


# Per-user chat history, kept as plain (role, text) pairs so it can be
# replayed against whichever model in MODEL_CHAIN ends up answering —
# a single google-genai ChatSession is bound to one model, which doesn't
# work once we need to fail over between models mid-conversation.
_histories: dict[str, list[dict]] = {}


def _build_contents(user_id: str, message: str) -> list[dict]:
    history = _histories.setdefault(user_id, [])
    history.append({"role": "user", "parts": [{"text": message}]})
    return history


def send_message(user_id: str, message: str, db: Session) -> str:
    """Sends a message and returns the reply. Retries transient failures on
    the current model, then fails over to the next model in MODEL_CHAIN."""
    if not message or not message.strip():
        return "Ask me anything about phishing, deepfakes, account security, or how CyberGuard's detection works."

    client = _get_client()
    if client is None:
        raise ChatUnavailableError(
            "The AI assistant isn't configured on this server. Set GEMINI_API_KEY in backend/.env."
        )

    contents = _build_contents(user_id, message.strip())
    tools = build_tools(db, user_id)
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        temperature=0.4,
        max_output_tokens=1024,
        tools=tools,
    )

    last_error: Exception | None = None
    for model in MODEL_CHAIN:
        for attempt in range(MAX_RETRIES_PER_MODEL + 1):
            try:
                response = client.models.generate_content(model=model, contents=contents, config=config)
                reply = response.text or "I couldn't generate a response to that — try rephrasing your question."
                _histories[user_id].append({"role": "model", "parts": [{"text": reply}]})
                return reply
            except errors.APIError as e:
                last_error = e
                retryable = _is_retryable(e)
                logger.warning(f"Gemini call failed (model={model}, attempt={attempt}, retryable={retryable}): {e}")
                if retryable and attempt < MAX_RETRIES_PER_MODEL:
                    time.sleep(BACKOFF_SECONDS[attempt])
                    continue
                break  # move to next model in the chain
            except Exception as e:
                last_error = e
                logger.warning(f"Gemini call failed unexpectedly (model={model}): {e}")
                break

    # Every model/retry combination failed — remove the unanswered user
    # turn so the next attempt doesn't replay a broken conversation state.
    if _histories.get(user_id):
        _histories[user_id].pop()

    clean_message = getattr(last_error, "message", None) or str(last_error)
    raise ChatUnavailableError(
        f"The AI assistant is temporarily unavailable ({clean_message}). Please try again in a moment."
    )


def reset_session(user_id: str) -> None:
    _histories.pop(user_id, None)