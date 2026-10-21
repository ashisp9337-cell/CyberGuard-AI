"""Chat assistant (20 Oct): a Gemini request that hangs is dropped after a time limit and the backup model answers."""
import httpx
from google import genai

from app.services import chat_service as C


def test_the_gemini_client_has_a_time_limit(monkeypatch):
    monkeypatch.setattr(C.settings, "GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(C, "_client", None)
    client = C._get_client()
    assert C.REQUEST_TIMEOUT_MS <= 30_000
    assert client._api_client._http_options.timeout == C.REQUEST_TIMEOUT_MS


def test_a_hanging_model_is_skipped_and_the_backup_model_answers(monkeypatch):
    calls = []

    class FakeModels:
        def generate_content(self, model, contents, config):
            calls.append(model)
            if model == C.MODEL_CHAIN[0]:
                raise httpx.ReadTimeout("timed out")              # what a request past the time limit raises
            return type("R", (), {"text": "backup model answer"})()

    monkeypatch.setattr(C, "_get_client", lambda: type("Cl", (), {"models": FakeModels()})())
    monkeypatch.setattr(C, "build_tools", lambda db, user_id, ctx=None: [])
    assert C.send_message("timeout-test-user", "what is phishing?", db=None) == "backup model answer"
    assert calls == C.MODEL_CHAIN[:2]
