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


def test_no_internet_goes_straight_to_the_backup_answer(monkeypatch):
    """Wi-Fi drop on demo day: one failed connection, no second model, the built-in backup answer comes back."""
    calls = []

    class FakeModels:
        def generate_content(self, model, contents, config):
            calls.append(model)
            raise httpx.ConnectError("[Errno 11001] getaddrinfo failed")

    monkeypatch.setattr(C, "_get_client", lambda: type("Cl", (), {"models": FakeModels()})())
    monkeypatch.setattr(C, "build_tools", lambda db, user_id, ctx=None: [])
    reply = C.send_message("offline-test-user", "what is phishing?", db=None)
    assert len(calls) == 1 and reply


def test_a_slow_google_is_cut_off_by_the_total_reply_budget(monkeypatch):
    """Each attempt 'takes' 20 s and fails with a retryable 503: no new attempt starts after TOTAL_DEADLINE_S."""
    from google.genai import errors
    clock = [0.0]
    calls = []

    class FakeModels:
        def generate_content(self, model, contents, config):
            calls.append(model)
            clock[0] += 20
            raise errors.ServerError(503, {"error": {"code": 503, "message": "overloaded", "status": "UNAVAILABLE"}})

    monkeypatch.setattr(C, "_now", lambda: clock[0])
    monkeypatch.setattr(C.time, "sleep", lambda s: None)
    monkeypatch.setattr(C, "_get_client", lambda: type("Cl", (), {"models": FakeModels()})())
    monkeypatch.setattr(C, "build_tools", lambda db, user_id, ctx=None: [])
    reply = C.send_message("slow-test-user", "what is phishing?", db=None)
    assert reply and len(calls) == 2             # 0 s and 20 s start; at 40 s the budget (25 s) is used up
