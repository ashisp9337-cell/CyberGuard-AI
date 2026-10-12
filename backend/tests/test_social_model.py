"""Social-media scam model (phishing_social.joblib): loads for the social-media subtopic and separates
obvious scams from normal chat. Skipped when the model has not been trained on this machine."""
import os

import pytest

from app.core.config import get_settings

MODEL = os.path.join(get_settings().MODELS_DIR, "phishing_social.joblib")
pytestmark = pytest.mark.skipif(not os.path.exists(MODEL), reason="phishing_social.joblib not trained here")


def test_social_model_is_used_and_separates_scams():
    from app.detectors import phishing
    model = phishing._get_model("social-media-analysis")
    assert model is not None
    scam = model.predict_proba(["You won our giveaway! Send your bank details and OTP to claim the prize now"])[0][1]
    normal = model.predict_proba(["haha see you at the library at 5, bring the notes"])[0][1]
    assert scam > 0.5 > normal


def test_social_scan_reports_the_trained_model():
    from app.detectors import phishing
    r = phishing.analyze_text("FREE gift card codes!!! claim yours now at http://bit.ly/x before they run out",
                              subtopic_title="Social Media Message Analysis", subtopic_id="social-media-analysis")
    assert r["classification"] != "safe"
