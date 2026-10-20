"""The extra details the result page shows: auto-detect routing, every trained model's verdict, image provenance,
the read-only link check and the detectors run for an unclear impersonation - whitelisted and size-capped."""
from app.services.scan_store import detail_fields


def test_routing_is_shown_without_internal_names():
    r = detail_fields({"routing": {"mode": "auto", "subtopicId": "contact-impersonation", "subtopicTitle": "Friend",
                                   "method": "claimed-identity", "reasons": ["opens like a family member (Hi Mum)"],
                                   "secondary": [], "status": "ok", "detector": "known_contact_impersonation.analyze_x",
                                   "detectorNote": ""}})
    assert r["autoDetect"]["subtopicId"] == "contact-impersonation" and r["autoDetect"]["note"] == ""
    assert "analyze" not in str(r["autoDetect"])
    assert detail_fields({})["autoDetect"] is None


def test_image_models_and_provenance():
    res = {"aiImageModel": {"probability": 0.97, "level": "high", "views": [0.2, 0.97, 0.1], "alertThreshold": 0.9,
                            "verifyThreshold": 0.59},
           "deepfakeModel": {"probability": 0.79, "level": "low", "faces": [{"box": [1, 2, 3, 4], "probability": 0.79}],
                             "wholeImage": False, "alertThreshold": 0.9999999957, "verifyThreshold": 0.9999977},
           "provenance": {"proof": True, "hasContentCredentials": True,
                          "findings": [{"label": "Content Credentials: made with AI", "detail": "x" * 900, "proof": True}]}}
    r = detail_fields(res)
    names = [m["name"] for m in r["modelDetails"]]
    assert names == ["AI-generated image model (CLIP ViT-L/14)", "Face-swap model (EfficientNet-B0)"]
    assert r["modelDetails"][0]["notes"] == ["3 parts of the picture checked; the most AI-looking one decides"]
    assert r["modelDetails"][1]["notes"] == ["Face 1: raw score 79%"]
    assert r["provenance"]["proof"] and len(r["provenance"]["findings"][0]["detail"]) == 300


def test_url_and_login_models_and_live_check():
    res = {"subtopicModel": {"subtopic": "lookalike-domain", "model": "Look-alike domain model", "probability": 0.98,
                             "level": "high", "brandDomain": "paypal.com", "tricks": ["digits that look like letters"],
                             "alertThreshold": 0.8, "verifyThreshold": 0.5},
           "urlModels": [{"subtopic": "lookalike-domain", "model": "Look-alike domain model", "level": "high", "probability": 0.98},
                         {"subtopic": "domain-spoofing", "model": "Domain spoofing model", "level": "low", "probability": 0.1}],
           "liveCheck": {"status": "ok", "reason": "", "finalUrl": "https://evil.example/login",
                         "redirectChain": ["start: http://bit.ly/x (301)", "redirect: https://evil.example/login (200)"],
                         "page": {"title": "PayPal", "has_password": True, "brands_imitated": ["paypal"],
                                  "external_form_targets": [], "sensitive_fields": ["otp"]}},
           "checkedDetectors": [{"detector": "Brand", "riskScore": 40}]}
    r = detail_fields(res)
    assert [m["name"] for m in r["modelDetails"]] == ["Look-alike domain model", "Domain spoofing model"]
    assert "Imitated real site: paypal.com" in r["modelDetails"][0]["notes"]
    assert r["liveCheck"]["page"]["hasPassword"] and len(r["liveCheck"]["redirectChain"]) == 2
    assert r["checkedDetectors"] == [{"detector": "Brand", "riskScore": 40}]
    login = detail_fields({"modelAssessment": {"percentile": 99.5, "level": "high", "verifyPercentile": 95,
                                               "alertPercentile": 99, "loginsScored": 4, "loginsFlagged": 1,
                                               "reasons": ["country never seen for this account"]}})
    m = login["modelDetails"][0]
    assert m["kind"] == "percentile" and m["probability"] == 0.995 and "1 of 4 logins flagged" in m["notes"]


def test_bad_or_missing_values_never_break_the_page():
    r = detail_fields({"aiImageModel": {"probability": "x"}, "deepfakeModel": {"faces": "bad"}, "liveCheck": "nope",
                       "provenance": [], "checkedDetectors": ["x", {"detector": None, "riskScore": "y"}]})
    assert r["modelDetails"][0]["probability"] is None and r["liveCheck"] is None and r["provenance"] is None
    assert r["checkedDetectors"] == [{"detector": "None", "riskScore": 0}]
