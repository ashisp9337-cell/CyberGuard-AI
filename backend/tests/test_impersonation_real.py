"""Retrained impersonation models: sender-domain matching, the brand 'held until you pay' rule, and wiring."""
import os

import pytest

from app.detectors import brand_impersonation as B
from app.detectors import financial_impersonation as Fi

MODELS = os.path.join(os.path.dirname(__file__), "..", "app", "ml", "models")


class Fixed:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        return [[1 - self.p, self.p] for _ in X]


@pytest.fixture()
def neutral_models(monkeypatch):
    """Rules only matter here, so give both detectors a model that is unsure (50%)."""
    monkeypatch.setattr(B, "_get_model", lambda: Fixed(0.5))
    monkeypatch.setattr(Fi, "_get_model", lambda: Fixed(0.5))


def _labels(r):
    return [i["label"] for i in r["indicators"] if i["triggered"]]


def test_brand_subdomains_are_the_brands_own(neutral_models):
    text = "Netflix: your payment failed, update your card in the app"
    for sender in ("info@netflix.com", "info@account.netflix.com"):
        assert "Sender domain does not match the claimed brand" not in _labels(
            B.analyze_brand_impersonation(text, {"senderEmail": sender}, "x"))
    for sender in ("mailer@netflix.com.secure-billing.top", "netflix@gmail.com"):
        assert "Sender domain does not match the claimed brand" in _labels(
            B.analyze_brand_impersonation(text, {"senderEmail": sender}, "x"))


def test_bank_subdomains_are_the_banks_own(neutral_models):
    text = "HDFC Bank: Rs 2,450 debited from A/c XX1234 on 14-Oct. Not you? Call 18002026161."
    ok = Fi.analyze_financial_impersonation(text, {"senderEmail": "alerts@alerts.hdfcbank.net"}, "x")
    bad = Fi.analyze_financial_impersonation(text, {"senderEmail": "hdfcbank.net@secure-kyc.top"}, "x")
    assert "Sender domain does not match the claimed institution" not in _labels(ok)
    assert "Sender domain does not match the claimed institution" in _labels(bad)


@pytest.mark.parametrize("text", [
    "ur netflix acct is on hold pls update ur card asap link below",
    "DHL: Your parcel is on hold due to unpaid customs fees. Pay Rs 49 now to release delivery.",
])
def test_held_until_you_pay_is_at_least_suspicious(monkeypatch, text):
    monkeypatch.setattr(B, "_get_model", lambda: Fixed(0.1))        # even if the model is unsure
    r = B.analyze_brand_impersonation(text, {}, "x")
    assert "Account or parcel held until you pay" in _labels(r) and r["riskScore"] >= 51


def test_held_rule_not_used_against_the_real_sender(monkeypatch):
    monkeypatch.setattr(B, "_get_model", lambda: Fixed(0.1))
    r = B.analyze_brand_impersonation("Netflix: your payment failed, update your card in the app",
                                      {"senderEmail": "info@netflix.com"}, "x")
    assert "Account or parcel held until you pay" not in _labels(r) and r["riskScore"] < 51


def test_normal_delivery_update_is_not_a_hold_scam(neutral_models):
    r = B.analyze_brand_impersonation("Your Amazon order has been shipped and will arrive on Friday.", {}, "x")
    assert "Account or parcel held until you pay" not in _labels(r)


@pytest.mark.parametrize("name", ["financial_impersonation", "brand_impersonation",
                                  "government_official_impersonation"])
def test_retrained_models_report_real_held_out_results(name):
    import json
    path = os.path.join(MODELS, f"{name}.metrics.json")
    if not os.path.exists(path):
        pytest.skip("model metrics not present")
    info = json.load(open(path))
    new = info["results"]["new_detector"]
    genuine = [v["false_alarm_rate"] for k, v in new.items() if "genuine" in k]
    assert max(genuine) <= 0.06                     # few false alarms on REAL genuine messages
    assert info["training_rows"]["real_genuine_on_topic"] > 0
