"""Friend / relative / known-contact impersonation: the 'Hi Mum, new number' scam script, the trained router,
tested on REAL reported scam messages and real personal SMS."""
import re

import numpy as np
import pandas as pd
import pytest

from app.detectors import known_contact_impersonation as K
from app.services import subtopic_router as R

DATA = "app/ml/training/data/"


def score(text, **extra):
    return K.analyze_known_contact_message(text, extra, "Friend / Relative / Known Contact Impersonation")


@pytest.mark.parametrize("text,low,high", [
    ("Hi Papa, this is my new number. UPI isn't working on the new phone. Please send 3000, I'm in class", 85, 100),
    ("Hey Dad, I'm in trouble. I lost my phone and need money - please text me at this number.", 80, 100),
    ("Hey, it's me! I lost my wallet. Can you send me Rs 5,000?", 80, 100),
    ("I sent you an OTP by mistake, please share it", 75, 100),
    ("Hi Mum, I lost my phone, this is my new number", 51, 70),            # opening message: verify, not alarm
    ("Hey mum, can lend me 500 for camp first? I need to top up some of the funds.", 51, 70),  # real child: verify
    ("Hey mom! I'm gonna be home in an hour, see you soon!", 0, 25),
    ("This is my new number by the way. Catching up on some sleep.", 0, 50),
])
def test_script_levels(text, low, high):
    r = score(text)
    assert low <= r["riskScore"] <= high, (r["riskScore"], r["explanation"])


def test_alert_explains_the_script_and_what_to_do():
    r = score("Hi Mum, I broke my phone, this is my new number. Need to pay a bill urgently, can you send 4000 on GPay?")
    assert r["riskScore"] >= 85 and "Hi Mum, new number" in r["explanation"] and "OLD number" in r["explanation"]
    labels = {i["label"] for i in r["indicators"] if i["triggered"]}
    assert {"Story to explain an unknown number", "Asks for money or bank details"} <= labels


def test_real_reported_scams_and_real_personal_sms():
    pos = pd.read_csv(DATA + "known_contact_scams_real.tsv", sep="\t")
    caught = np.mean([score(t)["riskScore"] >= 51 for t in pos.text])
    rows = [ln.rstrip("\n").partition("\t") for ln in open(DATA + "phishing_sms_clean_v2.tsv", encoding="utf-8",
                                                          errors="replace")][1:]
    rel = re.compile(r"\b(mum|mom|mummy|dad|daddy|papa|son|daughter|beta|bro|brother|sis|sister|friend)\b|new number", re.I)
    genuine = [t for lab, _, t in rows if lab == "legitimate" and rel.search(t)][:600]
    false_alarm = np.mean([score(t)["riskScore"] >= 71 for t in genuine])
    assert caught >= 0.8 and false_alarm <= 0.005


def test_router_sends_each_identity_to_its_subtopic():
    if R._router_model() is None:
        pytest.skip("impersonation_router.joblib not installed")
    cases = {
        "Dear customer, your SBI account will be blocked today. Update KYC at sbi-kyc.in": "financial-impersonation",
        "Hi Mum, this is my new number, my phone fell in water. Send 5000 on UPI": "contact-impersonation",
        "Your Amazon order #123 could not be delivered. Pay Rs 25 redelivery fee": "brand-impersonation",
        "Hi, this is your CEO. I'm in a meeting, buy 5 gift cards for a client and send the codes": "management-impersonation",
        "Dear Student, your hall ticket is blocked due to pending exam fee. Pay now": "teacher-impersonation",
        "Income Tax Department: you are eligible for a refund of Rs 15,490. Submit bank details": "government-impersonation",
        "Bro it's me Rahul, new number. Need 2000 urgently, will return tomorrow": "contact-impersonation",
        "Congratulations! You have won 25 lakh in KBC lottery. Call now to claim.": "generic",
    }
    for text, want in cases.items():
        got = R.classify(module_id="impersonation", text_input=text, url_input=None, file_path=None,
                         file_name=None, extra_field_values={}).subtopic_id
        assert got == want, (text, got)


def test_router_without_model_still_uses_rules(monkeypatch):
    monkeypatch.setattr(R, "_router_model", lambda: None)
    c = R.classify(module_id="impersonation", text_input="Hi Mum, I lost my phone, this is my new number",
                   url_input=None, file_path=None, file_name=None, extra_field_values={})
    assert c.subtopic_id == "contact-impersonation"
