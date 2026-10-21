"""Text-scam fixes from the Phase 2 audit (19 Oct): government "digital arrest" scripts, shared scam patterns and
bare-domain links. Every example here is worded differently from the Phase 2 samples, so the tests check the
idea, not one sentence."""
import pytest

from app.detectors import government_impersonation as G
from app.detectors import phishing
from app.services.analysis_service import run_scan


def score(module, sub, text):
    return run_scan(module_id=module, subtopic_id=sub, subtopic_title=sub, text_input=text, url_input=None,
                    file_path=None, file_name=None, extra_field_values={})["riskScore"]


# ---- government impersonation -------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    "Narcotics Control Bureau: a courier booked on your Aadhaar contains 200g MDMA. An FIR is registered. Stay on this "
    "video call, do not inform your family, and transfer Rs 1,80,000 for verification or you will be arrested.",
    "ED officer here. Your bank account is used in a hawala case. Pay the refundable security deposit today to clear your name.",
    "Delhi Police Crime Branch: non-bailable warrant issued against you. Press 1 to talk to the investigating officer.",
    "Your GST registration will be cancelled. Pay the penalty of Rs 4,500 now at gst-penalty-portal.online",
    "Income tax refund of Rs 9,820 approved. To receive it, enter your net banking password and ATM PIN on the form.",
])
def test_government_scam_scripts_are_flagged(text):
    assert score("impersonation", "government-impersonation", text) >= 71, text


@pytest.mark.parametrize("text", [
    "Your income tax return for AY 2026-27 has been processed and the refund has been credited to your bank account.",
    "Passport has been dispatched by Speed Post. Track it on www.passportindia.gov.in",
    "EPFO: Your PF claim has been approved and will be credited in 3 working days.",
    "Traffic Police: e-challan OD12345 of Rs 1000 has been paid successfully. Receipt on echallan.parivahan.gov.in",
])
def test_genuine_government_notices_are_not_flagged(text):
    assert score("impersonation", "government-impersonation", text) < 51, text


def test_a_threat_alone_is_verify_not_alert():
    _, floor, _ = G.scam_script("Customs department: your parcel was seized for containing illegal items.")
    assert floor == 55


def test_official_links_are_not_counted_as_bad_links():
    inds, _, _ = G.scam_script("UIDAI: download your updated e-Aadhaar from myaadhaar.uidai.gov.in")
    assert not any(i["label"] == "Link to a non-government website" for i in inds)


# ---- shared scam patterns -----------------------------------------------------------------------------
@pytest.mark.parametrize("sub,text", [
    ("sms-analysis", "DTDC: shipment 88231 is held at our hub, address incomplete. Pay Rs 30 charge to re-deliver: dtdc-help.click"),
    ("social-media-analysis", "My uncle turned $500 into $9,000 with bitcoin trading, inbox @cryptoqueen_signals on Telegram, guaranteed returns"),
    ("social-media-analysis", "Part time job: rate hotels on Google and earn Rs 3000 per day, small registration fee to join"),
    ("social-media-analysis", "Your page will be permanently disabled for community guidelines violation. Submit an appeal: fb-appeal-center.help"),
    ("sms-analysis", "Spotify: your payment was declined. Update your billing details at spotify-account-renew.top to keep Premium"),
    ("sms-analysis", "Dad it's Aman, lost my wallet at the station and my card got blocked, please send 6000 on PhonePe to this number"),
])
def test_scam_patterns_catch_reworded_scams(sub, text):
    assert score("phishing", sub, text) >= 51, text


@pytest.mark.parametrize("sub,text", [
    ("sms-analysis", "Your Amazon parcel will arrive tomorrow between 10 am and 2 pm. No action needed."),
    ("sms-analysis", "Payment of Rs 499 for your Airtel bill was successful. Thank you."),
    # was a known false alarm (xfail) until 21 Oct: promotion that asks for nothing is now held at 50
    ("social-media-analysis", "Join our free webinar on stock market basics this Sunday, link in bio"),
    ("social-media-analysis", "My phone got stuck on the boot logo after the update, any idea how to fix it?"),
])
def test_scam_patterns_do_not_flag_normal_messages(sub, text):
    assert score("phishing", sub, text) < 51, text


def test_executive_fraud_needs_secrecy_close_to_the_payment_request():
    scam = "Hi, this is the MD. Keep this strictly confidential and wire the deposit for the acquisition today."
    _, floor = phishing.scam_patterns(scam)
    assert floor == 75
    newsletter = ("Our director spoke at the energy conference in Houston about market trends. " + "Filler text. " * 40 +
                  "The merger with our partner was approved by regulators and funds were released last quarter.")
    _, floor = phishing.scam_patterns(newsletter)
    assert floor == 0


def test_contact_emergency_scam_in_the_contact_detector():
    text = "Hey it's Neha, I'm stranded at the airport and my card is blocked, please transfer Rs 9000 to this UPI ID"
    assert score("impersonation", "contact-impersonation", text) >= 71


def test_email_addresses_are_not_social_handles():
    _, floor = phishing.scam_patterns("Training on trading software, contact nesa@energyexpo.org, fee $450 per seat")
    assert floor == 0


# ---- bare domains --------------------------------------------------------------------------------
def test_bare_domains_are_found_and_trusted_sites_are_left_out():
    found = phishing.bare_domains("Pay at indiapost-track.cyou or check swiggy.com, mail me at a.b@gmail.com")
    assert found == ["http://indiapost-track.cyou"]


def test_only_risky_looking_bare_domains_count_as_suspicious_links():
    assert phishing.risky_bare_domains("Rate us at m9s.in/hut3q") == []
    assert phishing.risky_bare_domains("Pay at sbi-kyc-update.in now") == ["http://sbi-kyc-update.in"]
    assert phishing.risky_bare_domains("visit claim-bonus.top") == ["http://claim-bonus.top"]


# ---- one-time-code messages, electricity and code-forward scams (validation round, 19 Oct) ----------
@pytest.mark.parametrize("text", [
    "Your OTP for login to the BPUT student portal is 482913. Do not share it with anyone.",
    "482913 is your Amazon OTP. Do not share it with anyone.",
    "123456 is your HDFC Bank verification code. Never share it, bank staff will never ask for it.",
])
def test_genuine_code_delivery_sms_is_not_phishing(text):
    assert phishing.otp_notice(text)
    assert score("phishing", "sms-analysis", text) < 51


@pytest.mark.parametrize("text", [
    "Your OTP is 482913. Do not share it with anyone. Please send the OTP to our agent to complete KYC.",
    "Your OTP is 4821. Do not share. Verify at sbi-kyc-update.top",
    "Share the OTP you received to unblock your account",
])
def test_asking_for_a_code_is_never_a_code_notice(text):
    assert not phishing.otp_notice(text)


def test_electricity_disconnection_scam():
    text = ("Dear consumer, your power supply will be disconnected tonight because your bill is not updated. "
            "Contact the electricity officer on 9xxxxxx210 now.")
    assert score("impersonation", "government-impersonation", text) >= 71


def test_forward_me_the_code_scam():
    text = "Hi, I sent a six-digit code to your number by mistake, can you forward it to me please?"
    assert score("impersonation", "contact-impersonation", text) >= 71
