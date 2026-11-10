"""(10 Nov) "False positive" teaches CyberGuard (per user), and genuine bank e-mails copied from Gmail are not phishing.

The e-mails here are made-up copies in the layout Gmail / Outlook show (account numbers changed); the scams use domains
that do not exist (.top / .xyz), so no real site is contacted."""
import uuid

import pytest

from helpers import register_user

SCAM_SMS = ("Dear customer your SBI account will be blocked today. Update KYC now at "
            "http://sbi-kyc-update-now.top/login and enter your password and OTP")

HDFC_ALERT = """You have done a UPI txn. Check details!
Inbox
HDFC Bank InstaAlerts <alerts@hdfcbank.net>
Tue, Nov 10, 2026, 11:42 AM
to me

Dear Customer,

Rs.450.00 has been debited from account **9999 to VPA zomato@hdfcbank ZOMATO on 10-11-26. Your UPI transaction \
reference number is 612345678901.

If you did not authorize this transaction, please report it immediately by calling 18002586161.

Warm Regards,
HDFC Bank

This is a system-generated e-mail. Please do not reply to this e-mail."""

KOTAK_OTP = """OTP for transaction
Kotak Mahindra Bank <bankalerts@kotak.com>
10:02 AM (4 hours ago)
to me

Dear Customer,
Your One Time Password (OTP) for transaction of Rs. 2,000.00 at AMAZON is 482913. Valid for 5 minutes.
Do not share this OTP with anyone. Kotak Bank never asks for your OTP.
Regards, Kotak Mahindra Bank"""

SBI_STATEMENT = """E-Account Statement for the period 01-10-2026 to 31-10-2026
Inbox
SBI <cbssbi.cas@alerts.sbi.co.in>
Sun, Nov 8, 9:05 AM (2 days ago)
to me

Dear Customer,

Please find attached the E-statement of your account XXXXXXX9999 for the period 01-10-2026 to 31-10-2026.

The attachment is password protected. The password is the last 5 digits of your registered mobile number followed \
by your date of birth in DDMMYY format.

Regards,
State Bank of India
This is an auto-generated email. Please do not reply."""

OUTLOOK_COPY = """From: SBI Card <statements@sbicard.com>
Sent: Monday, November 9, 2026 8:15 AM
To: Ashis Pal
Subject: Your SBI Card Monthly Statement - November 2026

Dear Cardholder,
Your SBI Card statement for November 2026 is ready. Total amount due Rs 3,210. Due date 28 Nov 2026.
Regards, SBI Card"""

SPOOF_OTP = """Verify your account
SBI <noreply@sbi.co.in>
Tue, Nov 10, 2026, 11:42 AM
to me
Dear Customer, your YONO account will be blocked today. Reply to this email with your account number, OTP and date \
of birth to keep it active."""

SPOOF_LINK = """Account suspended
HDFC Bank <alerts@hdfcbank.net>
Tue, Nov 10, 2026, 11:42 AM
to me
Dear Customer, your NetBanking access is suspended. Restore it within 24 hours: http://hdfc-netbanking-restore.top/login"""

FREEMAIL_BANK = """Urgent KYC
HDFC Bank Support <hdfcbank.support@gmail.com>
Tue, Nov 10, 2026, 11:42 AM
to me
Dear Customer, update your KYC today or your account will be blocked. Enter your NetBanking password at the branch \
portal."""


@pytest.fixture()
def offline_dns(monkeypatch):
    """The workspace has no DNS: real bank domains resolve on a real PC, made-up .top/.xyz ones do not."""
    from app.services import network_intel as ni
    monkeypatch.setattr(ni, "resolve_domain", lambda d: {"status": "unresolvable", "reason": "x"}
                        if d.endswith((".top", ".xyz")) else {"status": "ok", "ips": ["8.8.8.8"]})
    monkeypatch.setattr(ni, "get_domain_age", lambda d: {"status": "unavailable", "reason": "offline"})
    monkeypatch.setattr(ni, "get_ssl_info", lambda d: {"status": "unavailable", "reason": "offline"})


def _route(text):
    from app.services import subtopic_router as R
    return R.route(module_id="phishing", text_input=text, url_input=None, file_path=None, file_name=None,
                   extra_field_values={})


@pytest.mark.parametrize("mail", [HDFC_ALERT, KOTAK_OTP, SBI_STATEMENT, OUTLOOK_COPY])
def test_genuine_bank_emails_copied_from_a_mail_app_are_safe(mail, offline_dns):
    res, c = _route(mail)
    assert c.subtopic_id == "email-analysis"
    assert res["riskScore"] <= 25, (res["riskScore"], res["explanation"])
    assert any(i["label"] == "Official sender address (copied e-mail)" for i in res["indicators"])


@pytest.mark.parametrize("mail", [SPOOF_OTP, SPOOF_LINK, FREEMAIL_BANK])
def test_scams_using_a_bank_name_or_address_stay_high(mail, offline_dns):
    res, c = _route(mail)
    assert c.subtopic_id == "email-analysis"
    assert res["riskScore"] >= 71, (res["riskScore"], res["explanation"])


def test_body_copied_without_the_sender_line_is_an_email_and_only_suspicious(offline_dns):
    body = HDFC_ALERT.split("to me", 1)[1].strip()
    res, c = _route(body)
    assert c.subtopic_id == "email-analysis"
    assert 26 <= res["riskScore"] <= 55
    assert "sender line" in res["explanation"]


def test_credential_words_are_whole_words_and_warnings_are_not_requests():
    from app.detectors.phishing import credential_request
    assert not credential_request("Happy shopping this Diwali!")
    assert not credential_request("HDFC Bank never asks for your password, OTP or PIN over phone, SMS or e-mail.")
    assert not credential_request("Do not share this OTP with anyone.")
    assert credential_request("Share the OTP with our executive now")
    assert credential_request("Do not ignore this, share your OTP now")
    assert credential_request("We do not ask for PIN but please confirm your card number and CVV here")


def test_a_bank_alert_naming_the_shop_is_not_brand_impersonation():
    from app.detectors.brand_impersonation import analyze_brand_impersonation
    r = analyze_brand_impersonation("Rs 450 debited from your HDFC Bank account to ZOMATO.",
                                    {"senderEmail": "alerts@hdfcbank.net"}, "x")
    fired = {i["label"] for i in r["indicators"] if i["triggered"]}
    assert "Sender domain does not match the claimed brand" not in fired
    assert "Multiple brands named in one message" not in fired
    r = analyze_brand_impersonation("Your Amazon order is on hold, pay the fee", {"senderEmail": "help@amaz0n-pay.top"}, "x")
    assert "Sender domain does not match the claimed brand" in {i["label"] for i in r["indicators"] if i["triggered"]}


# ---------------------------------------------------------------------------------------------------------------
# learning from "False positive"
# ---------------------------------------------------------------------------------------------------------------
def _scan(client, text):
    return client.post("/api/analysis/scan", data={"moduleId": "phishing", "subtopicId": "sms-analysis",
                                                    "subtopicTitle": "SMS / Message Analysis", "textInput": text}).json()


def test_false_positive_is_learned_and_can_be_undone(auth_client, offline_dns):
    first = _scan(auth_client, SCAM_SMS)
    assert first["riskScore"] >= 71
    inc = next(i for i in auth_client.get("/api/incidents").json() if i["scanId"] == first["scanId"])

    r = auth_client.patch(f"/api/incidents/{inc['id']}", json={"status": "false_positive", "note": "my own test"})
    assert r.status_code == 200 and r.json()["learned"] >= 2          # the message + its link / domain

    again = _scan(auth_client, "  " + SCAM_SMS.replace(" ", "  ") + "\n")   # same message, other spacing
    assert again["riskScore"] <= 20 and again["classification"] == "safe"
    assert again["indicators"][0]["label"] == "You marked this exact message as safe"
    assert not any(i["label"] == "Seen before in an earlier threat" for i in again["indicators"])
    assert not [i for i in auth_client.get("/api/incidents").json() if i["scanId"] == again["scanId"]]
    marked = auth_client.get("/api/iocs?status=allowlisted").json()
    assert {m["type"] for m in marked} >= {"message", "domain"}

    other = _scan(auth_client, SCAM_SMS.replace("blocked today", "closed tonight"))   # a different message
    assert other["riskScore"] >= 51

    r = auth_client.patch(f"/api/incidents/{inc['id']}", json={"status": "open"})
    assert r.json()["learned"] >= 2
    assert _scan(auth_client, SCAM_SMS)["riskScore"] >= 71
    assert not [m for m in auth_client.get("/api/iocs?status=allowlisted").json() if m["type"] == "message"]


def test_what_one_user_marks_safe_does_not_change_another_users_scans(client, offline_dns):
    from fastapi.testclient import TestClient
    from app.main import app
    a, b = TestClient(app), TestClient(app)
    for c in (a, b):
        assert register_user(c, {"name": "U", "email": f"u_{uuid.uuid4().hex[:8]}@example.com",
                                 "password": "TestPass123"}).status_code == 201
    first = _scan(a, SCAM_SMS)
    inc = next(i for i in a.get("/api/incidents").json() if i["scanId"] == first["scanId"])
    assert a.patch(f"/api/incidents/{inc['id']}", json={"status": "false_positive"}).status_code == 200
    assert _scan(a, SCAM_SMS)["riskScore"] <= 20
    assert _scan(b, SCAM_SMS)["riskScore"] >= 71


def test_trusted_sender_still_flags_a_risky_link(auth_client, offline_dns):
    from app.db.database import SessionLocal
    from app.services import feedback
    db = SessionLocal()
    try:
        result = {"riskScore": 90, "classification": "critical", "severity": "critical", "threatType": "x",
                  "explanation": "", "indicators": [], "recommendations": [],
                  "email": {"from_address": "friend@company.example"},
                  "components": [{"component": "url", "score": 80}], "escalations": []}
        from app.db.models import IOC, User
        uid = db.query(User).filter(User.email == auth_client._test_email).one().id
        db.add(IOC(user_id=uid, ioc_type="email", value="friend@company.example", status="allowlisted",
                   note="False positive (scan SCN_x) - added"))
        db.commit()
        feedback.apply_user_verdict(db, uid, "phishing", result, None)
        assert result["riskScore"] == 90
        assert any("risky link" in i["label"] for i in result["indicators"])
        result2 = dict(result, riskScore=80, components=[{"component": "url", "score": 10}], indicators=[])
        result2.pop("userVerdict", None)
        feedback.apply_user_verdict(db, uid, "phishing", result2, None)
        assert result2["riskScore"] <= 25
    finally:
        db.close()


# ---------------------------------------------------------------------------------------------------------------
# (10 Nov) a real bank newsletter (.eml with Gmail's authentication results), modelled on a Kotak 811 mailer
# ---------------------------------------------------------------------------------------------------------------
_TRACK = ("https://u9160131.ct.sendgrid.net/ls/click?upn=u001.LvbU017X57Abv4S32yRixhVaCCWFQ2zUeNhnI2Yv-2BfN-2FtyL4q"
          "zNw3japzL-2B3P0TRzDLnGIKb9ZNlS3-2FFlHwkZeXbIovE9cCxeI-2FzB4pWWw1lwg598w-2BAo0P9UlC1e7mKJeYW5IDDrJd3PWIx"
          "RrxOG6zVRbDKgpcya-2FvpfB8A31zgV0EsR-2BP0uYqgf5nRdwg0sWrPF-2F22rlwOGA112J2303EI0sqiS-2BRUtnefsu-2FUyQ7EN")


def _bank_mail(from_addr, dmarc_domain, link):
    from urllib.parse import quote
    wrapped = "https://ems-urlprotect.trendmicro.com/wis/clicktime/v1/query?url=" + quote(link, safe="") + "&umid=1"
    return (f"""Authentication-Results: mx.google.com;
       dkim=pass header.i=@{dmarc_domain} header.s=outgoing01;
       spf=pass (google.com: domain of {from_addr} designates 121.241.26.153 as permitted sender) smtp.mailfrom={from_addr};
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={dmarc_domain}
Date: Thu, 5 Nov 2026 14:35:43 +0530
From: Kotak 811 <{from_addr}>
To: someone@example.com
Subject: Invest in Government Securities with RBI Retail Direct
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body><p>Dear Customer,</p>
<p>Now invest in Government Securities and Treasury Bills directly through RBI Retail Direct, from the comfort of
your Kotak 811 account. Safe, government-backed returns.</p>
<p><a href="https://rbiretaildirect.org.in/#/">Know more</a> | <a href="{wrapped}">Invest now</a></p>
<p><a href="https://www.kotak.bank.in/en/terms-conditions.html">Terms</a></p>
</body></html>
""").encode()


def test_authenticated_bank_newsletter_with_tracking_links_is_safe(offline_dns):
    from app.email_pipeline import analyze_email
    r = analyze_email(_bank_mail("kotak811@kotak.bank.in", "kotak.bank.in", _TRACK))
    assert r["riskScore"] <= 25, (r["riskScore"], r["explanation"])
    assert r["trust"]["official_domain_for_claim"]
    assert not any("trendmicro" in u for u in r["links_scanned"])          # the security wrapper is unwrapped
    fired = {i["label"] for i in r["indicators"] if i["triggered"]}
    assert not fired & {"Sender impersonates an organisation", "Look-alike sender domain"}


def test_same_newsletter_from_a_look_alike_domain_or_with_a_bad_link_is_flagged(offline_dns):
    from app.email_pipeline import analyze_email
    fake = analyze_email(_bank_mail("kotak811@kotak811-rewards.top", "kotak811-rewards.top", _TRACK))
    assert fake["riskScore"] >= 71, fake["explanation"]
    bad_link = analyze_email(_bank_mail("kotak811@kotak.bank.in", "kotak.bank.in",
                                        "http://kotak-rbi-retail-kyc.top/login?verify=1"))
    assert bad_link["riskScore"] >= 51, bad_link["explanation"]


def test_bank_in_is_the_banks_own_zone():
    from app.detectors.url_features_v2 import registered_domain
    from app.email_pipeline import org_directory as orgs
    assert registered_domain("prod.smartnudges.kotak.bank.in") == "kotak.bank.in"
    kotak = next(e for e in orgs.ORG_ENTITIES if e["name"].lower().startswith("kotak"))
    assert orgs.is_official_sender(kotak, "kotak.bank.in")
    assert not orgs.is_official_sender(kotak, "hdfc.bank.in")
    assert not orgs.is_official_sender(kotak, "kotak-bank.in")


def test_mail_security_wrappers_are_unwrapped():
    from app.email_pipeline.orchestrator import unwrap_link as u
    assert u("https://ems-urlprotect.trendmicro.com/wis/clicktime/v1/query?url=https%3a%2f%2fevil.top%2fx&umid=1") \
        == "https://evil.top/x"
    assert u("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.top%2Fx&data=1") == "https://evil.top/x"
    assert u("https://urldefense.com/v3/__https://evil.top/p?x=1__;!!abc") == "https://evil.top/p?x=1"
    assert u("https://evil-trendmicro.com/wis/clicktime/?url=https://x.top").startswith("https://evil-trendmicro.com")


# ---------------------------------------------------------------------------------------------------------------
# (10 Nov) every bank on RBI's list, with its .bank.in address
# ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,domain", [("Indian Bank", "indianbank.bank.in"), ("Odisha Grameen Bank", "odishabank.bank.in"),
                                         ("Union Bank of India", "unionbankonline.bank.in"), ("Yes Bank", "yes.bank.in"),
                                         ("Federal Bank", "federal.bank.in"), ("India Post Payments Bank", "ippbonline.bank.in")])
def test_every_rbi_listed_bank_knows_its_own_domain(name, domain):
    from app.email_pipeline import org_directory as orgs
    ents = orgs.find_entities(f"Dear customer, greetings from {name}.")
    assert [e["name"].lower() for e in ents] == [name.lower()]
    assert orgs.is_official_sender(ents[0], domain)
    assert not orgs.is_official_sender(ents[0], domain.replace(".bank.in", "-bank.in"))


def test_a_bank_name_inside_a_longer_bank_name_is_not_a_second_bank():
    from app.email_pipeline import org_directory as orgs
    assert [e["name"] for e in orgs.find_entities("State Bank of India: your statement")] == ["SBI"]
    assert [e["name"] for e in orgs.find_entities("Indian Overseas Bank alert")] == ["Indian Overseas Bank"]
    assert orgs.find_entities("I am an Indian student at a federal university") == []


def test_a_real_bank_writing_about_rbi_is_not_rbi_impersonation():
    from app.detectors.financial_impersonation import analyze_financial_impersonation as f
    real = f("Invest in Government Securities with RBI Retail Direct from your Kotak account.",
             {"senderEmail": "kotak811@kotak.bank.in"}, "x")
    assert "Sender domain does not match the claimed institution" not in \
        {i["label"] for i in real["indicators"] if i["triggered"]}
    fake = f("RBI notice: your account is frozen, pay the release fee.", {"senderEmail": "rbi.notice@rbi-help.top"}, "x")
    assert "Sender domain does not match the claimed institution" in {i["label"] for i in fake["indicators"] if i["triggered"]}


# ---------------------------------------------------------------------------------------------------------------
# (10 Nov) fixes found by the real-data check (UCI SMS ham, Enron ham, loghub logs)
# ---------------------------------------------------------------------------------------------------------------
def test_send_it_to_me_is_only_an_otp_ask_when_a_code_is_named():
    from app.detectors.known_contact_impersonation import CODE_RE
    for chat in ("Lmao. Take a pic and send it to me.", "How r u going to send it to me?",
                 "Oh that was a forwarded message. I thought you send that to me"):
        assert not CODE_RE.search(chat), chat
    for scam in ("Hi, I sent a six-digit code to your number by mistake, can you forward it to me please?",
                 "An OTP came to your phone, forward it to me", "send me the OTP", "Forward that code to me now"):
        assert CODE_RE.search(scam), scam


def test_apache_error_log_is_a_log():
    from app.services import subtopic_router as R
    log = "\n".join(["[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties",
                     "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6",
                     "[Sun Dec 04 04:51:08 2005] [notice] jk2_init() Found child 6725 in scoreboard slot 10"])
    c = R.classify(module_id="cyber-threat", text_input=log, url_input=None, file_path=None, file_name=None,
                   extra_field_values={})
    assert c.subtopic_id == "log-analysis"


@pytest.mark.parametrize("age,expect_low", [(5000, True), (40, False)])
def test_an_old_domain_close_to_a_famous_name_is_not_a_look_alike(monkeypatch, age, expect_low):
    from app.detectors import malicious_url as M
    from app.services import network_intel as ni
    monkeypatch.setattr(ni, "resolve_domain", lambda d: {"status": "ok", "ips": ["8.8.8.8"]})
    monkeypatch.setattr(ni, "get_ssl_info", lambda d: {"status": "unavailable"})
    monkeypatch.setattr(ni, "get_domain_age", lambda d: {"status": "ok", "age_days": age})
    monkeypatch.setattr(M, "_registry", lambda h: None)
    r = M.analyze_url("https://kayak.co.in/", subtopic_id="general")
    assert (r["riskScore"] <= 50) is expect_low, r["riskScore"]
    assert M.analyze_url("https://paypa1-login.com/", subtopic_id="general")["riskScore"] >= 71   # still caught


def test_whole_word_brand_mismatch_and_forwarded_mail():
    from app.detectors.phishing import _rule_indicators
    fired = {i["label"] for i in _rule_indicators("Join our user groups and backups team first thing on Monday",
                                                  sender="hr@company.example") if i["triggered"]}
    assert "Sender domain mismatch" not in fired                          # "ups" in groups, "irs" in first
    fired = {i["label"] for i in _rule_indicators("Your PayPal account is limited", sender="x@pay-help.top")
             if i["triggered"]}
    assert "Sender domain mismatch" in fired
