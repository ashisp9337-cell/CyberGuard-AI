"""Upgrade #11 (31 Oct): auto-detect labels. A normal application log is labelled "log analysis" (not insider risk), and
when several kinds of impersonation fit, the sender's own introduction ("this is Principal ...") decides the label -
while every impersonation detector still checks the message, so the score never drops."""
from app.services import subtopic_router as R


def classify(module, text):
    return R.classify(module_id=module, text_input=text, url_input=None, file_path=None, file_name=None,
                      extra_field_values=None)


def test_normal_application_log_is_log_analysis():
    log = ("2026-10-20 10:15:02 INFO app=erp user=ashis action=view_timetable status=200 duration_ms=84\n"
           "2026-10-20 10:15:40 INFO app=erp user=ashis action=download_admit_card status=200 duration_ms=120")
    assert classify("cyber-threat", log).subtopic_id == "log-analysis"


def test_user_activity_records_are_still_insider_risk():
    assert classify("cyber-threat", "user=ravi action=file_copy target=payroll.xlsx\n"
                                    "user=ravi action=logon").subtopic_id == "insider-risk"
    usb = "2026-10-20 23:05:00 INFO user=ravi action=usb_copy file=payroll.xlsx"
    assert classify("cyber-threat", usb).subtopic_id == "insider-risk"          # data-handling signs win


def test_sender_introduction_settles_a_close_call():
    text = ("Hi, this is Principal Dr. Mishra. I'm in a meeting and can't talk. I need you to buy 5 Amazon gift cards "
            "of Rs 2000 each for a staff event and send me the codes urgently.")
    c = classify("impersonation", text)
    assert c.subtopic_id == "teacher-impersonation" and R.CLAIM_TIE_REASON in c.reasons
    result, _ = R.route(module_id="impersonation", text_input=text, url_input=None, file_path=None, file_name=None,
                        extra_field_values={})
    assert result["riskScore"] >= 71                                           # strongest of every detector
    assert "category unclear" not in result["analysisEngine"] and "close call" in result["analysisEngine"]


def test_being_busy_is_not_an_identity_claim():
    # "I'm in a meeting" names nobody, so it never decides a close call by itself
    m = [x.group(2) for x in R.SELF_CLAIM_RE.finditer("I'm in a meeting. Please buy Amazon gift cards.")]
    assert m == ["in a meeting"]


def test_no_identity_at_all_stays_generic():
    c = classify("impersonation", "Please send the money today, it is urgent.")
    assert c.subtopic_id == "generic"
