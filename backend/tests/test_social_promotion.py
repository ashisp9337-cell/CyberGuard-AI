"""Social-media page: plain promotion is not a scam (21 Oct live check), real scams still are."""
from app.detectors.phishing import analyze_text


def score(t):
    return analyze_text(t, subtopic_title="Social", subtopic_id="social-media-analysis", scan_links=False)["riskScore"]


def test_promotional_posts_are_not_flagged():
    for t in ("New video is up on my channel! Link in bio. Thanks for 10k subscribers",
              "Please vote for our project in the innovation contest, link in comments",
              "Subscribe to our channel for weekly coding tutorials!"):
        assert score(t) <= 50, t


def test_scams_on_the_social_page_are_still_caught():
    for t in ("I'm a crypto investor, I can double your money in 48 hours guaranteed. Send funds to this wallet.",
              "You've won our monthly giveaway! Send your bank account details to claim your prize before it expires."):
        assert score(t) >= 51, t
    # a scam sign (parcel / confirm / money) means the promotion rule never holds the score down
    r = analyze_text("Your parcel is waiting. Confirm the settlement of 2.99 EUR now", subtopic_title="Social",
                     subtopic_id="social-media-analysis", scan_links=False)
    assert "held at 50" not in r["explanation"]


def test_other_pages_are_unchanged():
    t = "Subscribe to our channel for weekly coding tutorials!"
    r = analyze_text(t, subtopic_title="SMS", subtopic_id="sms-phishing", scan_links=False)
    assert "held at 50" not in r["explanation"]


def test_academic_authority_scams():
    """Teacher / university page: the classic college scams found missed on 21 Oct are caught; real notices are not."""
    from app.detectors.teacher_university_impersonation import analyze_teacher_university_impersonation as A
    scams = ["Hi, this is Principal Dr. Mishra. I'm in a meeting and can't talk. Buy 5 Amazon gift cards and send me the codes.",
             "Hello, I am your HOD. Kindly WhatsApp me on this new number 9876501234, I need a small favour urgently.",
             "You got an internship offer from the Training & Placement cell. Pay Rs 999 security deposit for the offer letter.",
             "Professor here. Please send me your OTP that you just received, I'm adding you to the exam portal.",
             "NSP Scholarship: your amount of Rs 12000 is on hold. Update your bank details and Aadhaar today."]
    real = ["Scholarship applications on the National Scholarship Portal close on 31 October. Apply only through scholarships.gov.in.",
            "Fee reminder: the last date to pay the semester fee through the official ERP portal is 25 October.",
            "The Training & Placement cell is organizing a pre-placement talk by Infosys on Monday in the seminar hall.",
            "Your OTP for the exam portal is 482913. Do not share this OTP with anyone, including your teachers."]
    for t in scams:
        assert A(t, {}, "Teacher")["riskScore"] >= 51, t
    for t in real:
        assert A(t, {}, "Teacher")["riskScore"] < 51, t
