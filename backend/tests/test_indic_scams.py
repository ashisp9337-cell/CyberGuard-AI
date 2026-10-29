"""Hindi / Hinglish / Odia scam patterns (30 Oct). Scam examples are real messages quoted by banks / news sites (source in
app/ml/training/test_indic_scams.py) or worded like the public warnings; the genuine ones are ordinary messages."""
import pytest

from app.detectors import government_impersonation as G
from app.detectors import indic_scams as I
from app.detectors import phishing
from app.services.analysis_service import run_scan


def scan(text, sub="sms-analysis", module="phishing"):
    return run_scan(module_id=module, subtopic_id=sub, subtopic_title=sub, text_input=text, url_input=None,
                    file_path=None, file_name=None, extra_field_values={})


def indic_hits(text):
    names = {p[0] for p in I.PATTERNS}
    inds, _ = phishing.scam_patterns(text)
    return [i["label"][len("Scam pattern: "):] for i in inds if i["label"][len("Scam pattern: "):] in names]


def test_language_and_digits():
    assert I.main_language("आपका बिजली कनेक्शन आज रात कट जाएगा") == "Hindi"
    assert I.main_language("ଆପଣଙ୍କ ବିଦ୍ୟୁତ ସଂଯୋଗ ଆଜି କାଟି ଦିଆଯିବ") == "Odia"
    assert I.main_language("Aapka bijli connection aaj kat jayega") is None      # Hinglish: Roman letters
    assert I.main_language("Your OTP is 4821") is None
    assert "९:३० ୯୮".translate(I.DIGITS) == "9:30 98"


@pytest.mark.parametrize("text", [
    # real quotes (lock.pub, allblogs.in, indianpaycalculator.in, IOB)
    "Dear Customer, आपका बिजली कनेक्शन आज रात 9 बजे काट दिया जाएगा। तुरंत ₹1,850 का पेमेंट करें। Contact: 9876XXXXXX",
    "प्रिय ग्राहक, आपका KYC लंबित है। आपका खाता आज ब्लॉक कर दिया जाएगा। अपडेट करने के लिए यहाँ क्लिक करें।",
    "आपका बैंक अकाउंट 2 घंटे में ब्लॉक हो जाएगा। अभी KYC अपडेट करें,",
    "RBI KYC सत्यापन आवश्यक है। खाते को फ्रीज़ होने से बचाने के लिए OTP साझा करें।",
    # worded like the warnings: Hindi digits, Hinglish, Odia
    "प्रिय उपभोक्ता, आपका बिजली कनेक्शन आज रात ९:३० बजे काट दिया जाएगा क्योंकि पिछले महीने का बिल अपडेट नहीं हुआ। "
    "तुरंत बिजली अधिकारी से संपर्क करें 9876543210",
    "Aapka bijli connection aaj raat 9:30 baje kaat diya jayega. Pichle mahine ka bill update nahi hua. "
    "Turant bijli officer ko call karein 9876543210",
    "ପ୍ରିୟ ଗ୍ରାହକ, ଆପଣଙ୍କ ବିଦ୍ୟୁତ ସଂଯୋଗ ଆଜି ରାତି 9:30 ରେ କାଟି ଦିଆଯିବ। ଗତ ମାସର ବିଲ ଅପଡେଟ ହୋଇନାହିଁ। "
    "ତୁରନ୍ତ ଅଧିକାରୀଙ୍କୁ 9876543210 ରେ କଲ କରନ୍ତୁ।",
    "Badhai ho! Aapne KBC lucky draw mein 25 lakh jeeta hai. Processing fee 12,500 jama karein aur WhatsApp par manager ko call karein.",
    "Mumbai Police Cyber Cell: aapke Aadhaar se money laundering ka case darj hai, aapka arrest warrant hai. "
    "Video call par rahiye aur kisi ko mat bataiye.",
    "FedEx: Your parcel to Taiwan contains 5 passports, 3 credit cards and 140g MDMA. It is held by customs. "
    "Press 1 to speak to our executive.",
])
def test_scams_are_flagged(text):
    r = scan(text)
    assert r["riskScore"] >= 71, (r["riskScore"], text)
    assert indic_hits(text), text


def test_hindi_results_say_the_patterns_decide():
    r = scan("आपका बिजली कनेक्शन आज रात 9 बजे काट दिया जाएगा। तुरंत बिजली अधिकारी को 9876543210 पर कॉल करें।")
    assert "Hindi scam patterns" in r["analysisEngine"]
    r = scan("कल हमारे स्कूल में वार्षिक खेल दिवस है, सभी छात्र सुबह आठ बजे पहुंचें।")
    assert r["riskScore"] < 51 and "read English only" in r["explanation"]


@pytest.mark.parametrize("text", [
    "आपका ओटीपी 482913 है। इसे किसी के साथ साझा न करें। - SBI",
    "OTP किसी को न बताएं। बैंक कभी भी OTP नहीं मांगता।",
    "प्रिय उपभोक्ता, रखरखाव कार्य के कारण कल सुबह 10 बजे से दोपहर 2 बजे तक आपके क्षेत्र की बिजली आपूर्ति बंद रहेगी। असुविधा के लिए खेद है।",
    "आपके बिजली बिल ₹1,240 की अंतिम तिथि 15 नवंबर है। भुगतान आधिकारिक ऐप या वेबसाइट से करें।",
    "ମା, ମୁଁ ଘରକୁ ସନ୍ଧ୍ୟା ସାତଟାରେ ଆସିବି। ଖାଇବା ପ୍ରସ୍ତୁତ ରଖ।",
    "Bhai kal light chali gayi thi, aaj raat 9 baje cricket dekhne aa jana.",
    "Aapka parcel kal tak deliver ho jayega. Track karne ke liye Amazon app dekhein.",
])
def test_ordinary_messages_are_not_flagged(text):
    assert not indic_hits(text), text
    assert scan(text)["riskScore"] < 51, text


def test_a_seized_parcel_notice_alone_stays_a_verify_case():
    text = "Customs department: your parcel was seized for containing illegal items."
    assert not indic_hits(text)
    _, floor, _ = G.scam_script(text)
    assert floor == 55


def test_impersonation_detectors_get_their_own_patterns():
    assert "Electricity cut-off tonight - call the 'officer' (Hindi / Hinglish / Odia)" in phishing.PATTERNS_FOR["government"]
    assert "KYC / Aadhaar update or your account is blocked (Hindi / Hinglish / Odia)" in phishing.PATTERNS_FOR["financial"]
    text = "प्रिय ग्राहक, आपका KYC लंबित है। आपका खाता आज ब्लॉक कर दिया जाएगा। अपडेट करने के लिए यहाँ क्लिक करें।"
    assert scan(text, "financial-impersonation", "impersonation")["riskScore"] >= 71
