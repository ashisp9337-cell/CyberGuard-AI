"""
Scam patterns for messages written in HINDI (Devanagari), HINGLISH (Hindi in Roman letters) and ODIA - added 30 Oct.

Why rules and not a model: CyberGuard's SMS / e-mail models were trained on English text only, and no openly licensed,
real, labelled Hindi or Odia scam-SMS dataset was available. So these patterns were written from the scam descriptions in
public warnings (RBI, DoT / TRAI, I4C cybercrime.gov.in, electricity companies, banks, police) and are checked:
  * for false alarms on real, ordinary text: Hindi news sentences (UD Hindi-HDTB + PUD), Odia news sentences
    (UD Odia-ODTB), human-written Hinglish requests (Google Hinglish-TOP) and the real SMS corpus;
  * for catches on real scam messages quoted word for word by news sites and banks (app/ml/training/test_indic_scams.py).

Like the English scam patterns in phishing.py, every pattern needs SEVERAL parts of the scam close together (one ~300
character window) - one word alone never fires. Same tuple format as phishing.SCAM_PATTERNS:
    (name, regexes that must ALL match, needs a link?, minimum score, description[, unless-regex])
Devanagari / Odia words are matched as plain text (Python's word boundary \\b breaks inside those scripts at vowel
signs); Roman (Hinglish / English) words use \\b.
"""
from __future__ import annotations

import re

_P = lambda rx: re.compile(rx, re.I)  # noqa: E731

# Devanagari and Odia digits -> 0-9, so "९:३० बजे" and "9:30 बजे" match the same patterns
DIGITS = str.maketrans("०१२३४५६७८९୦୧୨୩୪୫୬୭୮୯", "01234567890123456789")
_DEVA = re.compile(r"[ऀ-ॿ]")
_ODIA = re.compile(r"[଀-୿]")
_LATIN = re.compile(r"[A-Za-z]")


def script_share(text: str) -> dict:
    """Share of letters in Devanagari, Odia and Latin script."""
    d, o, l = len(_DEVA.findall(text or "")), len(_ODIA.findall(text or "")), len(_LATIN.findall(text or ""))
    n = max(d + o + l, 1)
    return {"devanagari": d / n, "odia": o / n, "latin": l / n}


def main_language(text: str) -> str | None:
    """'Hindi' / 'Odia' when most letters are in that script (the English models cannot read it), else None."""
    s = script_share(text)
    if s["devanagari"] >= 0.5:
        return "Hindi"
    if s["odia"] >= 0.5:
        return "Odia"
    return None


# ---- building blocks (Hindi | Hinglish | Odia | English) ---------------------------------------------------------
PHONE = r"(?:\+?91[\s-]?)?[6-9]\d{3,4}[\s-]?(?:\d{5}|[\dxX*]{5,6})"      # mobile number, also "9876XXXXXX"
_URGENT = (r"(आज|अभी|तुरंत|तुरन्त|घंटे|घण्टे|रात|बजे|शीघ्र|जल्दी|\b(aaj|abhi|turant|turent|ghante|raat|baje|jaldi|"
           r"today|tonight|immediately|urgent|within \d+ ?(hours?|hrs|minutes|mins))\b|ଆଜି|ତୁରନ୍ତ|ରାତି|ଘଣ୍ଟା)")

# 1. electricity cut-off over an "unpaid / not updated bill" - call "the officer" on a mobile number
#    (a planned power shutdown notice has no bill in it; a real bill gives the toll-free 1912 / a website, not a mobile)
_ELEC = (_P(r"(बिजली|विद्युत|लाइट|\b(bijli|bijlee|light|electricity|power|vidyut|current)\b|ବିଦ୍ୟୁତ|ବିଜୁଳି)"),
         _P(r"(काट|कट |कट जा|कटेगा|बंद|बन्द|\b(cut|kat|kaat|disconnect\w*|band)\b|କାଟ|କଟା|ବିଚ୍ଛିନ୍ନ|ବନ୍ଦ)"),
         # an unpaid / "not updated" bill, or YOUR connection (a planned area shutdown notice has neither)
         _P(r"(बिल|भुगतान|पेमेंट|बकाया|अपडेट|आपका|आपकी|आपके|\b(bill|payment|pay|update\w*|pending|dues?|bakaya|your|"
            r"aapka|aapki|aapke|apka|apki|apke)\b|ବିଲ|ଦେୟ|ଆପଣଙ୍କ)"),
         _P(rf"(अधिकारी|ऑफिसर|\b(officer|adhikari)\b|ଅଧିକାରୀ|{PHONE})"))
# 2. KYC / PAN / Aadhaar "account will be blocked" + click / app / OTP
_KYC = (_P(r"(\bkyc\b|केवाईसी|के\.वाई\.सी|\bpan\b|पैन|आधार|\baadhaa?r\b|କେୱାଇସି|ଆଧାର)"),
        _P(r"(ब्लॉक|ब्लाक|बंद|बन्द|फ्रीज|फ्रीज़|निलंबित|सस्पेंड|लंबित|समाप्त|\b(block\w*|band|freez\w*|suspend\w*|deactivat\w*|"
           r"pending|expir\w*)\b|ବ୍ଲକ|"
           r"ବନ୍ଦ|ଅବରୋଧ)"),
        _P(r"(क्लिक|लिंक|ऐप|एप|इंस्टॉल|डाउनलोड|ओटीपी|अपडेट कर|\b(click|link|app|apk|install|download|otp|update kar\w*)\b|"
           r"https?://|ଲିଙ୍କ|କ୍ଲିକ|ଓଟିପି)"),
        _P(_URGENT))      # "today / in 2 hours / right now": real banks give a date, not a countdown
# 3. asks you to TELL / SEND the OTP / PIN (a warning "do not share" never counts)
_OTP = (_P(r"(ओटीपी|\botp\b|पिन|\bpin\b|\bcvv\b|कोड|\bcode\b|ଓଟିପି|ପିନ)"),
        _P(r"(बताएं|बताइए|बताओ|बताये|बताएँ|भेजें|भेजो|भेज दें|शेयर करें|शेयर कर दें|साझा करें|\b(batao|bataiye|bata do|"
           r"bhejo|bhej do|bhejiye|share karo|share kare|share kar do|share karein)\b|କୁହନ୍ତୁ|ପଠାନ୍ତୁ)"))
_OTP_SAFE = _P(r"(न |ना |मत |नहीं|कभी|किसी को|किसी के साथ|\b(na|mat|nahi|kabhi|kisi)\b|ନାହିଁ|କାହାକୁ)")
# 4. lottery / prize / KBC - pay a fee or tax first
_LOTTERY = (_P(r"(लॉटरी|लाटरी|इनाम|पुरस्कार राशि|कौन बनेगा करोड़पति|केबीसी|लकी ड्रा|जीता है|जीते हैं|\b(lottery|inaam|inam|"
               r"kbc|lucky draw|jeeta hai|jeet gaye|you (have )?won(?!\s*['’]\s*t\b)|winner)\b|ଲଟେରୀ|ପୁରସ୍କାର)"),   # not "you won't"
            # a fee / tax first, or "call the manager on WhatsApp and give your lottery number" (the fee comes on the call)
            _P(r"(शुल्क|फीस|टैक्स|प्रोसेसिंग|रजिस्ट्रेशन|जमा कर|पैसे भेज|लॉटरी नंबर|मैनेजर|व्हाट्सएप कॉल|\b(fee|fees|tax|"
               r"jama kar\w*|deposit|processing|registration|paise bhej\w*|lottery number|(bank )?manager|whatsapp call)\b|ଶୁଳ୍କ|ଜମା)"),
            _P(r"(आप|बधाई|\b(aap\w*|you|your|congrat\w*|badhai)\b|ଆପଣ|ଅଭିନନ୍ଦନ)"))
# 5. work from home / like-and-earn task jobs
_JOB = (_P(r"(घर बैठे|पार्ट टाइम|पार्ट-टाइम|नौकरी|\b(ghar baithe|ghar se|work from home|part[- ]?time|naukri|job)\b|ଘରେ ବସି)"),
        _P(r"(कमाएं|कमाई|कमाओ|रोज़|रोज|प्रतिदिन|\b(kamaye|kamaye?n|kamao|kamai|earn\w*|income|daily|roz|per day)\b|ରୋଜଗାର)"),
        _P(r"(टेलीग्राम|व्हाट्सएप|लाइक|रिव्यू|टास्क|जॉइनिंग|\b(telegram|whatsapp|like|likes|review|task|joining)\b)"))
# 6. "digital arrest": police / CBI / customs + arrest / case + money / video call / secrecy
_ARREST = (_P(r"(पुलिस|सीबीआई|ईडी|क्राइम ब्रांच|साइबर सेल|कस्टम|एनसीबी|ट्राई|\b(police|cbi|crime branch|cyber cell|customs|"
              r"ncb|trai|narcotics)\b|ପୋଲିସ)"),
           _P(r"(गिरफ्तार|गिरफ़्तार|अरेस्ट|वारंट|एफआईआर|केस दर्ज|\b(arrest\w*|giraftar|warrant|fir|case (registered|filed)|"
              r"money laundering)\b|ଗିରଫ)"),
           _P(r"(पैसे|ट्रांसफर|खाते में|वीडियो कॉल|स्काइप|किसी को न बताएं|किसी को मत|गोपनीय|सत्यापन|\b(paise|transfer|"
              r"video call|skype|kisi ko (mat|na)|verification|safe account|rbi account|settle)\b|ଟଙ୍କା)"),
           _P(r"(आप|\b(aap\w*|you|your)\b|ଆପଣ)"))       # spoken TO you - a news report about an arrest is not
# 7. courier carrying drugs / passports in your name (the start of digital arrest) - Hindi and English
_COURIER = (_P(r"(पार्सल|कूरियर|पैकेज|\b(parcel|package|courier|fedex|dhl|consignment|shipment)\b|ପାର୍ସଲ)"),
            _P(r"(ड्रग्स|ड्रग|नशीले|पासपोर्ट|अवैध|\b(drugs?|mdma|narcotic\w*|passports?|illegal|contraband|ganja|cocaine)\b)"),
            # ...and pushes you to act (press a key, talk to "police", video call, pay): a seized-parcel notice alone stays a
            # "verify" case (government_impersonation gives it 55)
            _P(r"(दबाएं|दबाइए|बात कर|वीडियो कॉल|ट्रांसफर|भुगतान|गिरफ्तार|गिरफ़्तार|\b(press \d|dial \d|connect\w*|talk to|"
               r"speak to|video call|skype|transfer|pay|arrest\w*|fir)\b)"),
            _P(r"(आप|\b(aap\w*|you|your)\b|ଆପଣ)"))
# 8. instant loan without CIBIL / documents - pay a fee or install an app
_LOAN = (_P(r"(लोन|ऋण|कर्ज|\b(loan|rin|karz|karj)\b|ଋଣ)"),
         _P(r"(बिना|\b(bina|without|no)\b)[^\n]{0,25}(सिबिल|दस्तावेज|गारंटी|\b(cibil|documents?|guarantee|credit (score|check))\b)"),
         _P(r"(शुल्क|फीस|ऐप|एप|लिंक|डाउनलोड|\b(fee|processing|app|apk|link|download)\b|https?://)"))
# 9. refund / cashback that needs your UPI PIN or a "collect request" (you never enter a PIN to RECEIVE money)
_UPI = (_P(r"(रिफंड|कैशबैक|पैसे वापस|इनाम|\b(refund|cashback|cash back|paise wapas|reward|received money)\b)"),
        _P(r"(यूपीआई पिन|upi पिन|पिन डाल|पिन दर्ज|अनुरोध स्वीकार|रिक्वेस्ट|\b(upi ?pin|enter (your )?pin|pin daal\w*|"
           r"approve|accept (the )?(request|collect)|collect request|scan (the |this )?qr)\b)"))
# 10. "this is my new number" + send money now
_NEWNUM = (_P(r"(नया नंबर|नए नंबर|\b(naya number|naye number|new number|mera number badal)\b)"),
           _P(r"(पैसे|पेमेंट|ट्रांसफर|\b(paise|payment|transfer|upi|gpay|phonepe|paytm|rs\.? ?\d|₹ ?\d)\b|₹)"),
           _P(r"(जल्दी|तुरंत|अभी|अर्जेंट|\b(jaldi|turant|abhi|urgent\w*|emergency)\b)"))
# 11. SIM / mobile number blocked in 2 hours (fake TRAI / DoT calls) - press 9 / call
_SIM = (_P(r"(सिम|मोबाइल नंबर|\b(sim|mobile number|mobile connection)\b)"),
        _P(r"(बंद|ब्लॉक|निष्क्रिय|\b(band|block\w*|deactivat\w*|disconnect\w*|suspend\w*)\b)"),
        _P(r"(घंटे|आज|\b(ghante|aaj|hours?|today)\b)"),
        _P(r"(दबाएं|दबाइए|कॉल|संपर्क|\b(press \d|dabaye\w*|call|contact)\b)"))

PATTERNS = [
    ("Electricity cut-off tonight - call the 'officer' (Hindi / Hinglish / Odia)", _ELEC, False, 75,
     "Says your electricity will be cut today / tonight and asks you to call an 'officer' on a mobile number: the "
     "electricity-bill scam. Real power companies send bills with a due date and ask you to pay on their own website or "
     "app - never to call a private number."),
    ("KYC / Aadhaar update or your account is blocked (Hindi / Hinglish / Odia)", _KYC, False, 75,
     "Threatens to block your account or card over KYC / PAN / Aadhaar and pushes a link, an app or an OTP: banks never "
     "ask for KYC through a link or an app sent by message (RBI warning)."),
    ("Asks for your OTP / PIN (Hindi / Hinglish / Odia)", _OTP, False, 75,
     "Asks you to tell or send an OTP, PIN or code: whoever has it can log in or pay as you. No bank, company or "
     "government office ever needs it.", _OTP_SAFE),
    ("Lottery / prize - pay a fee first (Hindi / Hinglish / Odia)", _LOTTERY, False, 80,
     "You have 'won' a lottery / KBC prize but must pay a fee or tax first: real prizes never cost money to receive."),
    ("Work-from-home task job (Hindi / Hinglish / Odia)", _JOB, False, 71,
     "Promises daily earnings from home for liking / reviewing / simple tasks and moves you to Telegram / WhatsApp: the "
     "task-job scam, which later asks for 'deposits'."),
    ("Digital arrest - police / CBI threat (Hindi / Hinglish / Odia)", _ARREST, False, 85,
     "Police / CBI / customs say you are involved in a case and must pay, stay on a video call or keep it secret: the "
     "'digital arrest' scam. Indian police never arrest anyone over a call or ask for money to 'verify' (I4C warning)."),
    ("Parcel with drugs / passports in your name (courier - digital arrest)", _COURIER, False, 85,
     "Says a parcel in your name holds drugs, passports or illegal items and connects you to 'police' or 'customs': the "
     "first step of the digital-arrest scam. Courier companies never do this."),
    ("Instant loan without CIBIL / documents (Hindi / Hinglish / Odia)", _LOAN, False, 71,
     "Offers a loan with no credit check or documents but asks for a fee or an app install: fake loan-app fraud (RBI "
     "warning) - the app then steals contacts and photos."),
    ("Refund / cashback that needs your UPI PIN", _UPI, False, 80,
     "A refund, cashback or reward that asks you to enter your UPI PIN, approve a request or scan a QR: you never need a "
     "PIN to RECEIVE money - entering it sends money away."),
    ("'My new number' - send money urgently (Hindi / Hinglish)", _NEWNUM, False, 71,
     "Someone writes from a 'new number' and needs money urgently: call the person on their old number first."),
    ("SIM / mobile number blocked in hours (fake TRAI / DoT)", _SIM, False, 75,
     "Says your SIM or mobile number will be blocked within hours unless you press a key or call: TRAI / DoT never call "
     "or message to block numbers (DoT warning)."),
]

# which impersonation detectors these belong to (see phishing.PATTERNS_FOR)
FOR_TOPIC = {
    "government": ("Electricity cut-off tonight - call the 'officer' (Hindi / Hinglish / Odia)",
                   "Digital arrest - police / CBI threat (Hindi / Hinglish / Odia)",
                   "Parcel with drugs / passports in your name (courier - digital arrest)",
                   "SIM / mobile number blocked in hours (fake TRAI / DoT)"),
    "financial": ("KYC / Aadhaar update or your account is blocked (Hindi / Hinglish / Odia)",
                  "Asks for your OTP / PIN (Hindi / Hinglish / Odia)",
                  "Instant loan without CIBIL / documents (Hindi / Hinglish / Odia)",
                  "Refund / cashback that needs your UPI PIN",
                  "Lottery / prize - pay a fee first (Hindi / Hinglish / Odia)"),
    "brand": ("Parcel with drugs / passports in your name (courier - digital arrest)",
              "Lottery / prize - pay a fee first (Hindi / Hinglish / Odia)",
              "Work-from-home task job (Hindi / Hinglish / Odia)",
              "Refund / cashback that needs your UPI PIN"),
    "contact": ("'My new number' - send money urgently (Hindi / Hinglish)",),
    "teacher": ("Asks for your OTP / PIN (Hindi / Hinglish / Odia)", "Work-from-home task job (Hindi / Hinglish / Odia)"),
    "management": (),
}
