r"""Test the Hindi / Hinglish / Odia scam patterns (app/detectors/indic_scams.py) on REAL text.

There is no openly licensed, real, labelled Hindi or Odia scam-SMS dataset, so the patterns are rules written from
public warnings, and this script measures them in the two ways that are possible with real data:

1. FALSE ALARMS on real, ordinary text (none of it is a scam):
     * Hindi news / Wikipedia sentences - Universal Dependencies UD_Hindi-HDTB (~16,600) and UD_Hindi-PUD (1,000)
     * Odia sentences - UD_Odia-ODTB
     * Hinglish written by people - Google's Hinglish-TOP dataset (requests like "kal subah 9 baje ka alarm laga do")
     * the legitimate rows of the real SMS corpus used to train the SMS model (if present)
   Single sentences are short, so the UD sentences are also tested three at a time (one SMS-sized chunk).
2. CATCHES on real scam messages quoted word for word by banks, news and fact-check sites (QUOTES below, with the
   source). "dev" quotes were read while the patterns were written; "held-out" quotes were collected afterwards and
   never used to change a pattern. Quotes marked "cut" were shortened by the source or by the quoting tool and miss
   part of the message - they are reported apart.
   Plus: how many rows of the real SMS corpus's scam side the new patterns fire on (most of it is not Indian).

Get the data once (about 130 MB, from the backend folder; licences: UD CC BY-SA / CC BY-NC-SA, Hinglish-TOP Apache-2.0):
    git clone --depth 1 https://github.com/UniversalDependencies/UD_Hindi-HDTB app\ml\training\data\indic\UD_Hindi-HDTB
    git clone --depth 1 https://github.com/UniversalDependencies/UD_Hindi-PUD  app\ml\training\data\indic\UD_Hindi-PUD
    git clone --depth 1 https://github.com/UniversalDependencies/UD_Odia-ODTB  app\ml\training\data\indic\UD_Odia-ODTB
    git clone --depth 1 https://github.com/google-research-datasets/Hinglish-TOP-Dataset app\ml\training\data\indic\Hinglish-TOP-Dataset
    python -I app\ml\training\test_indic_scams.py app\ml\training\data\indic
Writes app/ml/models/indic_scams.json (numbers) and app/ml/training/indic_scams_report.txt (every text a pattern fired
on, and every quote missed, to read; git-ignored).
"""
import csv
import glob
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, BACKEND)   # the backend folder (python -I ignores cwd)

from app.detectors import indic_scams as I  # noqa: E402
from app.detectors import phishing as P  # noqa: E402

NAMES = {p[0] for p in I.PATTERNS}
SMS_CORPUS = os.path.join(HERE, "data", "phishing_sms_clean_v2.tsv")
OUT_JSON = os.path.join(BACKEND, "app", "ml", "models", "indic_scams.json")
OUT_REPORT = os.path.join(HERE, "indic_scams_report.txt")

# (message as quoted, source, dev / held-out, cut?)
QUOTES = [
    ("Dear Customer, आपका बिजली कनेक्शन आज रात 9 बजे काट दिया जाएगा। तुरंत ₹1,850 का पेमेंट करें। Contact: 9876XXXXXX",
     "https://lock.pub/hi/blog/electricity-bill-scam-india", "dev", False),
    ("आपका बिजली कनेक्शन आज कट जाएगा।", "https://lock.pub/hi/blog/electricity-bill-scam-india", "dev", True),
    ("प्रिय ग्राहक, आपका KYC लंबित है। आपका खाता आज ब्लॉक कर दिया जाएगा। अपडेट करने के लिए यहाँ क्लिक करें।",
     "https://allblogs.in/post/fake-kyc-update-sms-scam-check-before-click/hindi", "dev", False),
    ("आपकी बैंक केवाईसी की अवधि समाप्त हो गई है। आज खाता ब्लॉक कर दिया जाएगा। अपडेट करने के लिए लिंक पर क्लिक करें।",
     "https://allblogs.in/post/fake-kyc-update-sms-scam-check-before-click/hindi", "dev", False),
    ("प्रिय ग्राहक, अधूरी केवाईसी के कारण आपका डेबिट कार्ड निलंबित कर दिया जाएगा। अभी अपडेट करें।",
     "https://allblogs.in/post/fake-kyc-update-sms-scam-check-before-click/hindi", "dev", False),
    ("आपके वॉलेट की KYC लंबित है। 24 घंटे के भीतर सत्यापन पूरा करें।",
     "https://allblogs.in/post/fake-kyc-update-sms-scam-check-before-click/hindi", "dev", False),
    ("RBI KYC सत्यापन आवश्यक है। खाते को फ्रीज़ होने से बचाने के लिए OTP साझा करें।",
     "https://allblogs.in/post/fake-kyc-update-sms-scam-check-before-click/hindi", "dev", False),
    ("नेट बैंकिंग को पुनः सक्रिय करने के लिए यह सुरक्षित KYC ऐप इंस्टॉल करें।",
     "https://allblogs.in/post/fake-kyc-update-sms-scam-check-before-click/hindi", "dev", False),
    ("आपका बैंक अकाउंट 2 घंटे में ब्लॉक हो जाएगा। अभी KYC अपडेट करें,",
     "https://indianpaycalculator.in/sarkari-news/rbi-fake-kyc-account-closure-2-hours-scam-2026", "dev", False),
    ("2 घंटे में अकाउंट बंद, अभी KYC अपडेट करो",
     "https://indianpaycalculator.in/sarkari-news/rbi-fake-kyc-account-closure-2-hours-scam-2026", "dev", False),
    ("अपना KYC अभी अपडेट करें, नहीं तो आपका बैंक खाता फ्रीज हो जाएगा!",
     "https://www.thequint.com/hindi/webqoof/kyc-bank-fake-calls-scam-guard-how-to-identify-phishing-email-and-bank-requests-scamguard",
     "dev", False),
    ("your electricity power will be disconnected tonight at 9.30 pm from electricity office",
     "https://www.tribuneindia.com/news/chandigarh/chandigarh-electricity-dept-cautions-consumers-against-fake-messages-circulating-via-social-media-sms-430693/amp",
     "dev", True),
    ("Sir I am WhatsApp customer officer calling from WhatsApp head office New Delhi. Your WhatsApp number has won lottery of 25,00",
     "https://www.sonicwall.com/blog/indian-whatsapp-customers-are-being-targeted-for-fraudulent-attacks", "dev", True),
    ("Sir I am customer officer from Kaun Banega Crorepati (KBC) Mumbai, you have won lottery of 25,00,000 from our company, congra",
     "https://www.sonicwall.com/blog/indian-whatsapp-customers-are-being-targeted-for-fraudulent-attacks", "dev", True),
    ("Hello Sir, I am Sonia Kumari from Kaun Banega Crorepati (KBC) company director call Centre Mumbai. You have a good news and s",
     "https://www.sonicwall.com/blog/indian-whatsapp-customers-are-being-targeted-for-fraudulent-attacks", "dev", True),
    # ---- held-out: collected after the patterns were written, never used to change one ----
    ("Dear customer, your electricity power will be disconnected. Tonight at 9:30 from the electricity officer. Our previous month",
     "https://www.siasat.com/telangana-electricity-board-warns-people-against-online-fraud-2660063/amp/", "held-out", True),
    ("Your bank account will be blocked. Click here to update KYC immediately.",
     "https://www.iob.bank.in/documents/d/guest/iob-anna-series-chapter-14-the-fake-kyc-trap", "held-out", False),
    # copied from a PDF: the broken Hindi spacing / letters are as published
    ("आपका बैंक अकाउं ट ब्लॉक हो र्जाएगा। तुरंत KYC अपडेट करनेकेललए यहााँ क्ललक करें।",
     "https://www.iob.bank.in/documents/d/guest/iob-anna-series-chapter-14-the-fake-kyc-trap", "held-out", False),
    ("aapke liye good news hai aapke iss number pe Kaun Banega Maha Crorepati ki Janab se Aapke is number pe",
     "https://www.boomlive.in/viral-fake-kbc-lottery-promising-rs-25-lakhs-traced-to-pakistan", "held-out", True),
    ("All you need to do here is to LIKE the videos(YouTube) and you will be paid Rs. 50 per video you LIKE.",
     "https://www.mymobileindia.com/like-a-video-and-make-money-scam-all-about-the-cyber-fraud-on-whatsapp-received-whatsapp-message-asking-you-to-like-youtube-videos-for-rs-150-its-a-scam/amp/",
     "held-out", True),
    ("Do you want to do a part-time work-from-home job and earn money?",
     "https://newschecker.in/scam-watch/fraud-terror-and-trail-of-death-the-telegram-task-scam-spreading-fast-in-india",
     "held-out", True),
]


def fired(text: str) -> list:
    """Names of the Hindi / Hinglish / Odia patterns that fire on the text."""
    inds, _ = P.scam_patterns(text)
    return [i["label"][len("Scam pattern: "):] for i in inds if i["label"][len("Scam pattern: "):] in NAMES]


def _conllu(pattern):
    out = []
    for f in sorted(glob.glob(pattern)):
        with open(f, encoding="utf-8") as fh:
            out += [line[9:].strip() for line in fh if line.startswith("# text = ")]
    return out


def ordinary_texts(folder):
    """{name: [texts]} of real, ordinary (not scam) text found in the folder."""
    sets = {}
    for name, pat in (("Hindi sentences (UD HDTB)", "UD_Hindi-HDTB/*.conllu"), ("Hindi sentences (UD PUD)", "UD_Hindi-PUD/*.conllu"),
                      ("Odia sentences (UD ODTB)", "UD_Odia-ODTB/*.conllu")):
        s = _conllu(os.path.join(folder, pat))
        if s:
            sets[name] = s
            sets[name.replace("sentences", "3-sentence chunks")] = [" ".join(s[i:i + 3]) for i in range(0, len(s) - 2, 3)]
    hg = []
    for f in sorted(glob.glob(os.path.join(folder, "Hinglish-TOP-Dataset", "Dataset", "Human Annotated Data", "*.tsv"))):
        with open(f, encoding="utf-8", newline="") as fh:
            hg += [r["cs_query"] for r in csv.DictReader(fh, delimiter="\t") if r.get("cs_query")]
    if hg:
        sets["Hinglish requests (Hinglish-TOP)"] = hg
    return sets


def sms_corpus():
    if not os.path.exists(SMS_CORPUS):
        return [], []
    legit, scam = [], []
    with open(SMS_CORPUS, encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh, delimiter="\t", quoting=csv.QUOTE_NONE):
            if len(row) >= 2 and row[1].strip():
                (scam if row[0] == "phishing" else legit if row[0] == "legitimate" else []).append(row[1])
    return legit, scam


def main(folder):
    results, report = {"false_alarms": {}, "quotes": {}}, []
    sets = ordinary_texts(folder)
    legit, scam = sms_corpus()
    if legit:
        sets["SMS corpus - rows labelled legitimate"] = legit
    if not sets:
        sys.exit(f"No corpus found in {folder} - see the download commands at the top of this file.")
    for name, texts in sets.items():
        hits = Counter()
        n_fired = 0
        for t in texts:
            f = fired(t)
            if f:
                n_fired += 1
                hits.update(f)
                report.append(f"[FALSE ALARM? {name}] {', '.join(f)}\n    {t[:300]}")
        results["false_alarms"][name] = {"texts": len(texts), "fired": n_fired, "rate": round(n_fired / len(texts), 5),
                                         "by_pattern": dict(hits)}
        print(f"{name:42s} {n_fired:5d} of {len(texts):6,} texts fired ({n_fired / len(texts):.3%})")
    if scam:
        hits = Counter(n for t in scam for n in fired(t))
        n = sum(1 for t in scam if fired(t))
        results["sms_corpus_scam_rows"] = {"texts": len(scam), "fired": n, "by_pattern": dict(hits)}
        print(f"{'SMS corpus - rows labelled scam':42s} {n:5d} of {len(scam):6,} fired (most of the corpus is not Indian)")

    for split in ("dev", "held-out"):
        for cut in (False, True):
            qs = [(t, src) for t, src, s, c in QUOTES if s == split and c == cut]
            if not qs:
                continue
            caught = 0
            for t, src in qs:
                f = fired(t)
                caught += bool(f)
                report.append(f"[{'CAUGHT' if f else 'MISSED'} {split}{' cut' if cut else ''}] {', '.join(f) or '-'}\n    {t}\n    {src}")
            key = f"{split}{' (cut quotes)' if cut else ''}"
            results["quotes"][key] = {"caught": caught, "of": len(qs)}
            print(f"real scam quotes, {key:24s} caught {caught} of {len(qs)}")

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, ensure_ascii=False)
    with open(OUT_REPORT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    print(f"\nwrote {OUT_JSON}\nevery firing / miss is listed in {OUT_REPORT}")
    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
