"""Quick URL benchmark.  Run from the backend folder:   python benchmark_urls.py
Network lookups are switched off so the result is the same every time."""
import warnings
warnings.filterwarnings("ignore")
from app.detectors.malicious_url import analyze_url

SAFE = [
    "https://www.google.com", "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://retail.onlinesbi.sbi/retail/login.htm", "https://netbanking.hdfcbank.com/netbanking/",
    "https://www.amazon.in/dp/B0CHX1W1XY?ref=ppx_yo2ov_dt_b_product_details",
    "https://www.irctc.co.in/nget/train-search", "https://www.incometax.gov.in/iec/foportal/",
    "https://github.com/ashisp9337-cell/Cyberdeck-AI", "https://www.linkedin.com/in/some-user-123/",
    "https://www.makemytrip.com/flights",
]
PHISH = [
    "http://paypa1-login.verify-account.xyz/signin", "https://sbi-yono-kyc.web.app/update",
    "https://hdfc-netbanking-secure.pages.dev/login", "http://192.168.43.21/icici/login.php",
    "https://amazon-in.order-refund.shop/claim", "https://login.microsoftonline.com.secure-auth.ru/owa/",
    "https://incometax-refund.in.net/verify", "https://google.com@evil-site.tk/login",
    "https://aadhaar-update-uidai.co/kyc", "https://netflix-billing-update.com/account",
]

def score(u):
    return analyze_url(u, "x", subtopic_id="malicious-url", network=False)["riskScore"]

safe_scores = [score(u) for u in SAFE]
phish_scores = [score(u) for u in PHISH]
print(f"Real sites flagged (score > 50):    {sum(s > 50 for s in safe_scores)} of {len(SAFE)}   <- want 0")
print(f"Phishing links caught (score > 50): {sum(s > 50 for s in phish_scores)} of {len(PHISH)}  <- want {len(PHISH)}")
for u, s in zip(SAFE, safe_scores):
    if s > 50: print("  FALSE ALARM", s, u)
for u, s in zip(PHISH, phish_scores):
    if s <= 50: print("  MISSED     ", s, u)