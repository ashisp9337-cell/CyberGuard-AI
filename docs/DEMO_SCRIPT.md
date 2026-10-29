# CyberGuard AI: demo script (about 7 minutes)

Every input below is in `backend/demo_cases.py` and is checked by `python demo_check.py`: each must get the verdict
written here. **Run that check on the demo laptop the evening before and again 30 minutes before you go on stage.**

All scam examples are made up for the demo. The scam web addresses are unregistered names, so no phishing site is
contacted. The attacker IP addresses come from the ranges reserved for documentation.

---

## The day before

| ✔ | What | Why |
|---|---|---|
| ☐ | `python demo_check.py --gemini` ends with **READY FOR THE DEMO** | every demo input, the database, the models and the chat backup are checked at once |
| ☐ | Put 4 files in `backend\demo_samples\`: `real_photo.jpg`, `ai_image.png`, `fake_video.mp4`, `real_video.mp4`, then re-run the check | the deepfake part uses your own files. Pick ones that pass, and keep videos short (10–20 s) |
| ☐ | **Record a screen video of the whole demo** (Win + G or OBS) | if anything breaks on stage, you play the recording and keep talking |
| ☐ | Make a demo account and run each demo input once | the dashboard and scan history then show real activity |
| ☐ | Charge the laptop, and have a phone hotspot ready | the scans work without internet; the chat and the registry checks need it |
| ☐ | Gemini: decide about the free limit (see the end of this file) | the free tier allows 20 requests a day per model |

## 30 minutes before

1. Start PostgreSQL, then the backend: `cd backend`, `venv\Scripts\activate`, `uvicorn app.main:app --port 8000`.
2. In a second terminal, start the frontend: `npm run dev`.
3. In a third terminal: `python demo_check.py`. It must say **READY FOR THE DEMO**.
4. Open http://localhost:5173, log in, and zoom the browser to 125% so judges can read it.
5. Open this file and `demo_cases.py` side by side for copy-paste. Close other apps and turn off notifications
   (Focus assist).

---

## The demo

### 0:00 – Opening (30 s)
> "Every day Indians get SMS about parcels on hold, calls from fake police announcing a 'digital arrest', and
> messages from a 'principal' asking for gift cards. These scams are in many forms: SMS, links, QR codes, deepfake
> videos, stolen logins. CyberGuard checks all of them in one place, explains **why** something is dangerous, and
> every model is tested on data it has never seen."

### 0:30 – Phishing (1 min 15 s)
Open **Phishing** and paste **P1**:
```
India Post: Your parcel is on hold due to an incomplete address. Pay Rs 25 redelivery fee within 12 hours at http://indiapost-redeliver.top/pay or it will be returned.
```
**Expected:** score about **71, high risk**. Point at the evidence: *Scam pattern: parcel held – pay a fee*, the
link scored on its own, and the subtopic chosen automatically (*SMS analysis*).
> "It recognised the parcel-fee scam and checked the link inside the message by itself."

Then paste **P2**, a real OTP message:
```
482913 is your OTP for login to the BPUT student portal. Do not share it with anyone.
```
**Expected:** about **20, safe**.
> "A real OTP message is not flagged. A detector that flags everything is useless."

*(If there is time, upload `test_samples\qr_upi_refund_scam.png` (**P5**). It shows a UPI "refund" QR that actually
**takes** ₹4,999 (about 88). The QR is decoded and the UPI request is read.)*

### 1:45 – URL security (1 min)
Open **URL Security** and scan **U1**:
```
https://sbi-netbanking-login.top/retail/login
```
**Expected:** **100, critical**. Show the look-alike of SBI and the risky ending (.top). With internet you also see
*registry record not found / brand-new domain*.

Then the real one, **U3**:
```
https://retail.onlinesbi.sbi/retail/login.htm
```
**Expected:** about **15, safe**.
> "Same bank, same login path: one is fake, one is real. On a live page, our fake-login-page model also reads the
> page's code. It was trained on 4,500 real pages, caught 85% of phishing pages, and wrongly flagged only 1% of
> real ones."

### 2:45 – Impersonation (1 min)
Open **Impersonation** and paste **I3**, the "digital arrest" scam:
```
This is Inspector Sharma from Mumbai Cyber Crime. A parcel with drugs in your name was seized. You are under digital arrest. Do not disconnect the video call and transfer Rs 50,000 for verification or we will issue an arrest warrant.
```
**Expected:** about **85**. The category is detected automatically (*Government official impersonation*). Show the
MITRE ATT&CK technique and the "what to do" steps.

Quick second one, **I1** (made for a college audience):
```
Hi, this is Principal Dr. Mishra. I'm in a meeting and can't talk. I need you to buy 5 Amazon gift cards of Rs 2000 each for a staff event and send me the codes urgently.
```
**Expected:** about **89**.

### 3:45 – Account takeover (45 s)
Open **Credential Theft** and paste **C2** (copy it from `demo_cases.py`, the case "Same-country takeover"):
7 normal logins from Bhubaneswar, then at 23:50 a new Android device in Delhi, MFA disabled, and all mail forwarded.

**Expected:** about **98**, subtopic *Unknown device*. The evidence lists: MFA settings changed, mail forwarding
rule, unrecognised device.
> "This attacker stayed in India, so a 'foreign country' check would miss it. The sequence of what happened after
> the login gives it away."

### 4:30 – Deepfake (45 s)
Open **Deepfake** and upload `demo_samples\fake_video.mp4`, then `real_video.mp4`.
> "16 frames are sampled and every face is checked by a model trained on Celeb-DF. On videos it had never seen it
> had an AUC of 0.996, and it still caught 83% after heavy compression."

**Honest line, if asked:** on a different dataset (DFDC) it is weaker (AUC 0.72); fully AI-generated video doesn't
have a model yet, and the app then says *unverified*, never *real*.

*(Optional — 30 s: **Deepfake → Voice & Audio Analysis**, upload `demo_samples\my_voice_clone.*` — an AI clone of
**your own** voice — then `my_real_voice.*`. Optionally add your real recording in the second box for the voice match.)*
> "It listens for the fingerprints of AI voices with a speech model tested on real deepfakes from the internet, it
> turns the words into text — Hindi too — and checks them with our scam models, because a real voice reading a scam
> script is still a scam. And it never says a voice is proven real."

*(Optional, if there is time — 30 s: **Cyber Threat Detection → System & Application Log Analysis**, upload
`test_samples\loghub_openssh_real_attacks.log`. Expected: about **80**, "Read 2,000 log lines", incident
**Password brute-force attack** with the attackers' IP addresses and times.)*
> "This is a real server log from the LogHub research collection. The whole file is read; one wrong password is
> normal, so it looks for bursts. The burst sizes were chosen from a dataset of real attacks on four servers, and on
> normal logs from 14 other real systems it raised nothing."

*(Optional — 30 s: **Cyber Threat Detection → Suspicious Network Traffic Detection**, upload your own
`demo_samples\nmap_scan.pcapng` — captured in Wireshark while you ran nmap from Kali against **your own VM**.
Expected: **71 or more**, incident **Port scan** with the scanner's address and how many ports it tried.)*
> "This is a real capture I recorded. Every packet becomes a connection, and it looks at behaviour: one machine trying
> a thousand ports in seconds. The alert levels were learned from 2.1 million real connections, and we tested it on
> days of attacks it had never seen."

*(Optional — 45 s: **Cyber Threat Detection → Insider Risk**, upload
`backend\app\ml\training\data\insider\demo\insider_demo_leak.csv` (real CERT activity: 20 people, about 6 weeks).
Expected: **71 or more**; first in the queue is the CERT insider named in `insider_demo_answers.txt`, at alert level, with
the three lenses filled in. Do not open the answers file on screen before the scan.)*
> "This is one engine for data exfiltration, abnormal activity and insider threat, like a small SOC. Each person is
> compared with their own last 30 days and with colleagues in the same role. Trained on CERT's insider dataset, it
> caught all 35 insiders it had never seen with 10 reviews a day; for insider *patterns* it never saw, 40 of 70 -
> that's the honest number. It's a review queue for an analyst, not a verdict on a person."

*(Optional — 30 s: **Cyber Threat Detection → Malware Detection**. NEVER use real malware. Upload (1) any normal
program, e.g. a copy of an installer you downloaded from its official site: expected **low**, the model gives a low
score; then (2) the same file renamed `invoice.pdf.exe`: expected **80 or more**, "Double file extension".)*
> "The file is only read, never run. Every program goes through the EMBER2024 model, trained on 2.6 million real files;
> we set its alert level so only 0.1% of clean files reach it, and tested it on newer malware it never saw - including
> malware that 70 antivirus engines first missed. And a program pretending to be a PDF is flagged on its own."

### 5:15 – Threatora, the assistant (45 s)
On a result, click **"Ask Threatora about this scan"**. Then switch the reply language with the **हिं** or **ଓଡ଼ି** button and ask
*"What should I do now?"*
> "Phone numbers, OTPs and card numbers are masked before anything is sent to the AI, and text that tries to trick
> the AI is detected."

*(If Gemini is slow or out of quota, a backup answer appears that says so. Say: "and if the AI service is down, it
still answers from our own data." That is a feature, not a failure.)*

### 6:00 – Close (45 s)
Show the **Dashboard** (scans, alerts, threat types), then:
> "Six modules, more than 20 trained models, 758 automated tests, and every number we quote comes from data the model never
> saw. Where it's weak, we say so. That's what makes it trustworthy."

---

## If something goes wrong

| Problem | What to do |
|---|---|
| No internet / venue Wi-Fi blocked | Keep going: every demo input above works offline (checked). The registry details and the chat need the internet, so switch to the phone hotspot for those. |
| Chat shows the "AI assistant is busy" backup answer | Say the line above and move on. |
| Backend crashed or a page shows an error | In the backend terminal: Ctrl+C, then `uvicorn app.main:app --port 8000` (about 10 s). Meanwhile, talk about the results table. |
| A scan gives a different score | Read out the evidence list; the explanation matters more than the exact number. Then run `demo_check.py` later to see what changed. |
| Laptop dies | Play the recorded demo video from your phone or a teammate's laptop. |

## Questions judges are likely to ask (honest answers)

- **"Is this just keyword matching?"** No. There are trained models (scikit-learn, and ONNX for images and video)
  plus explainable rules, and every model is tested on unseen data: unseen websites, phishing kits, people and time
  periods. The rules exist so every verdict can be explained.
- **"How accurate is it?"** Give the numbers with the false-alarm rate, never "99%". For example: fake login pages
  85% caught with 1% false alarms; face-swap video AUC 0.996 on unseen Celeb-DF videos but 0.72 on DFDC.
- **"Where does the data come from?"** urlscan.io, OpenPhish, PhishTank, Tranco, UCI datasets, the RBA login
  dataset (31 million logins), Celeb-DF, OpenForensics. All are public and credited in the README.
- **"Does it send my data to Google?"** Only the chat sends anything, and private details are masked first. All the
  detectors run locally.
- **"Is the scanner safe when it opens a phishing link?"** It reads the page as text only: no JavaScript, no forms,
  no cookies. It never connects to private addresses and checks every redirect hop.
- **"Is the insider detection real?"** It is trained on CERT r4.2, the standard insider-threat benchmark, which is
  *simulated* (real employee data is never published). Known playbooks in new people: 35 of 35; patterns it never saw:
  40 of 70. It flags for review; HR and a person decide.
- **"Can it read our Windows logs?"** Yes: an .evtx saved from Event Viewer, or a JSON / XML export (Sysmon,
  Defender, PowerShell too). The rules were tested on 121 real attack recordings: the technique was seen in 63, and
  credential theft in 20 of 24. Each finding names the user and computer.
- **"Do you run the uploaded file?"** Never. It is read as bytes (pefile, pure Python) in a separate process with a time
  limit and deleted afterwards. That also means malware that only shows itself when run can look clean - we say so.
- **"What would you add next?"** A model for AI-generated video, Indian-language voice-deepfake data, FaceForensics++ for
  stronger video results, and more real Indian scam data.

## Gemini free limit (decide before the day)
The free tier allows about **20 chat requests per day per model**. CyberGuard tries a second model automatically,
then falls back to backup answers. Two choices:
1. **Stay free:** don't use the chat while rehearsing on demo day; run `demo_check.py --gemini` only once.
2. **Enable billing** on the Google AI Studio key: the cost for a demo is a few rupees, and the limit goes away.
