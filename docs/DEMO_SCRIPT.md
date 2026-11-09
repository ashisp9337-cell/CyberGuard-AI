# CyberGuard AI: demo script (about 7½ minutes)

*(Updated 7 Nov 2026: automatic protection, browser extension, PC Network page, new start-up commands.)*

Every input below is in `backend/demo_cases.py` and is checked by `python demo_check.py`: each must get the verdict
written here. **Run that check on the demo laptop the evening before and again 30 minutes before you go on stage**
(in the backend folder: `venv\Scripts\python.exe demo_check.py`).

All scam examples are made up for the demo. The scam web addresses are unregistered names, so no phishing site is
contacted. The attacker IP addresses come from the ranges reserved for documentation.

---

## The day before

| ✔ | What | Why |
|---|---|---|
| ☐ | `venv\Scripts\python.exe demo_check.py --gemini` ends with **READY FOR THE DEMO** | every demo input, the database, the models and the chat backup are checked at once |
| ☐ | Put 4 files in `backend\demo_samples\`: `real_photo.jpg`, `ai_image.png`, `fake_video.mp4`, `real_video.mp4`, then re-run the check | the deepfake part uses your own files. Pick ones that pass, and keep videos short (10–20 s) |
| ☐ | **Record a screen video of the whole demo** (Win + G or OBS) | if anything breaks on stage, you play the recording and keep talking |
| ☐ | Make a demo account and run each demo input once | the dashboard and scan history then show real activity |
| ☐ | Charge the laptop, and have a phone hotspot ready | the scans work without internet; the chat and the registry checks need it |
| ☐ | Gemini: decide about the free limit (see the end of this file) | the free tier allows 20 requests a day per model |
| ☐ | **Rehearse the "Automatic protection" part today, not on demo morning** | each automatic finding is reported once: a website attack once a day, an open port once a week. A rehearsal on the morning would use them up before the judges see them |
| ☐ | Settings → Automatic Protection: switch on *Network connections*, *Websites this PC looks up*, *Your website's requests* | the dashboard must show **3/7 · all working** (more if Gmail / Downloads are on too) |
| ☐ | Browser extension connected: its toolbar icon says **Protecting** | the extension is the live part of URL security |
| ☐ | Wi-Fi at the venue → Settings > Network & internet → set it to **Public network** | Windows then blocks your open ports from other people on the same Wi-Fi |

## 30 minutes before

PostgreSQL starts with Windows (service *postgresql-x64-18*) and now only accepts connections from this laptop.
Use `venv\Scripts\python.exe` directly — `venv\Scripts\activate` is blocked in PowerShell on this laptop.

1. Backend (terminal 1):
   ```
   cd C:\Users\ashis\Desktop\cyberguard-ai-fullstack\cyberguard-ai\backend
   venv\Scripts\python.exe -m uvicorn app.main:app --port 8000 --no-server-header
   ```
   Wait for **`voice / image / video models ready`** (about a minute). Until then the pages answer slowly.
2. Website (terminal 2, project folder): `npm run demo` — the fast production version at the same address.
3. Check (terminal 3, backend folder): `venv\Scripts\python.exe demo_check.py`. It must say **READY FOR THE DEMO**.
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
**Expected:** score about **74, high risk**. Point at the evidence: *Scam pattern: parcel held – pay a fee*, the
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

### 4:30 – Automatic protection: it works without anyone pasting anything (1 min 30 s)
> "Scanning what you paste is not enough - nobody pastes every link. So CyberGuard also watches by itself, after
> asking permission."

1. **Browser extension (works in Chrome, Edge, Brave, Opera).** In the address bar type exactly
   `http://secure-paypa1-login.test/account/verify` and press Enter.
   **Expected:** the red page **"CyberGuard stopped this website"**, score **93**, reasons *Look-alike of paypal*,
   *No HTTPS*, *2026 link model*. Click **Go back to safety** (never "open it anyway" - that lets the site through
   until the browser is closed).
   > "The address is judged on this laptop by our models - CyberGuard never opens the fake site. A `.test` address can
   > never be a real website, so this demo is safe."
2. **Your own website under attack.** In a separate PowerShell window, paste this one line (7 fake attack requests
   against our own backend, looking like the sqlmap hacking tool):
   ```
   $paths = "/api/health?id=1%27%20OR%20%271%27=%271", "/api/health?q=%3Cscript%3Ealert(1)%3C/script%3E", "/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/shell.php?cmd=whoami"; foreach ($p in $paths) { curl.exe -s -o NUL -A "sqlmap/1.8" "http://127.0.0.1:8000$p" }
   ```
   Within a minute **Scan History** shows four findings from 127.0.0.1: *Web attack payloads* (SQL injection, XSS),
   *Web shell / remote command execution*, *Web vulnerability scan* and *Attack / scanning tool identified* (sqlmap).
   > "Every GET and POST that reaches our site goes through the same log checks we validated on 143,000 real requests
   > from a red-team competition."
3. **PC Network page.** Show the live open ports and connections, then tell the true story:
   > "On its first run, CyberGuard flagged our own PostgreSQL database as open to the whole Wi-Fi. We fixed it,
   > and now the port says *this computer only*."

   *(Optional, +20 s: in PowerShell, in the backend folder, run
   `venv\Scripts\python.exe -m http.server 1337 --bind 127.0.0.1 --directory C:\Users\ashis\cg-port-test` (make the
   empty folder first). Within 30 s: **"A program is listening on backdoor port 1337"**, critical, with "find the
   program" steps. Ctrl+C to stop. Rehearse with port **4444**, so 1337 is still unreported on the day.)*

### Optional – Company mode (+1 min 15 s): one server protects every employee's PC

Prepare (the day before): the cloud link (or the laptop) runs with `COMPANY_NAME` / `COMPANY_EMAIL_DOMAINS` set
(docs/COMPANY_MODE.md); your admin account plus one employee account exist; on the Devices page the laptop is added as
an employee PC and the agent runs in an administrator terminal:
`backend\venv\Scripts\python.exe agent\cyberguard_agent.py` (it shows **online** within a minute).

1. **Employees** (as administrator): "Every employee uses all the modules for their own protection. The administrator
   also sees the company: who is online, their sign-ins, scans and threats, failed sign-ins." Click **Activity** on the
   employee. Show **Invite**: a judge's Gmail is refused at sign-up until you invite it.
2. **Devices**: "Each company PC runs the CyberGuard Agent. It only reads security facts - open ports and
   connections, failed Windows sign-ins, website names, new risky downloads - and the central server judges them with
   the same engines." Open **Details** on the laptop: its open ports and findings.
3. Optional live finding: copy a harmless test program into Downloads under a fake name
   (`copy C:\Windows\System32\notepad.exe %USERPROFILE%\Downloads\Invoice_2026.pdf.exe`) - within a minute the
   Devices page shows the finding (*a program pretending to be a PDF*). Delete the copy afterwards.
4. Say: "If an employee's PC is compromised, the security team sees it on one screen; disabling the account signs the
   person out everywhere and stops that PC's agent."

### Optional – Deepfake (+45 s, only with your own files in `demo_samples\`)
Open **Deepfake** and upload `demo_samples\fake_video.mp4`, then `real_video.mp4`.
> "16 frames are sampled and every face is checked by a model trained on Celeb-DF and FaceForensics++ (107,417
> faces). On Celeb-DF videos it had never seen: AUC 0.999 - 89% caught with no false alarm, and 83% still caught after
> heavy compression. On FaceForensics++'s official test: 0.942."

**Honest line, if asked:** on a dataset it never trained on (Meta's DFDC) the AUC is 0.839, but the strict alert level
catches only 17% of those fakes (39% at "check carefully") - it is set so real videos are not flagged. Fully
AI-generated video doesn't have a model yet, and the app then says *unverified*, never *real*.

*(Optional — 30 s: **Deepfake → Voice & Audio Analysis**, upload `demo_samples\my_voice_clone.*` — an AI clone of
**your own** voice — then `my_real_voice.*`. Optionally add your real recording in the second box for the voice match.)*
> "It listens for the fingerprints of AI voices with a speech model tested on real deepfakes from the internet, it
> turns the words into text — Hindi too — and checks them with our scam models, because a real voice reading a scam
> script is still a scam. And it never says a voice is proven real."

**Honest line, if asked:** on real recordings from the internet (In-the-Wild, 28,319 clips the model never heard)
it caught 97.7% of the deepfakes, but about 1 in 4 real voices also reached the alert level - so a voice alert means
*check*, never proof.

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

### 6:00 – Threatora, the assistant (45 s)
On a result, click **"Ask Threatora about this scan"**. Then switch the reply language with the **हिं** or **ଓଡ଼ି** button and ask
*"What should I do now?"*
> "Phone numbers, OTPs and card numbers are masked before anything is sent to the AI, and text that tries to trick
> the AI is detected."

*(If Gemini is slow or out of quota, a backup answer appears that says so. Say: "and if the AI service is down, it
still answers from our own data." That is a feature, not a failure.)*

### 6:45 – Close (45 s)
Show the **Dashboard** (scans, alerts, threat types, *Protection Status*: watchers on, IOCs, ATT&CK), then:
> "Six modules, more than 20 trained models, over 1,000 automated tests, automatic protection that asks permission
> first, and every number we quote comes from data the model never saw. Where it's weak, we say so. That's what makes
> it trustworthy."

---

## If something goes wrong

| Problem | What to do |
|---|---|
| No internet / venue Wi-Fi blocked | Keep going: every demo input above works offline (checked), and so do the browser extension, the PC Network page and the automatic watchers. The registry details, live page reading, the chat, Telegram / e-mail alerts and the Gmail watcher need the internet, so switch to the phone hotspot for those. |
| Chat shows the "AI assistant is busy" backup answer | Say the line above and move on. |
| Pages are slow right after starting | The models are still loading. Wait for `voice / image / video models ready` in the backend terminal. |
| Extension says "CyberGuard is not running on this computer" | The backend is off - start it (terminal 1). Pages still open normally meanwhile. |
| `npm run demo` says port 5173 is in use | An old `npm run dev` is still running: close that terminal and run it again. |
| An automatic finding does not appear again | Expected: each one is reported once (website attack: once a day, open port: once a week). Show the earlier finding in Scan History. |
| Backend crashed or a page shows an error | In the backend terminal: Ctrl+C, then `venv\Scripts\python.exe -m uvicorn app.main:app --port 8000 --no-server-header` (about 10 s plus model loading). Meanwhile, talk about the results table. |
| A scan gives a different score | Read out the evidence list; the explanation matters more than the exact number. Then run `demo_check.py` later to see what changed. |
| Laptop dies | Play the recorded demo video from your phone or a teammate's laptop. |

## Questions judges are likely to ask (honest answers)

- **"Can a company use it?"** Yes: one server, company e-mail domains + invites, Google sign-in, an Employees page,
  and the CyberGuard Agent on each PC reporting to the server (Devices page). The agent is read-only (it never blocks or
  deletes), tells the employee what it reads, sends website NAMES only (the server keeps only dangerous ones) and risky
  downloads only. Honest limits: the agent is a Python program (a one-click installer is the next step), and the
  Windows sign-in part needs administrator rights.

- **"Is this just keyword matching?"** No. There are trained models (scikit-learn, and ONNX for images and video)
  plus explainable rules, and every model is tested on unseen data: unseen websites, phishing kits, people and time
  periods. The rules exist so every verdict can be explained.
- **"How accurate is it?"** Give the numbers with the false-alarm rate, never "99%". For example: fake login pages
  85% caught with 1% false alarms; face-swap video AUC 0.999 on unseen Celeb-DF videos but 0.839 on DFDC (only 17% caught at the strict level).
- **"Where does the data come from?"** urlscan.io, OpenPhish, PhishTank, Tranco, UCI datasets, the RBA login
  dataset (31 million logins), Celeb-DF, FaceForensics++, OpenForensics. All are public and credited in the README.
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
- **"Does the automatic protection spy on me?"** Every watcher has an on/off switch in Settings, and the three that
  read more of the PC (network connections, website names, your website's requests) start off and run only after you
  allow them. Those three only read - ports, website names, request lines; no page contents, no cookies - and block
  nothing. The Gmail and Downloads watchers can move a dangerous email or file into quarantine, and that can be undone.
  The browser extension reads a page's code only on pages that ask for a password, and only if you tick that option.
  Everything is judged on the laptop; nothing they find leaves it except your own alerts (Telegram / e-mail).
- **"Is CyberGuard itself secure?"** We attacked it ourselves: 56 of 56 pentest checks pass (login, access between
  users, SQL injection, SSRF, CORS, oversized requests), rate limits on every route, security headers, bcrypt
  passwords, and the whole Git history was scanned for leaked keys (none). The extension's keys are stored only as
  hashes.
- **"What would you add next?"** A model for fully AI-generated video, fewer false alarms on real-world voices
  (Indian-language voice data), newer AI-image generators, and more real Indian scam data.

## Gemini free limit (decide before the day)
The free tier allows about **20 chat requests per day per model**. CyberGuard tries a second model automatically,
then falls back to backup answers. Two choices:
1. **Stay free:** don't use the chat while rehearsing on demo day; run `demo_check.py --gemini` only once.
2. **Enable billing** on the Google AI Studio key: the cost for a demo is a few rupees, and the limit goes away.
