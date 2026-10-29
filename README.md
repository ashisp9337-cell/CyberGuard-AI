# CyberGuard AI

**AI-powered detection of phishing, scams, impersonation, deepfakes, account takeover and cyber threats — built for
Indian users, with honest results.**

Team **THREATORA** · BPUT Hackathon 2026

Paste a message, a link, a login log or a system log, or upload a QR code, photo or video. CyberGuard decides what
kind of threat it might be, runs the matching trained models and rule checks, and returns:
- a **0–100 risk score** with a verdict: *safe*, *low risk*, *suspicious* (verify first) or *high risk / critical*
- the **evidence in plain words**: which clues fired and why
- the **MITRE ATT&CK** technique, and what to do next

An AI assistant, **Threatora**, explains results in **English, Hindi and Odia**.

---

## What it detects

| Module | Subtopics | How it decides |
|---|---|---|
| **Phishing** | Email, SMS, social-media messages, QR codes, fraudulent websites, malicious URLs | Text models (SMS, email, social media), scam-pattern rules (parcel fee, KYC, task scam, OTP request …; also in **Hindi, Hinglish and Odia**), every embedded link scored by the URL engine, QR decoder (UPI / Wi-Fi / links) |
| **URL security** | Domain spoofing, look-alike domains, URL manipulation, redirect analysis, SSL & domain age, fake login pages | Six trained URL models, live registry (RDAP/WHOIS) and SSL checks, safe read-only page fetch that follows redirects, **Fake Login Page model** on the page's HTML |
| **Impersonation** | Government / police, senior management (CEO fraud), teacher / university, bank, brand, friend or relative ("new number") | A router model picks the category; each category has its own model and rules (e.g. "digital arrest", gift-card requests, scholarship / KYC scams) |
| **Credential theft & account takeover** | Failed logins, password spraying, unusual location, unknown device, session activity, behaviour change | Parses pasted auth logs (SSH, Windows 4625/4624, web logins); trained on 31 million real logins (RBA dataset); rules for brute force, impossible travel, MFA disabled, mail forwarding |
| **Deepfake** | Images, videos, voice notes / calls, AI-generated media | Provenance check (C2PA / AI-tool tags), **AI-image model**, **face-swap image model**, **face-swap video model** (16 frames, every face); **voice**: AI / cloned-voice model, speech-to-text scam-script check (Hindi too), optional voice match against a genuine recording of the person |
| **Cyber threat** | **Malware** (upload a program, app, PDF, Office file or zip - never run), network traffic, API abuse, **Insider Risk** (data exfiltration + abnormal activity + insider threat as one engine), log analysis | Recognises the log format, then rules for encoded PowerShell, LOLBins (certutil …), large transfers, request floods, off-hours activity; **API Abuse model** + attack-type checks (SQL injection, XSS, path traversal, command injection, SSRF, Log4Shell) on every web / API request in a pasted log; **whole log files** (upload .log / .txt up to 15 MB) are read line by line and summarised as incidents; **network traffic**: upload a Wireshark capture (.pcap / .pcapng) or paste flow records / Zeek conn.log / firewall lines - every connection is read and judged for scans, sweeps, floods and login brute force; **Windows event logs** (.evtx from Event Viewer, or JSON / XML exports of Security, Sysmon, PowerShell, Defender): credential theft, security tools switched off, suspicious PowerShell / Windows tools, new accounts and admin-group changes, persistence, remote commands, discovery bursts and password guessing - each attributed to a user and computer; **Insider Risk (mini-SOC / UEBA)**: upload a user-activity log (logons, USB, file copies, e-mail, web; CSV) - every person-day is compared with the person's own past and with colleagues, scored, and shown as a triage queue with three lenses (exfiltration, abnormal activity, insider pattern), MITRE techniques and response steps |

**Auto mode:** inside each module CyberGuard detects the subtopic by itself (e.g. an SMS vs an email, a brute-force
log vs a new-device login), and shows the reason it chose that subtopic.

### Around the detectors
- **Threatora chat assistant** (Google Gemini) can check links and messages with the real detectors, look up domain
  registrations and threat indicators, explain MITRE techniques and answer about *your own* scans and alerts.
  - **Privacy:** phone numbers, OTPs, card / Aadhaar / PAN numbers and e-mail names are replaced with placeholders
    before anything is sent to Google.
  - **Safety:** pasted text that tries to give the AI instructions (prompt injection) is detected and treated as data.
  - **If Gemini is down or the free limit is used up:** built-in backup answers in all three languages.
  - **Screenshots:** send a screenshot of an SMS, chat or QR code. It is read **on this computer** (local OCR + QR
    decoder), scanned by the detectors, and only the text read from it reaches the AI.
  - **Actions with confirmation:** it can prepare releasing a quarantined e-mail, allowlisting an indicator or
    making a report. Nothing happens until you press **Confirm**, and every confirmed action is audit-logged.
  - **Streaming replies and saved history:** answers appear as they are written, and the conversation is kept in
    PostgreSQL.
- **Telegram forwarding:** forward a suspicious message or screenshot to your CyberGuard bot and it replies with
  the verdict. Only your own chat is answered.
- **Gmail inbox protection** (read-only IMAP): scans new mail, quarantines dangerous mail in the app and alerts you.
- **Alerts** by e-mail and Telegram; incidents, indicators of compromise (IOCs), an audit log and PDF reports.
- **Dashboard, scan history, threat overview, live monitoring** (Server-Sent Events).

---

## Models and honest results

Every number below comes from data the model **never saw in training**: held-out websites, phishing kits, people or
time periods. "Caught at alert" is measured at a threshold where only about 1% of real, safe items are flagged.

| Model | Trained on | Result on unseen data |
|---|---|---|
| Fake login page (HTML) | 4,556 urlscan.io page copies: live phishing (OpenPhish / PhishTank) vs real login pages and ordinary websites | AUC **0.981**; **85%** caught at alert with **1.0%** false alarms; October-only phishing: 66% / 0.4% |
| Look-alike domain | 186k generated look-alikes (dnstwist) vs Tranco top sites | AUC **0.993**; 84% caught at alert, 0.7% false alarms |
| Domain age / registry (RDAP) | fresh phishing domains (urlscan + OpenPhish) vs real domains | AUC 0.93; 64% caught at alert, 3.4% false alarms |
| Domain spoofing | PhiUSIIL phishing domains vs Tranco | AUC 0.87; 52% caught at alert, 0.7% false alarms |
| URL manipulation | DEPHIDES (PhishTank + CommonCrawl) + Kaggle URLs | AUC 0.90; 37% at alert / 57% at verify |
| Domain name (2026 re-check) | PhiUSIIL + Tranco; level re-measured on 315,735 real 2026 sites it never saw (Chrome UX Report) | AUC **0.81** on phishing domains first listed April–October 2026; **36%** of them reach "check carefully", 1.05% of real 2026 sites do |
| QR codes (whole URL engine, offline) | 9,987 public QR codes (quishing dataset, CC BY 4.0) + 4,078 urlscan.io 2026 phishing links | 100% of codes decoded; QR phishing caught 19% → **25%** and 2026 phishing links 13% → **25%** after the 21 Oct checks, with real QR links flagged 0.9% → 1.1% |
| API abuse (web-attack requests) | CSIC 2010 attacks + real requests from thousands of websites (CommonCrawl, MIT); judged by request *shape*, not one site's words | AUC **0.947** on an independent attack set (Fwaf), 0.989 vs real requests from unseen websites; alert level flags 0.08–0.15% of real requests; CSIC official test 0.868 |
| Log analysis (whole log files) | Incident detectors (password brute force, web scan, scanning tools, web shell / exploit, account enumeration, probing); burst sizes chosen from the AIT attack dataset (4 attacked servers) + real website logs | On held-out AIT servers: web scan, brute force, web shell and mail enumeration caught on **every** server, 0 real false incidents; nmap probing missed (too few lines). Outside test: 0 incidents on 14 normal real systems (LogHub), real SSH password attacks found in both attacked logs |
| Network traffic (captures, flow records) | Behaviour incidents (port scan, internal host sweep, DoS flood, failed-connection flood, login brute force, backdoor ports, web attacks in plain HTTP); alert levels = busiest *normal* machine in CIC-IDS2017 (KU Leuven's corrected labels, 2.1 million connections) | Each attack day held out in turn: **9 of 15** attack types caught (all brute force, all DoS / DDoS, port scans incl. one the dataset left unlabelled); 4 false incidents on held-out normal traffic (busy clients). Missed: Bot, Heartbleed, infiltration, web attacks hidden in normal volumes. A per-connection model is **supporting only**: AUC 0.64-0.998 on unseen attack days, but it misses most new attack types |
| Malware (uploaded files) | Static checks (disguised extensions, content that does not match its type, macros, PDF scripts, archive tricks) + the **EMBER2024** LightGBM model (Joyce et al., KDD 2025, Apache-2.0) trained by its authors on 2.6 million real files (Windows / .NET / Android / PDF / Linux, Sep 2023 - Sep 2024). CyberGuard's alert levels are set per file type on clean files of the next 6 weeks | Tested by CyberGuard on files first seen Nov-Dec 2024 (never used for training or for the levels) and on the challenge set of malware ~70 antivirus engines first missed: `python show_auc.py` after `calibrate_malware_model.py`. (The authors report test AUC 0.998 for Windows programs and 0.969 on the challenge set.) |
| Windows event rules (Security / Sysmon / PowerShell / Defender) | Rules written from MITRE ATT&CK descriptions before testing (credential theft, LSASS memory reads, security controls off, encoded PowerShell, abused Windows tools, new accounts / admin groups, persistence, remote commands, discovery bursts, password guessing; added 26 Oct: registry tampering with protections, WMI event subscriptions, code injection, commands started through WMI / PowerShell remoting, remote service and account queries over admin pipes) | Tested on **121 real attack recordings** (OTRF Security-Datasets, MIT): the technique was seen in **63** - credential theft 20/24, defense evasion 25/42, persistence 5/9, lateral movement 9/29, discovery 1/9. A review of every incident found 4 kinds of false alarm (Defender's own driver, Teams' autostart, the Azure VM agent reading LSASS, inventory by the machine account), fixed before the final count (first, blind run: 64). Log clearing at the start of each recording is lab procedure and not counted. **26 Oct additions:** 63 → **87** of 121 (written while looking at OTRF's misses, so also tested on an **independent** set never used to write them: EVTX-ATTACK-SAMPLES, 263 attack files: 41 → **61**); one false alarm found and fixed (Windows' own "SCM Event Log" WMI subscription) |
| Insider Risk (exfiltration + abnormal activity + insider threat) | CERT Insider Threat r4.2 (CMU SEI, **synthetic**): 1,000 people, 330,452 person-days, 70 insiders in 3 scenarios. Per person-day: own 30-day baseline, same-role colleagues that day, novelties (first USB, new PC, rare site); a model for known insider playbooks + a label-free "unlike themselves" score - the higher one counts | Trained before 1 Oct 2010, tested after it on **35 insiders it never saw**: with 10 reviews a day (1% of staff) **35 of 35** caught (random picking: 6.5), AUC 0.990; without any web signal 34 of 35. **Never-seen insider patterns** (one scenario left out of training each time): **40 of 70** (random 11.5) - slow job-hunt theft only 11 of 30. False alert-level person-days: 0.8 per day out of ~600 |
| Voice: AI / cloned voice | XLS-R speech model (frozen) + logistic regression, trained in Colab on ASVspoof 2019 LA + MLAAD (modern TTS / cloning) + LibriSpeech, with phone / WhatsApp codecs applied to real and fake alike | Tested on data it never saw: In-the-Wild (real vs deepfake celebrities from the internet), ASVspoof 2019 eval (unseen attacks), held-out MLAAD systems, In-the-Wild after WhatsApp-style compression. Numbers: `python show_auc.py` after the Colab run + the In-the-Wild Kaggle test (`voice_ai.json`) |
| E-mail phishing (text model) | 18,634 real phishing / genuine e-mails | AUC **0.996** on the 20% it never trained on (proved: a copy trained on the other 80% gives the same scores); **0.998** on e-mails unlike any training e-mail; the model alone: 98.8% caught, 3.8% false alarms |
| Hindi / Hinglish / Odia scam rules (added 30 Oct) | No open real Hindi / Odia scam-SMS dataset exists, so 11 rules were written from public warnings (RBI, DoT, I4C, power companies): electricity cut-off, KYC block, OTP ask, lottery / KBC fee, task jobs, digital arrest, drugs-in-parcel, instant loan, UPI refund, "new number", SIM block | False alarms: **0** of 29,001 real ordinary texts (Hindi + Odia news sentences, people's Hinglish requests) and 0 of 6,034 SMS-sized chunks; 35 of 55,143 SMS-corpus rows labelled legitimate - read by hand: all are scam texts with a wrong label. Real scam messages quoted by banks / news: held-out **2 of 2**, dev 8 of 10 (shortened quotes: 1 of 4). Before: the same Hindi KYC / electricity messages scored 4-60 |
| SMS phishing (text model) | 77,891 SMS; the 3,500 template genuine messages added in cleaning are left out of the test | AUC **0.987** on 14,915 held-out real messages; the model alone: 96.3% caught, 6.5% false alarms (rules and link checks are added on top in the app) |
| Social-media messages | UCI YouTube Spam + real SMS | AUC 0.99 on an unseen video, 0.98 on held-out SMS |
| Impersonation: bank / brand / government | real scam and genuine SMS | **91% / 89% / 87%** of scams caught; 1–4% false alarms on real messages on the same topic |
| Impersonation: CEO fraud | real SMS and e-mail | 85% caught, 0% false alarms |
| Impersonation: teacher / university | real SMS and e-mail (very little real data exists) | 51% caught by the model, under 0.5% false alarms; plus rules for gift-card, OTP, offer-letter-fee and scholarship scams |
| Account takeover (RBA) | 31.3 million real logins, Wiefling et al. | AUC 0.94 for an attacker with the right password logging in from attacker networks |
| Login subtopic models (6) | RBA dataset subsets | AUC 0.77–0.998, depending on the subtopic |
| AI-generated image | real photos vs modern AI generators, StyleGAN faces | AUC **0.98**; 80% caught at alert, 1.3% false alarms |
| Face-swap image | OpenForensics faces | AUC 0.95 |
| Face-swap video | Celeb-DF v2 (official test list held out) | AUC **0.996**; **87%** caught at alert with **0** false alarms; still 83% after heavy JPEG compression |

**Where it is weaker (said openly):**
- **Face-swap video on other datasets:** AUC is only 0.72 on DFDC videos (Meta). FaceForensics++ would fix that.
- **Fully AI-generated video** (no face swap): no model yet; the app says *unverified*, never *real*.
- **Voice:** no public training set has Hindi or Odia deepfakes, and brand-new cloning tools may not be caught; the
  verdict is "likely AI" or "no sign of AI", never "proven real". A voice *match* never proves identity (clones are
  built to match). Test it on your own recordings: `python -m app.ml.training.check_voice_samples <folder> --expect real`.
- **Attackers who reuse the victim's own country and network:** caught far less often than foreign logins.
- **Teacher / university scams:** very little real data is public.
- **Hindi / Hinglish / Odia messages:** the text models read English only; these messages are judged by the scam rules (and the English words in them). A scam worded unlike the 11 rules gets a low score with a note saying the result is less certain. The real test set is small (21 quoted messages, 9 of them shortened; no Odia scam text was found published) - real messages from family phones would make it stronger.
- **Network traffic** catches noisy attacks (scans, floods, brute force). Slow or encrypted attacks (a botnet's occasional check-in, Heartbleed, web attacks over HTTPS) can hide in normal traffic; botnet "beaconing" was tested and left out because normal software checks in on a timer too.
- **Windows event rules** see what Windows records: with process-creation auditing (event 4688 with command lines) or Sysmon switched off, most rules have nothing to read. Not covered yet: DLL hijacking, DCSync, Kerberos ticket attacks, LDAP-only discovery. The admin-pipe rule can also fire for real IT admins' remote tools (it says so and is "medium" for account queries).
- **Malware:** files are only read, never run, so malware that hides until it runs (or arrives encrypted) can look clean; a clean result is not proof. The model covers Windows programs, Android apps, PDFs and Linux programs (also inside zips); scripts and Office files get the static checks only.
- **Insider Risk** was trained and tested on CERT r4.2, a *simulated* company: its insiders follow three fixed playbooks, so "35 of 35" means "known playbooks in new people", not real-world accuracy. The fairer number is 40 of 70 for patterns it never saw. The data has no file permissions, process starts or locations, so those checks come from other parts (log analysis, account takeover) or are missing; the negligent-insider check is a rule with no accuracy number. Splunk / Sentinel / Cortex XDR are not integrated: their exported logs can be uploaded.
- **Log analysis** finds attacks that leave many lines (scans, password bursts, web shells). A quiet port scan that leaves only 2–3 lines is not raised, and a per-line AI model was tested and rejected: it flagged 40–100% of normal logs from other systems.
- **Brand-new phishing links checked offline:** most 2026 phishing sits on free hosts (vercel.app, netlify.app, pages.dev …) under random names; only the live page check (fake-login model) can judge those. The link-structure model was trained on older data and is weak on 2026 links (AUC 0.58), so its alert levels were re-measured on 2026 links. Added 26 Oct: a **2026 link model** (`train_link_2026.py`, urlscan.io 2026 links + real 2026 sites incl. 4,404 real free-hosted ones; the platform name is hidden from it). On later days and unseen sites the whole offline engine catches **39.6%** of phishing links instead of 26.7% (AUC 0.758 → 0.777), with no extra false alarms on real websites or real free-hosted sites.

---

## Architecture

```
Browser ── React 19 + TypeScript + Vite (Tailwind, Recharts)
   │  HTTPS, cookies (HTTP-only JWT)
   ▼
FastAPI backend (Python 3.13)
   ├── subtopic router ── picks the detector for each input
   ├── detectors/ ─────── trained models (scikit-learn, ONNX on CPU) + explainable rules
   ├── services/ ──────── network intel (DNS, RDAP, WHOIS, SSL), safe page fetch, threat intel, MITRE, IOCs,
   │                      incidents, alerts (SMTP, Telegram), chat (Gemini), Gmail IMAP pipeline
   └── PostgreSQL (SQLAlchemy + Alembic migrations)
```

The safe page fetch never runs JavaScript, never sends forms, never connects to private or local addresses (it
checks every redirect hop) and reads at most 300 KB of a page.

---

## Run it (Windows)

**You need:** Python 3.13, Node.js 20+, PostgreSQL 16.

### 1. Database
In pgAdmin, create a database `cyberguard` and a user that owns it. For the tests, also create
`cyberguard_test`, owned by the same user.

### 2. Backend
```
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install --no-deps -r requirements-ocr.txt     # screenshot text reading (keep --no-deps)
copy .env.example .env
```
- Edit `backend\.env`. At least set `DATABASE_URL` and `JWT_SECRET`.
- Optional:
  - `GEMINI_API_KEY` for the chat assistant
  - `SMTP_*` / `IMAP_*` (Gmail App Password) for e-mail alerts and inbox scanning
  - `TELEGRAM_*` for Telegram alerts
  - `URLSCAN_API_KEY`, only to collect training data

Then:
```
alembic upgrade head
uvicorn app.main:app --port 8000
```
API documentation: http://localhost:8000/docs

### 3. Frontend (second terminal, project folder)
```
npm install
copy .env.example .env
npm run dev
```
Open http://localhost:5173 and sign up.

### 4. Model files
Trained model files (`*.joblib`, `*.onnx`) and datasets are **not in git**, because they are too big. Their test
results are (`*.metrics.json`, `deepfake_video.json`).
- **Retrain:** run the scripts in `backend/app/ml/training/`. Each prints its results; the data sources are listed
  in `backend/app/ml/training/data/README.md`.
- **The video model:** trained on Kaggle with `docs/colab/CyberGuard_Deepfake_Video_Kaggle.ipynb`.
- **Malware model:** `download_malware_data.py` (EMBER2024 test features + the authors' model; features only, no
  programs; SHA-256 checked), then `calibrate_malware_model.py` (alert levels + honest test).
- **Insider Risk:** `download_insider_data.py` (4.8 GB, MD5 checked), `prepare_insider_data.py` (about 40 min),
  `train_insider_risk.py` (about 1 min); real demo logs: `make_insider_demo.py`.
- **The voice models:** trained on Google Colab with `docs/colab/CyberGuard_Voice_Colab.ipynb` (4 files);
  speech-to-text: `python -m app.ml.training.fetch_whisper` (once). Real-world test of the trained model:
  `docs/colab/CyberGuard_Voice_InTheWild_Kaggle.ipynb` on Kaggle (In-the-Wild, scored exactly like the app), then
  `python -I app\ml\training\add_voice_itw_results.py <path>\itw_results.json` adds the results to `voice_ai.json`.
- **E-mail / SMS results:** `python -I app\ml\training\measure_text_models.py` (about 1 minute) measures both models on
  the 20% they never trained on, proves that, and saves the results for `show_auc.py`.
- **Hindi / Hinglish / Odia scam rules:** `python -I app\ml\training\test_indic_scams.py app\ml\training\data\indic`
  (download commands at the top of that file, about 130 MB) re-measures false alarms and catches.
- **If a model file is missing:** that check is reported as *unavailable*, never as a made-up verdict.

### 5. Checks
```
cd backend
python -m pytest -q          # 854 tests (uses cyberguard_test, never your real database)
python demo_check.py         # demo-day pre-flight: models, database, internet, chat backup, every demo input
python phase2_live_check.py  # live services + 30 real / phishing URLs (phishing sites are never contacted)
```

---

## Security and privacy
- **Accounts:** passwords hashed with bcrypt; sessions are HTTP-only cookies; reset tokens are stored hashed and
  can be used only once.
- **CORS:** restricted to the configured frontend address.
- **Secrets:** stay in `backend/.env` (never in git). Only public `VITE_*` values reach the browser.
- **Uploads:** allow-listed file types, size-limited, stored under random names and never executed.
- **Chat privacy:** private details are masked before reaching the AI; the AI's tools only see the user's own data.
- **Scam examples in tests and the demo** are invented or quoted from public warnings (sources in `test_indic_scams.py`); the scam web addresses used are unregistered names.

---

## Datasets and credits
- **Phishing pages and links:** urlscan.io, OpenPhish, PhishTank, Tranco top-1M, PhiUSIIL (UCI), DEPHIDES (MIT),
  Kaggle malicious URLs
- **Messages:** UCI SMS Spam Collection, UCI YouTube Spam Collection (CC BY 4.0), SMS phishing corpora; false-alarm
  test of the Hindi / Odia rules: Universal Dependencies UD_Hindi-HDTB, UD_Hindi-PUD, UD_Odia-ODTB, Google Hinglish-TOP
- **Logins:** RBA dataset (Wiefling et al., CC BY 4.0)
- **Malware:** EMBER2024 (Joyce, Raff et al., KDD 2025; github.com/FutureComputing4AI/EMBER2024, Apache-2.0) - its
  feature code (thrember) is included unchanged in `backend/app/detectors/ember_features.py` with its licence
- **Windows attack recordings:** OTRF Security-Datasets (Open Threat Research Forge, MIT); .evtx reading: python-evtx
  (Willi Ballenthin, Apache-2.0)
- **Insider threat:** CERT Insider Threat Test Dataset r4.2, Carnegie Mellon University Software Engineering Institute
  (CERT Division) and ExactData, doi:10.1184/R1/12841247 (KiltHub, CC BY 4.0) - synthetic data
- **Images and video:** Celeb-DF v2, OpenForensics, DFDC sample videos (Meta), real-vs-AI image sets
- **Face detector:** YuNet (OpenCV Zoo)
