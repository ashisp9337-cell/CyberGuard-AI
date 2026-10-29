# CyberGuard AI — ML Model Training & Dataset Audit

| | |
|---|---|
| **Audit date** | 21 October 2026 |
| **Repository** | `cyberguard-ai/` (local working copy; file timestamps up to 21 Oct 2026, 13:41 UTC) |
| **Scope** | 6 modules, 36 subtopics as listed in the audit brief, plus every trained artefact in `backend/app/ml/models/` |
| **Mode** | Read-only. No model, dataset or application file was modified, retrained, deleted or overwritten. This report is the only file written into the project. |
| **Paths** | All paths are relative to the repository root `cyberguard-ai/`. `file.py:120` means line 120. |

## How to read this report

Every factual statement carries one of these evidence tags:

| Tag | Meaning |
|---|---|
| **[R]** | **Recorded** by the project itself: a `*.metrics.json` / model card / saved check output in the repo. Copied as-is, **not** independently reproduced unless stated. |
| **[A]** | **Audit-measured**: computed during this audit on a read-only copy of the project's own files, using the project's pinned library versions (scikit-learn 1.5.2, numpy 2.1.1, joblib 1.4.2, onnxruntime). Inference only — no model was trained or re-fitted. |
| **[C]** | **Code observation** with file:line reference. |
| **[I]** | **Inference / unverified** — a reasoned conclusion that the available evidence does not prove. |

Status vocabulary (from the brief): **TRAINED & VERIFIED**, **TRAINED — NEEDS VALIDATION**, **WEAK MODEL**, **PARTIALLY TRAINED**, **UNTRAINED**, **RULE-BASED ONLY**, **PLACEHOLDER / NOT IMPLEMENTED**, **UNKNOWN**.

Rules applied when assigning a status:
* **TRAINED & VERIFIED** requires (a) the artefact loads, (b) its inference path is wired and exercised, (c) a held-out evaluation exists (recorded or reproduced), and (d) that evaluation uses real data that is not from the same templated/synthetic source as the training positives. Dataset provenance is reported separately and does not by itself change the training status.
* **WEAK MODEL** is only used when a recorded or audit-measured evaluation shows inadequate performance for the real task (e.g. near-random AUC on real attacker data, or recall in single digits at the operating threshold). Missing metrics alone never produce "weak".
* A subtopic that has no model of its own but re-uses another subtopic's model is rated on **its own detection logic**; the shared model is named in the row so its status can be looked up.

### Limitations of this audit
* `backend/app/ml/models/ai_image.onnx` (1,216,261,479 bytes) exceeds the file-transfer limit, so it was **not loaded**; its existence, size and model card (`ai_image.json`) were checked.
* `.env` files were **not opened** (secrets). `backend/uploads/` (user images) was not opened.
* The full `pytest` suite was **not run** (it needs the project's PostgreSQL database). Model files were loaded and individual detectors were executed in an isolated sandbox instead.
* Git history was not inspected. The DEPHIDES and Kaggle `malicious_phish.csv` datasets, the 9 GB `rba-dataset.csv`, Celeb-DF, DFDC, OpenForensics and the AI-image training images are **not present** in the repository, so those parts of the provenance chain could only be read from documentation.
* Small probes in this report (marked [A]) use synthetic, benign strings and files created for the audit. No phishing site, attack traffic or credential request was sent anywhere.

---

## A. Executive summary

### A.1 Subtopic status (36 subtopics audited)

| Status | Count | Subtopics |
|---|---:|---|
| TRAINED & VERIFIED | **4** | SMS phishing; Government impersonation; Bank/financial impersonation; Brand impersonation *(all verified on the SMS channel only)* |
| TRAINED — NEEDS VALIDATION | **7** | Social-media phishing; Fraudulent website; Malicious URL (M1); Senior-management impersonation; Homoglyph attacks; Malicious website classification; Phishing URL detection (M5) |
| WEAK MODEL | **14** | Email phishing; Deepfake image; Deepfake video; Teacher/university impersonation; Repeated failed logins; Password spraying; Unusual location; New device; Suspicious session; Account-takeover behaviour; Domain spoofing; Look-alike domains; Typosquatting; Suspicious URL structures |
| PARTIALLY TRAINED | **1** | Friend / family / trusted-contact impersonation |
| UNTRAINED | **0** | — |
| RULE-BASED ONLY | **5** | QR-code phishing; Brute-force login; Malware indicators; Data exfiltration; Insider threats |
| PLACEHOLDER / NOT IMPLEMENTED | **5** | Deepfake audio; Suspicious network traffic; API abuse; DDoS; Ransomware |
| UNKNOWN | **0** | — |

### A.2 Unique trained models (26 CyberGuard-trained artefacts + 1 third-party)

| Status | Count | Models |
|---|---:|---|
| TRAINED & VERIFIED | **6** | `phishing_sms`, `financial_impersonation`, `brand_impersonation`, `government_official_impersonation`, `domain_age`, `fake_login` |
| TRAINED — NEEDS VALIDATION | **5** | `phishing_social`, `phishing_pipeline` (fallback only), `senior_management_impersonation`, `impersonation_router` (routing only), `deepfake_image` |
| WEAK MODEL | **15** | `phishing_email`, `teacher_university_impersonation`, `cred_failed-logins`, `cred_password-spraying`, `cred_unusual-location`, `cred_unknown-device`, `cred_session-activity`, `cred_behavior-changes`, `ato_rba_model`, `url_domain_model`, `lookalike_domain`, `domain_spoofing`, `url_manipulation`, `deepfake_video`, `ai_image` |
| Third-party, pre-trained (not audited as a CyberGuard model) | 1 | `face_detection_yunet_2023mar.onnx` (OpenCV YuNet face detector) |

Subtopics and models are counted separately because many subtopics share a model (e.g. the six URL models feed every URL subtopic; the look-alike model serves look-alike, typosquatting and homoglyph).

### A.3 Dataset provenance (26 models)

| Provenance | Count | Models |
|---|---:|---|
| **Verified** — source documented in the repo **and** local files present and consistent with the training script | **12** | `phishing_pipeline` (UCI SMS Spam), 6 × `cred_*` (RBA subsets), `url_domain_model`, `lookalike_domain`, `domain_spoofing`, `domain_age`, `fake_login` |
| **Partially verified** — local trace exists but part of the data has no recorded origin, or the data is documented but not in the repo | **9** | `phishing_social`, 5 × impersonation models, `impersonation_router`, `ato_rba_model`, `deepfake_video` |
| **DATASET PROVENANCE UNVERIFIED** | **5** | `phishing_email`, `phishing_sms`, `url_manipulation` (data not in repo), `deepfake_image` and `ai_image` (no training notebook, no data, model card only) |

### A.4 Most important findings

1. **P0 — Unsupported inputs are reported as "safe".** [A] A voice/audio file sent to *Voice & Audio Analysis* (or an `.mp3/.wav` to *AI-Generated Multimedia*) returns **score 4, "safe", "No immediate action required"** (`analysis_service.py:97-99` → `deepfake.py:321-355`). An uploaded log file in *System & Application Log Analysis* (or a PDF in *Malware Detection*) is **ignored** and the empty text scores **0, "safe"** (`analysis_service.py:144-147`); the same pasted content scores **100, critical**. The README's promise that voice cloning is shown as *"unverified, never real"* is true only for the auto-detect path.
2. **P0 — Four Module 6 capabilities have no detection logic.** [A] A 14-port scan, a 40-request burst of failed API logins, a request flood, `vssadmin delete shadows` + mass file renaming, and 60-second beaconing **all score 0 / "safe"**. 10,000 requests/minute alone = 12 "safe"; a 50 GB transfer alone = 18 "safe". The router recognises these log formats, which makes the "safe" verdicts look authoritative.
3. **Email text model learned 2000-era corpus artefacts.** [A] Its strongest "legitimate" features are `enron`, `language`, `2002`, `linguistics`, `edu`, `vince`, `2001`; strongest "phishing" features include `2004`, `2005`, `viagra`, `spamassassin sightings`. 99.8 % of years mentioned in the training data are ≤ 2010. On the repo's own 10 modern sample e-mails the model alone reaches **AUC 0.50** and scores 3 of 4 genuine e-mails at 0.69–0.72. No metrics file exists for it. (The e-mail *pipeline* compensates with sender authentication, URL and attachment checks.)
4. **Five of seven login-risk models were trained on simulated attackers and do not separate real attackers.** [R] On real attacker logins vs normal logins: unknown-device ROC-AUC **0.41**, behaviour-change **0.44**, session-activity **0.48**, RBA account-side **0.41** (all below random), unusual-location **0.63**. [A] The password-spraying model gives **0.0006** to an obvious 10-account spray. Module 4 verdicts are carried by the attack-chain rules.
5. **URL models are strong on synthetic / in-distribution data and weak on independent real data.** [R] Look-alike: AUC 0.993 on dnstwist-generated look-alikes but **0.507** on real PhiUSIIL phishing domains near a protected brand. Domain spoofing: AUC 0.87 held-out, **0.67 with 16.5 % false alarms** on an independent set. URL manipulation: after re-calibration on 2026 data it catches **0.12 %** of 2026 phishing links at the alert level (its statistical part is effectively off; explicit tricks are forced by rules). Domain-name model: AUC 0.78, **26.6 %** caught at 1 % false alarms.
6. **Deepfake models do not generalise across datasets.** [R] Video: AUC 0.996 on Celeb-DF but **0.72 on DFDC (2.8 % caught at alert)**. AI-image: AUC 0.98 in-distribution but **0.71–0.74 leave-one-source-out**. The image training notebooks referenced by the code (`docs/colab/CyberGuard_AI_Image_Colab.ipynb`, `CyberGuard_Deepfake_Image_Colab.ipynb`) are **not in the repository**.
7. **Models cannot be reproduced or linked to training runs.** [C] All `*.joblib`/`*.onnx` files and most datasets are git-ignored (`.gitignore:19,24-41`). No manifest or hashes exist. Model tests `skipif` the model file is missing (e.g. `tests/test_social_model.py:10`), so a fresh clone silently runs **rules-only** with passing tests. [A] For the 7 TF-IDF pipelines that have a metrics file, the artefact file is 2–6 minutes *newer* than the `trained_at` written by the same script (which saves the model *before* stamping `trained_at`), and the pipelines carry no run id; `phishing_social` and `fake_login` were re-fitted on all data after evaluation, so the recorded metrics belong to a different model object than the one deployed.
8. **Impersonation / social training data is heavily templated and label-confounded.** [A] In every base CSV the label equals the source: all "legitimate" rows are synthetic. Senior-management scams: 1,400 rows → **137** distinct templates; social-media curated scams: 1,400 → **28**. The October retraining (`retrain_impersonation_real.py`) added real SMS, which makes bank/brand/government credible on SMS — but management and teacher were validated on only **71** and **49** real scams (teacher recall **51 %**).

### A.5 Top five actions
1. **P0** Return an explicit *unsupported / unverified* result (never "safe") when the selected detector cannot read the input: audio files, uploaded log/PDF files in Module 6, file-only requests in Modules 3–4. Correct the README sentence on voice cloning.
2. **P0** Mark *Network traffic*, *API abuse*, *DDoS* and *Ransomware* as "not available" in the UI and API until real detectors exist; then implement minimal, tested rules (port-scan fan-out, per-IP request rate from parsed access logs, shadow-copy deletion / mass-rename, periodic beaconing).
3. **P1** Replace the e-mail text model with one trained on a modern, header-preserving corpus with a time-based split; save metrics; evaluate on a held-out modern set (including Indian banking/education/government mail).
4. **P1** Stop the simulated-label login models from raising scores to 71–100 on their own; keep them as explanatory signals until they beat random on real attacker logins; publish the real-label numbers in the README.
5. **P1** Add a model manifest (SHA-256, training commit, dataset hashes, metrics, thresholds) and make CI fail — not skip — when a required model is absent; make `MODELS_DIR` absolute.

---

## Phase 1 — Repository map

### Frameworks and model families [C][A]
| Family | Framework | Artefacts |
|---|---|---|
| TF-IDF + Logistic Regression text classifiers | scikit-learn 1.5.2 `Pipeline` | `phishing_email`, `phishing_sms`, `phishing_pipeline`, `phishing_social`, 5 impersonation models, `impersonation_router` |
| Gradient-boosted trees on engineered features | scikit-learn `HistGradientBoostingClassifier` | 6 × `cred_*`, `lookalike_domain`, `domain_spoofing`, `url_manipulation`, `domain_age`, `fake_login`, `url_domain_model` (HGB + char-n-gram LR average) |
| Frequency-table risk model | custom (`app/detectors/rba_risk.py`) | `ato_rba_model` |
| CNN / vision-transformer classifiers | PyTorch → ONNX, run with onnxruntime | `deepfake_image` (EfficientNet-B0), `deepfake_video` (EfficientNet-B0), `ai_image` (CLIP ViT-L/14 + linear layer) |
| Face detector (third-party) | OpenCV YuNet ONNX | `face_detection_yunet_2023mar.onnx` |

All 23 `.joblib` files load with scikit-learn 1.5.2 [A]. With a newer scikit-learn (1.9.1) the 12 HistGradientBoosting bundles **fail to load** (`ModuleNotFoundError: _loss`) and the TF-IDF pipelines load with `InconsistentVersionWarning` — the version pin in `backend/requirements.txt` is load-bearing [A].

### Training scripts (`backend/app/ml/training/`)
`train_phishing.py`, `train_sms_phishing.py`, `train_social_media_phishing.py`, `train_brand_impersonation.py`, `train_financial_impersonation.py`, `train_government_impersonation.py`, `train_senior_management_impersonation.py`, `train_teacher_university_impersonation.py`, `retrain_impersonation_real.py` (produced the current five impersonation artefacts), `train_impersonation_router.py`, `train_credential_subtopics.py`, `train_ato_login.py`, `train_url_domain.py`, `train_lookalike_domain.py`, `train_domain_spoofing.py`, `train_url_manipulation.py` (+ `calibrate_url_manipulation.py`), `train_domain_age.py`, `train_fake_login.py`; data helpers `extract_rba_subsets.py`, `explore_rba.py`, `prepare_brand_dataset.py`, `collect_urlscan.py`, `collect_domain_facts.py`, `sample_dom.py`. Deepfake video: `docs/colab/build_deepfake_video_kaggle.py` → `docs/colab/CyberGuard_Deepfake_Video_Kaggle.ipynb`. **No training code for `deepfake_image` or `ai_image` is present.**

### Inference entry points [C]
* `POST /api/analysis/scan` (`backend/app/api/routes/analysis.py:68-153`) → `subtopic_router.route` (when `subtopicId == "auto"`) or `analysis_service.run_scan` → `scan_store.save_result` (Scan + indicators + `ThreatEvent` when not safe, IOC memory) → `notifier.alert_for_scan` when score ≥ 51.
* `POST /api/email/analyze` and the e-mail watcher → `email_pipeline.analyze_email`.
* Chat / Telegram (`services/chat_scan.py:20,87`) → `subtopic_router.route`.
* Automation: `automation/login_monitor.py:89`, `automation/windows_logons.py:125` → `account_takeover.analyze_event` **without** a subtopic id (so the RBA model, not the subtopic models, is used); `automation/downloads_watcher.py:43` → attachment scanner.
* Frontend calls the real backend; the browser-only mock (`src/services/api/mockAnalysisFallback.ts`) is only used when `VITE_USE_MOCK_DATA=true` **and** not a production build (`src/services/api/config.ts:17`). `.env.example:15` sets it to `false`.

### Evaluation records found
24 JSON evaluation files in `backend/app/ml/models/` (20 `*.metrics.json`, 3 deepfake/AI-image model cards, 1 URL-manipulation re-calibration file); saved live-check outputs `backend/demo_check.txt`, `backend/phase2_live_check.txt`, `backend/social_check.txt`, `backend/fake_login_check.txt`; 32 ML-related test files with 305 test functions (13 of those files load real model files). **No metrics exist for `phishing_email`, `phishing_sms` or `phishing_pipeline`.**

---

## B. Master audit table

One row per subtopic, split by module for readability. Abbreviations: **TF-IDF+LR** = TF-IDF features + scikit-learn LogisticRegression; **HGB** = HistGradientBoostingClassifier; **FA** = false-alarm rate on genuine items; "@alert" = at the model's alert threshold (chosen for ≈1 % FA on calibration data unless stated). Paths under `backend/app/ml/models/` are written `models/…`; under `backend/app/ml/training/` as `training/…`.

### Module 1 — AI-Powered Phishing Detection

Routing [C]: the auto-detect router (`backend/app/services/subtopic_router.py:250-297`) **does** decide automatically between e-mail (RFC-822 header block or `.eml/.msg`), SMS (default for short text), social media (platform link, `@handle` + platform name, or a `platform` field), QR (any image file), website (bare domain) and URL (path or query). Users can also pick a subtopic manually. Gaps: an e-mail pasted without headers goes to the SMS model, a social DM without platform cues goes to the SMS model, and a screenshot of a message is routed to the QR decoder (returns *unverified*).

| Module | Subtopic | Implementation status | Detection approach | Model name | Algorithm / architecture | Training status | Artifact path | Training script | Dataset | Dataset path | Dataset size | Class distribution | Evaluation metrics | Strength assessment | Integration status | Main problems | Recommended next action |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M1 Phishing | Email phishing | Implemented | Fusion pipeline: sender auth (SPF/DKIM/DMARC) rules + ML text model + 6 impersonation detectors + URL engine + QR + attachment scanner + ATO rules (`email_pipeline/orchestrator.py:167-250`, `fusion.py:56-194`) | `phishing_email` (text component) | TF-IDF word 1–2-gram, English stop-words, 648,026 features + LR (C=3, balanced) [A] | **WEAK MODEL** (text component) | `models/phishing_email.joblib` | `training/train_phishing.py --data …/phishing_email_real.tsv --pos-label phishing` (per docstring; no run record) | **DATASET PROVENANCE UNVERIFIED** — README: "real phishing / legitimate emails", no source | `training/data/phishing_email_real.tsv` | 18,634 records; 1,119 normalised duplicates; 533 rows are the literal text "empty" [A] | 7,312 phishing / 11,322 legitimate (39.2 % positive) [A] | No metrics file. [A] reproduced 80/20 split (seed 42): acc 0.972, P 0.944, R 0.988, F1 0.966, ROC-AUC 0.996, PR-AUC 0.993, FPR 3.75 %, FNR 1.23 % (n=3,727; 288 test texts also in train). [A] 10 repo sample e-mails: AUC 0.50 | Strong in-distribution; learned corpus artefacts of ~2000-era mail, poor transfer to modern mail [A] | Verified: `orchestrator.py:217` → `phishing.py:385-459` (blend 0.6 model / 0.4 rules, `phishing.py:409`); trust rules in `fusion.py:71-86` discount text evidence for authenticated senders | Top features are artefacts (`enron`, `linguistics`, `2001`, `vince` → legit; `2004`, `2005`, `spamassassin sightings` → phish); 99.8 % of mentioned years ≤ 2010; 65.7 % of rows pre-tokenised lower-case (`re : 6 . 1100 ,`) vs raw text at inference; no headers in training text | Retrain on a modern header-preserving corpus with a time-based split; save metrics; build a held-out modern Indian e-mail test set |
| M1 Phishing | SMS / message phishing | Implemented | ML + rules: scam-pattern floors (`phishing.py:151-275`), keyword rules, embedded-link scoring via URL engine, OTP-notice cap | `phishing_sms` | TF-IDF word 1–2-gram, 92,306 features + LR (C=3, balanced) [A] | **TRAINED & VERIFIED** (in-distribution) | `models/phishing_sms.joblib` | `training/train_sms_phishing.py` (trap-set gate) | **DATASET PROVENANCE UNVERIFIED** — README: "SMS phishing corpus"; mixture: v2 contains 3,940 genuine rows that are not in v1, many of them templated synthetic ("Dear Amit, your EMI of Rs 3771 was auto-debited…") [A] | `training/data/phishing_sms_clean_v2.tsv` (v1 `phishing_sms.tsv` superseded) | 77,891 rows; 667 duplicates; 7 texts with conflicting labels [A] | 22,748 phishing / 55,143 legitimate (29.2 %) [A] | No metrics file. [A] reproduced split: acc 0.946, P 0.866, R 0.963, F1 0.912, ROC-AUC 0.988, PR-AUC 0.966, FPR 6.15 %, FNR 3.69 % (n=15,579; 200 overlap) | Good recall; model-alone FA ≈6 % at 0.5 is high for consumer SMS (rules then adjust) | Verified: `analysis_service.py:94` → `phishing.py:400-416` | Source not recorded; trap-set gate texts resemble the synthetic rows added to training (not an independent test); no saved metrics | Record provenance; evaluate on fresh 2026 Indian SMS (real scams + real transactional); pick threshold for ≤1 % FA |
| M1 Phishing | Social-media phishing | Implemented | ML + rules; promotion cap holds model-only posts at 50 (`phishing.py:437-443`) | `phishing_social` | TF-IDF word 1–2 + char_wb 3–5 (77,657 features) + LR (C=2), source-weighted [A] | **TRAINED — NEEDS VALIDATION** | `models/phishing_social.joblib` | `training/train_social_media_phishing.py` | UCI YouTube Spam Collection (URL + CC BY 4.0 recorded) + 8,000-row sample of the SMS set + hand-written curated DMs (weight 0.15) — partially verified | `training/data/youtube+spam+collection.zip`, `phishing_sms_clean_v2.tsv`, `social_media_phishing.csv` | YouTube 1,752 (after cleaning), SMS 8,000, curated 2,785 [R] | YouTube 834 spam; SMS 4,000/4,000; curated 1,400/1,385 [R] | [R] unseen YouTube video (n=318): F1 0.915, P 1.0, R 0.843, AUC 0.991; SMS hold-out (n=1,600): F1 0.933, AUC 0.978; trap set 0/12 FA, 8/8 caught. [R] live check: 1/20 normal posts flagged, 5/5 scams. [A] deployed artefact was re-fitted on all data incl. those tests (scores 1.00 on the "unseen" video) | No real Instagram/Facebook/X/LinkedIn DM data; YouTube comments are from 2015 | Verified (same path as SMS, `subtopic_id="social-media-analysis"`) | Domain mismatch; curated scams = 28 templates for 1,400 rows [A]; recorded metrics are for the pre-refit model | Collect labelled real social DMs/comments; keep a final test set untouched by the refit |
| M1 Phishing | QR-code phishing | Implemented | Rules: QR decode (zxing-cpp / OpenCV, multi-variant), payload classification (URL / UPI / Wi-Fi / SMS …), UPI field checks; URL payloads go through the URL engine and **every** trained URL model (`qr_analyzer.py:1-11`, `malicious_url.py:521`) | none QR-specific | — | **RULE-BASED ONLY** (URL payloads inherit the URL models' status) | — | — | — | — | — | — | [R] demo P5/P6 caught (n=2); `tests/test_qr_phishing.py` (10 tests). No labelled QR evaluation set | Depends on URL engine; unreadable QR → "unverified", never "safe" (`qr_analyzer.py:104-109`) [C] | Verified (`analysis_service.py:54-55`) | No QR evaluation set; screenshots of messages land here and are "unverified" | Build ≥200 labelled QR images (UPI collect requests, Wi-Fi, URL) and measure |
| M1 Phishing | Fraudulent website | Implemented | URL engine: structural rules + domain-name model + live DNS/WHOIS/SSL/RDAP + registry model + read-only page fetch with fake-login model + all three URL subtopic models; strongest model sets a floor (`malicious_url.py:309-429`) | `url_domain_model`, `domain_age`, `fake_login`, `lookalike_domain`, `domain_spoofing`, `url_manipulation` | HGB / LR ensembles (see Module 5) | **TRAINED — NEEDS VALIDATION** (composite) | see Module 5 | see Module 5 | see Section C | see Section C | see Module 5 | see Module 5 | Component metrics only [R]. End-to-end: [R] Phase-2 live check n=5+5: 4/5 phishing caught, 5/5 genuine correct | Mix of strong (`fake_login`, `domain_age`) and weak (`url_domain_model`, `lookalike`, `url_manipulation`) parts | Verified; live checks need network, offline = models + rules only | No end-to-end labelled evaluation; UI promises "upload screenshot" (`src/data/modules.ts:78`) but no screenshot path exists | Assemble ≥1,000 labelled URLs (fresh phishing feeds + Tranco + Indian sites), time-split, evaluate whole engine at fixed FA |
| M1 Phishing | Malicious / deceptive URL | Implemented | Same URL engine as above | same six models | — | **TRAINED — NEEDS VALIDATION** (composite) | see Module 5 | see Module 5 | see Section C | see Section C | — | — | [R] Phase-2 live check malicious-url: 4/5 phishing, 5/5 genuine | As above | Verified | As above | As above |

### Module 2 — Deepfake Detection

| Module | Subtopic | Implementation status | Detection approach | Model name | Algorithm / architecture | Training status | Artifact path | Training script | Dataset | Dataset path | Dataset size | Class distribution | Evaluation metrics | Strength assessment | Integration status | Main problems | Recommended next action |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M2 Deepfake | Deepfake image | Implemented | Provenance rules (C2PA / IPTC / generator metadata) + AI-image model + face-swap model on YuNet face crops; strongest decides (`deepfake.py:58-169`). Input: `.png/.jpg/.jpeg` (`.webp` listed in UI but rejected by upload allow-list, `routes/analysis.py:19`) | `deepfake_image`, `ai_image` (+ third-party YuNet) | EfficientNet-B0, 224 px, ImageNet normalisation, face margin 0.25 [R card]; CLIP ViT-L/14 + linear layer (UnivFD), up to 3 crops [R card] | **WEAK MODEL** (cross-source generalisation) | `models/deepfake_image.onnx` (16,009,989 B), `models/ai_image.onnx` (1,216,261,479 B, not loaded by audit), `models/face_detection_yunet_2023mar.onnx` | **None in repo** — `ai_image.py:17` and `deepfake_image.py:8` reference Colab notebooks that are not present | **DATASET PROVENANCE UNVERIFIED** — cards name "OpenForensics (Kaggle manjilkarki/deepfake-and-real-images)" and "modern-generators, shutterstock-pairs, stylegan-faces" | not in repo | Face: 140,002 training images; AI-image: 43,456 [R card] | not recorded | [R] face model test (n=5,453): AUC 0.948, 35.6 % caught at 0.96 % FA. [R] AI-image test (n=8,000): AUC 0.980, 79.5 % @1.3 % FA; modern generators AUC 0.928 (62 % @3.6 %); **leave-one-source-out AUC 0.715 / 0.735 / 0.718** with 22 % / 51 % / 1 % caught at 5.2 % / 21.1 % / 0.4 % FA | Good in-distribution, weak on unseen generators (the real-world case) | Verified (`deepfake.py:58-169`); face thresholds are 0.9999999957 / 0.9999977 (saturated logits) [R] | Training code and data absent; LOSO weakness; if `ai_image.onnx` is missing (git-ignored, 1.2 GB) a face-less image is judged by the face model on the whole picture and can be returned "safe" [A] | Commit the two notebooks; cross-dataset test on unseen generators and WhatsApp-recompressed photos; re-calibrate |
| M2 Deepfake | Deepfake video | Implemented | Provenance rules + face-swap video model on 16 sampled frames (largest face, mean score); < 3 faces → "no verdict" (`deepfake.py:200-285`) | `deepfake_video` | EfficientNet-B0 per face crop, mean aggregation [R card] | **WEAK MODEL** (cross-dataset) | `models/deepfake_video.onnx` (+ `deepfake_video.json`) | `docs/colab/build_deepfake_video_kaggle.py` → `docs/colab/CyberGuard_Deepfake_Video_Kaggle.ipynb` (seed 42, split by person) | Celeb-DF v2 (official test list held out) + DFDC 400-video sample — documented in notebook, data not in repo (private Drive link) — partially verified | not in repo | 55,605 face crops [R] | 19,221 real / 36,384 fake [R] | [R] Celeb-DF half B (n=259): AUC 0.996, 86.8 % @0 % FA; JPEG-35: AUC 0.991. **DFDC (n=400): AUC 0.721, 2.8 % caught @alert, 7.4 % @verify** | Strong on Celeb-DF, weak elsewhere; face-swap only (not fully AI-generated video, not lip-sync) | Verified; `.m4v` is routed as video (`subtopic_router.py:153`) but `deepfake.py:322` treats it as an image | Cross-dataset generalisation; [I] Celeb-DF is distributed under a research-use agreement — check before any commercial use | Add FaceForensics++/DFDC to training; evaluate on Indian social-media video; document licence |
| M2 Deepfake | Deepfake audio | **Not implemented** | None. Auto-detect refuses (`subtopic_router.py:99, 321-323`), but the manual subtopic *Voice & Audio Analysis* (`src/data/modules.ts:92`) and *AI-Generated Multimedia* with `.mp3/.wav` (`modules.ts:93`) are accepted by the upload allow-list (`routes/analysis.py:19`) and sent down the **image** path | none | — | **PLACEHOLDER / NOT IMPLEMENTED** | — | — | — | — | — | — | [A] 1-second WAV via manual path → score 4, **"safe"**, recommendations "No immediate action required" | n/a | **Broken (misleading verdict)** | Returns "safe" for any audio; contradicts README line 77 | P0: return "unsupported/unverified"; later train a voice-clone detector (e.g. ASVspoof + in-the-wild data) with EER reporting |

### Module 3 — Digital Impersonation Detection

All five topic models below were produced by `training/retrain_impersonation_real.py` (Oct 15–17): topic CSV + real SMS (and, for management/teacher, the first ≤3,000 characters of real e-mails), label cleaning by 5-fold "confident learning", 20 % of real messages held out by text hash. Each detector blends model and rules (bank/brand 0.6/0.4; government/management/teacher 0.65/0.35) and applies scam-pattern floors. [C]

| Module | Subtopic | Implementation status | Detection approach | Model name | Algorithm / architecture | Training status | Artifact path | Training script | Dataset | Dataset path | Dataset size | Class distribution | Evaluation metrics | Strength assessment | Integration status | Main problems | Recommended next action |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M3 Impersonation | Government official | Implemented | ML + rules: government claim vs sender-domain pattern, "digital arrest" scam script with floors/caps, shared phishing rules (`government_impersonation.py:182-256`) | `government_official_impersonation` | TF-IDF word 1–2 + char_wb 3–5 + LR (C=2, balanced) [A] | **TRAINED & VERIFIED** (SMS channel) | `models/government_official_impersonation.joblib` | `training/retrain_impersonation_real.py` (earlier: `train_government_impersonation.py`) | Topic CSV + real SMS — partially verified | `training/data/government_official_impersonation.csv` + `phishing_sms_clean_v2.tsv` | CSV 2,392 (109 dup) [A]; training 6,025 [R] | CSV: 942 phishing (750 templated "phish" = 120 templates, 192 real) / 1,450 legitimate (100 % synthetic) [A]; training 1,970 / 4,055 [R] | [R] held-out real SMS — model: 96.5 % caught (n=283), FA 7.9 % on government-related genuine (n=164), 1.9 % everyday (n=3,000). Detector (score ≥51): 87.3 % caught, FA 1.2 % / 0.5 % | Good on SMS; untested on e-mail / WhatsApp / call transcripts | Verified (`analysis_service.py:125-128`) | Base CSV label = source; 6 hard on-topic genuine messages removed from the test set (`retrain_impersonation_real.py:258-260`); engine label hard-codes "(192 real + synthetic)" (`government_impersonation.py:254`) | Add real government notices (Income Tax, EPFO, UIDAI) as genuine; add an e-mail test set |
| M3 Impersonation | Senior management / executive | Implemented | ML + BEC rules (secret payment, gift cards, "in a meeting") | `senior_management_impersonation` | same as above | **TRAINED — NEEDS VALIDATION** | `models/senior_management_impersonation.joblib` | `training/retrain_impersonation_real.py` | Topic CSV + real SMS + real e-mail — partially verified | `training/data/senior_management_impersonation.csv` + SMS + `phishing_email_real.tsv` | CSV 3,000 (126 dup) [A]; training 5,692 [R] | CSV: 1,400 templated scams (**137 templates**) / 1,600 synthetic genuine [A]; training 1,679 / 4,013 [R] | [R] real test: **71 scams**, 84.5 % caught; FA 0 % on 108 on-topic genuine, 0.1 % everyday | Plausible but on a small real test; scams in training are mostly templates | Verified | Real-scam test too small; e-mail loader truncates at the first newline (`retrain_impersonation_real.py:141-142`, `quoting=3`; 28 % of e-mails are multi-line [A]) | Collect ≥300 real BEC samples; fix the e-mail loader; re-evaluate |
| M3 Impersonation | Teacher / educational institution | Implemented | ML + academic scam rules (gift-card favour, offer-letter fee, OTP request, scholarship hold) | `teacher_university_impersonation` | same as above | **WEAK MODEL** | `models/teacher_university_impersonation.joblib` | `training/retrain_impersonation_real.py` | Topic CSV + real SMS + real e-mail — partially verified | `training/data/teacher_university_impersonation.csv` + SMS + e-mail | CSV 3,000 (175 dup) [A]; training 8,404 [R] | CSV: 1,400 templated scams (192 templates) / 1,600 synthetic genuine [A]; training 1,592 / 6,812 [R] | [R] real test: **49 scams, 51.0 % caught** (model and detector); FA 0.46 % on 437 on-topic genuine | Recall ≈ coin-flip on real scams | Verified | Very little real data (README admits it); the rules added on 19–21 Oct are not covered by the recorded metrics | Collect real Indian college scam messages (WhatsApp/e-mail); report rules+model recall on them |
| M3 Impersonation | Bank / financial institution | Implemented | ML + rules (sender domain vs institution directory `financial_institutions.json`, KYC/billing patterns) | `financial_impersonation` | same as above | **TRAINED & VERIFIED** (SMS channel) | `models/financial_impersonation.joblib` | `training/retrain_impersonation_real.py` | Topic CSV (real scam SMS + synthetic genuine) + real SMS — partially verified | `training/data/financial_institution_impersonation.csv` + SMS | CSV 5,097 (6 dup) [A]; training 13,717 [R] | CSV: 2,497 real scams / 2,600 synthetic genuine (308 templates) [A]; training 5,543 / 8,174 [R] | [R] model: 98.2 % caught (n=1,351), **FA 12.5 %** on bank-related genuine (n=417), 3.6 % everyday. Detector: 90.8 % caught, FA 3.1 % / 1.2 % | Credible on SMS; model alone over-flags real bank SMS, rules pull it back | Verified | 30 hard genuine removed from test; SMS-only evidence | Add real bank e-mails / app notifications as genuine; e-mail test set |
| M3 Impersonation | Organisation / brand | Implemented | ML on **brand-masked** text (same masking at training and inference, `brand_impersonation.py:135`) + sender/brand-domain rules | `brand_impersonation` | same as above | **TRAINED & VERIFIED** (SMS channel) | `models/brand_impersonation.joblib` | `training/retrain_impersonation_real.py` | Topic CSV + real SMS — partially verified | `training/data/brand_impersonation.csv` + SMS | CSV 3,989 (101 dup) [A]; training 10,834 [R] | CSV: 2,103 real scams / 1,886 genuine (286 real + 1,600 synthetic) [A]; training 4,565 / 6,269 [R] | [R] model: 97.9 % caught (n=991), FA 12.1 % brand-related genuine (n=406), 3.0 % everyday. Detector: 88.7 % caught, FA 3.7 % / 0.8 % | Credible on SMS | Verified | 16 hard genuine removed from test; SMS-only | As for bank |
| M3 Impersonation | Friend / family / trusted contact | Implemented | Rules: user's saved-contact baseline (name/e-mail/look-alike), "Hi Mum / new number" scam-script stages, plus the **SMS phishing model** (score = max of rules, script, 70 × SMS probability) (`known_contact_impersonation.py:216-225, 255-262`) | none dedicated (re-uses `phishing_sms`) | — | **PARTIALLY TRAINED** | (`models/phishing_sms.joblib`) | — | `known_contact_scams_real.tsv` (23 real messages, each with a source link) used for tests and router only | `training/data/known_contact_scams_real.tsv` | 23 | 23 scams / 0 genuine | No metrics. [R] router "contact" accuracy 0.939 (n=379, routing only); `tests/test_known_contact_script.py` | Unknown | Verified (needs DB session for contacts) | No labelled evaluation; generic SMS model is the only ML | Label ≥300 real family/friend scams + genuine family chats; measure |

The **impersonation router** (`models/impersonation_router.joblib`, 7-class TF-IDF+LR) only chooses the subtopic; it never scores risk (`subtopic_router.py:359-404, 470-474`). [R] rules+model routing: 94.4 % right, 4.0 % "generic", 1.6 % wrong (n=2,395) — but the management/teacher test parts are templated ("no real-only part").

### Module 4 — Credential Theft & Account Takeover

Data: subsets of the RBA login dataset (Wiefling et al., CC BY 4.0) made by `training/extract_rba_subsets.py`. Split 70/10/20 **by account or IP**, thresholds from the calibration part (1 % / 5 % FA), some accounts trained with country/ASN/UA blanked to mimic pasted logs (`train_credential_subtopics.py:76-115`) [C]. Four of the six labels are **simulated attackers** (a real attacker's IP/UA/time pasted onto a real account) (`train_credential_subtopics.py:13-22, 160-176`). The subtopic model can raise the final score to 71–100 on its own (`account_takeover.py:646-651`).

| Module | Subtopic | Implementation status | Detection approach | Model name | Algorithm / architecture | Training status | Artifact path | Training script | Dataset | Dataset path | Dataset size | Class distribution | Evaluation metrics | Strength assessment | Integration status | Main problems | Recommended next action |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M4 Credential | Repeated failed login attempts | Implemented | Log parser + rules (≥5 failures, success-after-failures, attack chains) + subtopic model | `cred_failed-logins` | HGB, 27 features, balanced [A] | **WEAK MODEL** | `models/cred_failed-logins.joblib` | `training/train_credential_subtopics.py` | RBA accounts subset — verified | `training/data/rba_accounts_subset.csv.gz` | 1,725,254 logins, 431,508 accounts, 2020-02-03 → 2021-02-28 [A]; 600,000 training rows [R] | 145,778 attack-IP rows (8.45 %), 141 account-takeover rows [A]; training 50,525 positives [R] | [R] test (n=347,380): ROC-AUC 0.877, **PR-AUC 0.399, 13.6 % caught @0.98 % FA**, 32.3 % @4.9 % FA. [A] probe: 25 failures then success → p=0.897 (rules alone already give 100) | Low recall at the operating point; label is "IP is on the attacker list", not "this is brute force" | Verified (`account_takeover.py:466-488, 628-652`) | Proxy label; 2020–21 data | Keep as secondary evidence; evaluate on real SSH/Windows 4625 logs |
| M4 Credential | Password spraying | Implemented | Rule: ≥5 distinct failed users from one source (weight 40, chain floor 75) + IP-side model | `cred_password-spraying` | HGB, 24 features [A] | **WEAK MODEL** | `models/cred_password-spraying.joblib` | same | RBA IP subset — verified | `training/data/rba_ip_subset.csv.gz` | 2,957,596 logins, 351,308 IPs [A]; 600,000 training rows [R] | 322,872 attack-IP rows (10.92 %) [A]; 125,129 training positives [R] | [R] test: ROC-AUC 0.773, PR-AUC 0.476, **8.7 % caught @1.2 % FA**. [A] probe: 10 accounts failed from one IP in 10 s → **p=0.0006 (low)**; rule fired → 75 | Model does not recognise a textbook spray | Verified | [R] RBA rule check: attack share does **not** rise with accounts-per-IP thresholds, i.e. the data contain no learnable spraying pattern | Use rules + labelled spraying logs (honeypot/AD lab); demote model |
| M4 Credential | Brute-force login attempts | Implemented | Rules only: ≥15 failures or ≥10 within 10 min on one account (`account_takeover.py:534-554`), chain "Brute force succeeded" (floor 90); shares the failed-logins model when the user picks *failed-logins* | none dedicated | — | **RULE-BASED ONLY** | — | — | — | — | — | — | [R] demo C1 = 100; [R] RBA rule check shows attack share does **not** rise with per-account failure thresholds (≥10/h: 3.5 %) → thresholds are not data-tuned | Works on obvious bursts | Verified | No brute-force subtopic id in UI (merged into failed-logins); thresholds unvalidated | Tune on labelled brute-force logs; add per-IP + per-account velocity |
| M4 Credential | Logins from unusual locations | Implemented | Rules (new country after ≥3 logins = 51, impossible travel = 51) + subtopic model + RBA model fallback | `cred_unusual-location` (+ `ato_rba_model`) | HGB, 18 features [A] | **WEAK MODEL** | `models/cred_unusual-location.joblib` | same | RBA accounts subset — verified | as above | as above; 600,000 training rows [R] | **simulated** positives 299,717 [R] | [R] simulated test ROC-AUC 0.984 (76.3 % @1 % FA). **Real attacker logins vs normal (n=53,774): ROC-AUC 0.625, 5.7 % caught @1 % FA** | Separates simulated, not real, attackers | Verified | Simulated label; RBA README admits same-country attackers are hard | Validate on real takeover cases; until then cap model-only effect at "verify" |
| M4 Credential | Login from new / unfamiliar device | Implemented | Rules (new-device keywords) + subtopic model | `cred_unknown-device` | HGB, 22 features [A] | **WEAK MODEL** | `models/cred_unknown-device.joblib` | same | as above | as above | 600,000 [R] | simulated positives 300,144 [R] | [R] simulated ROC-AUC 0.914. **Real attackers: ROC-AUC 0.411 (below random), 1.7 % caught @1 % FA** | Worse than random on real attackers | Verified | Simulated label | as above |
| M4 Credential | Suspicious session activity | Implemented | Rules (mass download, privilege escalation, anonymising network) + subtopic model | `cred_session-activity` | HGB, 17 features [A] | **WEAK MODEL** | `models/cred_session-activity.joblib` | same | as above | as above | 600,000 [R] | simulated positives 480,504 (80 %) [R] | [R] simulated ROC-AUC 0.998 (learns the injected 2–110 min gap). **Real attackers: ROC-AUC 0.476**, 0.7 % caught. Verify threshold 0.0116 | Artefact of the simulation | Verified (often not eligible → RBA fallback [A]) | Label construction leaks into `minutes_since_prev` | Re-label from real parallel-session data or drop the model |
| M4 Credential | Account-takeover behaviour | Implemented | Attack-chain rules (anomalous login + MFA/password/recovery change, forwarding rule, token, mass download; floors 80–90) + `cred_behavior-changes` + `ato_rba_model` (fallback and automation) + e-mail ATO-notification rules | `cred_behavior-changes`, `ato_rba_model` | HGB, 13 features; frequency-table RBA risk model [A] | **WEAK MODEL** (models); chain rules carry detection | `models/cred_behavior-changes.joblib`, `models/ato_rba_model.joblib` | `train_credential_subtopics.py`; `train_ato_login.py` | RBA subsets (verified); full `rba-dataset.csv` 9 GB not in repo (documented Kaggle source) | as above | RBA model: 25,015,411 training logins, 3,741,763 accounts [R] | behaviour: simulated 300,144 positives [R]; RBA: 141 ATO rows, **0 in test period** [R] | [R] behaviour-change real ROC-AUC **0.437**. RBA account-side: simulated ROC-AUC 0.944, **real attack-IP logins 0.412**; attacker-side ROC-AUC 0.854, recall 12 % @1 % FA | Models weak on real labels; rules do the work | Verified; automation calls without subtopic → RBA model live (`automation/login_monitor.py:89`) | ATO rows all inside training period (no clean test) | Build a small real ATO case set; report chain-rule precision/recall |

### Module 5 — Malicious URL & Website Detection

All URL subtopics share `malicious_url.analyze_url`; a subtopic model can only **raise** the score (alert → 71-100, verify → 51-70, `malicious_url.py:357-359, 598-605`). The domain-name model adds up to 40 points (`malicious_url.py:345-348`). [C]

| Module | Subtopic | Implementation status | Detection approach | Model name | Algorithm / architecture | Training status | Artifact path | Training script | Dataset | Dataset path | Dataset size | Class distribution | Evaluation metrics | Strength assessment | Integration status | Main problems | Recommended next action |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M5 URL | Domain spoofing | Implemented | URL engine + spoofing model (brand name inside a domain the brand does not own) | `domain_spoofing` | HGB, 27 features + brand/word tables [A] | **WEAK MODEL** | `models/domain_spoofing.joblib` | `training/train_domain_spoofing.py` (split by name 70/10/20, seed 42) | PhiUSIIL (UCI) + Tranco top-1M + wordfreq — verified | `training/data/phiusiil+phishing+url+dataset.zip`, `tranco_8PXYV-1m.csv.zip` | PhiUSIIL 235,795 URLs / 220,086 domains; Tranco 1,000,000 [A]; training 14,910 [R] | training 1,134 phishing / 13,776 genuine [R] | [R] held-out (n=4,278): AUC 0.866, 52.4 % @0.68 % FA. **Independent test (n=3,365): AUC 0.666, 48.4 % caught @16.5 % FA** | Does not generalise beyond its own split | Verified (`malicious_url.py:464-487`) | False alarms on genuine brand-containing domains (e.g. `leadertelegram.com`, `applecountryteam.com` [R]) | Re-train with more real brand-abuse domains; report independent-set FA |
| M5 URL | Look-alike domains | Implemented | URL engine + look-alike model on "skeleton" distance to 9,098 protected sites; one-typo rule floors to 51 (`malicious_url.py:351-355`) | `lookalike_domain` | HGB, 29 features + skeleton index [A] | **WEAK MODEL** (real-world) | `models/lookalike_domain.joblib` | `training/train_lookalike_domain.py` | Tranco + **dnstwist-generated** look-alikes; PhiUSIIL test only — verified | Tranco zip; PhiUSIIL zip | training 186,212 generated look-alikes / 103,605 genuine [R] | as left | [R] synthetic held-out (n=84,318): AUC 0.993, 84.4 % @0.7 % FA. **Real PhiUSIIL domains close to a protected site (n=37,914): AUC 0.507, 2.4 % caught**; within one edit: AUC 0.579 | Learns the generator, not real attacks | Verified (`malicious_url.py:433-461`) | Synthetic positives only | Add real typosquats (certificate-transparency + phishing feeds) as positives; evaluate on them |
| M5 URL | Typosquatting | Implemented | Same look-alike model and one-typo rule | `lookalike_domain` (shared) | as above | **WEAK MODEL** (shared model) | as above | as above | as above | as above | as above | as above | [R] synthetic per-trick @alert: omission 82.9 %, replacement 83.9 %, transposition 95.0 %, **TLD-swap 11.0 %**; real-world AUC as above | As above | Verified | As above | As above |
| M5 URL | Homoglyph attacks | Implemented | Look-alike model on Unicode TR39 confusable skeletons + punycode decoding (`lookalike_domain.py:43-168`); router flags `xn--` (`subtopic_router.py:594`) | `lookalike_domain` (shared) | as above | **TRAINED — NEEDS VALIDATION** | as above | as above | as above | as above | homoglyph 10,829 / Cyrillic 346 synthetic test items [R] | — | [R] synthetic homoglyph 95.6 %, Cyrillic 97.7 % caught @alert. No real IDN-homoglyph test | Unknown on real IDN abuse | Verified | Synthetic-only evaluation | Test on real IDN phishing domains |
| M5 URL | Suspicious URL structures | Implemented | URL-manipulation model + explicit-trick rules (`@` userinfo, odd IP forms, encoded traversal forced to alert/verify, `url_manipulation.py:247-255`) | `url_manipulation` | HGB, 41 features [A] | **WEAK MODEL** | `models/url_manipulation.joblib` + `url_manipulation.modern.json` | `training/train_url_manipulation.py`, `calibrate_url_manipulation.py` | DEPHIDES (PhishTank + CommonCrawl, MIT) + Kaggle `sid321axn` malicious URLs — **not in repo → provenance unverified locally** | not present | 744,813 links [R] | 285,062 malicious [R] | [R] held-out (n=149,683): AUC 0.895, 37.1 % @1.0 % FA; Kaggle part AUC 0.746. **2026 urlscan re-calibration: 0.12 % of 2026 phishing caught @alert, 0.55 % @verify** (thresholds 0.996/0.989 now override training ones, `url_manipulation.py:205-231`) | Statistical part effectively disabled on current phishing; explicit tricks still fire | Verified | Training data partly ISCX-URL-2016 era [R sources]; shorteners capped to "verify" (`malicious_url.py:535-547`) | Re-train on 2025–26 links with paths; keep rules |
| M5 URL | Malicious website classification | Implemented | URL engine incl. **fake-login page model** on the fetched HTML and **registry model** on RDAP facts | `fake_login`, `domain_age` (+ others above) | HGB 42 page features; HGB 16 registry features [A] | **TRAINED — NEEDS VALIDATION** (composite) | `models/fake_login.joblib`, `models/domain_age.joblib` | `training/train_fake_login.py`, `training/train_domain_age.py` | urlscan.io page copies (OpenPhish/PhishTank vs real logins) — verified; RDAP facts for Phishing.Database/OpenPhish/urlscan vs Tranco — verified | `training/data/urlscan/scans.jsonl` + `urlscan/dom/`; `domain_facts.jsonl`, `domain_age_sample.csv`, `urlscan_phish_domains.csv` | scans 6,849 (3,000 phish, 1,849 real login, 2,000 real web; 22 Jul → 19 Oct 2026) [A]; registry 6,070 records (3,501 usable) [A] | fake-login training 2,427 fake / 2,129 real [R]; domain-age 2,083/353/343 train/calib/test [R] | [R] fake-login grouped OOF (n=4,556): AUC 0.981, 85.4 % @1.0 % FA; October-only phishing: AUC 0.974, 65.7 % @0.4 % FA. [R] domain-age test (n=343): AUC 0.929, 63.9 % @3.4 % FA. [R] real-site check (`fake_login_check.txt`): 0 of 21 real sites shown as risky, but the model gave no verdict on 9 (JavaScript shells) and 2 pages could not be fetched. Phase-2: fake-login page 3/5 phishing caught | Components credible offline; end-to-end unmeasured | Verified; live fetch needs network (`settings.LIVE_PAGE_CHECKS`) | Training pages are browser-rendered (urlscan) but live pages are raw HTML (`fake_login.py:39-45` explains the gap); thresholds come from out-of-fold scores but are applied to a model re-fitted on all data (`train_fake_login.py:246-247`) | Render live pages headlessly or train on raw HTML; recalibrate thresholds on the deployed model |
| M5 URL | Phishing URL detection | Implemented | Whole URL engine + `url_domain_model` | `url_domain_model` (+ all above) | HGB on 15 name features + char 3–5-gram LR, averaged [A] | **TRAINED — NEEDS VALIDATION** (composite) | `models/url_domain_model.joblib` | `training/train_url_domain.py` | PhiUSIIL + Tranco — verified | as above | held-out 84,582 domains [R] | 8,351 phishing in test [R] | [R] domain-name model: **ROC-AUC 0.783, 26.6 % caught @1.0 % FA**; unseen popular sites flagged 1.3–1.5 %. [R] Phase-2: malicious-url 4/5 + 5/5, SSL/domain 5/5 + 5/5 | Name-only model is weak; engine relies on live checks | Verified | No end-to-end labelled set | As for M1 malicious URL |

### Module 6 — Intelligent Cyber Threat Detection

One shared, deterministic rule engine (`backend/app/detectors/cyber_threat.py:44-110`) serves every subtopic; the router only recognises the **log format** (`subtopic_router.py:630-691`). No model exists for any subtopic. Probes below are synthetic benign log strings run through the real engine [A].

| Module | Subtopic | Implementation status | Detection approach | Model name | Algorithm / architecture | Training status | Artifact path | Training script | Dataset | Dataset path | Dataset size | Class distribution | Evaluation metrics | Strength assessment | Integration status | Main problems | Recommended next action |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M6 Cyber threat | Malware indicators | Partial | Text rules: mimikatz/LSASS, encoded PowerShell, IEX/DownloadString, certutil/bitsadmin, regsvr32, script hosts, base64, file-hash presence (`cyber_threat.py:16-68`). File analysis exists only for e-mail attachments / downloads watcher (file type, macros, optional VirusTotal hash lookup — key empty per `phase2_live_check.txt`) | none | — | **RULE-BASED ONLY** | — | — | — | — | — | — | [R] demo T1 = 90. [A] `vssadmin delete shadows` + mass rename → 0 "safe" | Good on the listed command lines only | **Broken for files**: router refuses files (`subtopic_router.py:672-675`), manual path ignores the file (`analysis_service.py:144-147`) → [A] 0 "safe" | UI accepts `.exe/.apk/.dll/.pdf/.docx/.zip` (`modules.ts:152`); backend accepts only `.pdf` of these and then ignores it | P0: route files to `email_pipeline.attachments.scan_attachment` or refuse; add hash TI lookup |
| M6 Cyber threat | Suspicious network traffic | **Not implemented** | Router recognises firewall/flow formats; engine has **no** network rule | none | — | **PLACEHOLDER / NOT IMPLEMENTED** | — | — | — | — | — | — | [A] 14-port scan from one IP → 0 "safe"; 60-s beaconing → 0 "safe" | None | Misleading ("safe") | — | P0: hide or implement (fan-out, beacon periodicity, rare ports) with labelled flows (e.g. CIC-IDS2017) |
| M6 Cyber threat | API abuse | **Not implemented** (effectively) | Only a form field `requestsPerMinute > 500` (12 points) (`cyber_threat.py:76-78`); pasted access logs are not parsed for rates | none | — | **PLACEHOLDER / NOT IMPLEMENTED** | — | — | — | — | — | — | [A] 40 × `POST /api/v1/login 401` in 40 s → 0 "safe"; `requestsPerMinute=10000` alone → 12 "safe" | None | Misleading | — | Parse access logs; per-IP/token rate, 401/403 bursts, enumeration |
| M6 Cyber threat | Data exfiltration | Partial | Rules: upload to cloud storage / rclone (40), `dataTransferMb > 500` (18), off-hours (8) | none | — | **RULE-BASED ONLY** | — | — | — | — | — | — | [A] "4.2 GB to mega.nz via rclone" → 40 "low_risk"; `dataTransferMb=50000` alone → 18 "safe" | Weak weights; volume never alarms alone | Verified | Thresholds not tuned on data | Add volume baselines per user; raise weights; test on labelled insider/exfil logs (e.g. CERT r4.2) |
| M6 Cyber threat | Insider threats | Partial | Rules: copy to USB/removable (30), off-hours (8) | none | — | **RULE-BASED ONLY** | — | — | — | — | — | — | [A] 3,200 HR files copied to USB → 30 "low_risk" | Weak | Verified | No user baseline | As above |
| M6 Cyber threat | DDoS | **Not implemented** | No rule | none | — | **PLACEHOLDER / NOT IMPLEMENTED** | — | — | — | — | — | — | [A] 60-line request flood → routed *log-analysis*, 0 "safe" | None | Misleading | Not listed in UI; README silent | Implement only if in scope; otherwise state "not supported" |
| M6 Cyber threat | Ransomware | **Not implemented** | No rule (no shadow-copy deletion, mass rename, ransom-note patterns) | none | — | **PLACEHOLDER / NOT IMPLEMENTED** | — | — | — | — | — | — | [A] see malware row → 0 "safe" | None | Misleading | — | Add the classic indicators (vssadmin/wbadmin/bcdedit, mass rename, note files) with tests |

Code-only subtopics not in the brief (same detectors): *Video-call analysis* (video path), *AI-generated multimedia* (image/video path; audio → "safe", see Module 2), *Redirect analysis*, *SSL & domain analysis* (registry model), *Fake login page* (fake-login model), *Abnormal user activity* and *System & application log analysis* (Module 6 rule engine; uploaded log files ignored).

---

## C. Dataset provenance report

Chain: **source → local dataset → loader → preprocessing → training script → training run / checkpoint → saved model → inference service**. ✔ = evidenced in the repo, ✖ = missing link, ~ = partial. "Run record" means something that ties the saved file to one execution (embedded `trained_at`, metrics file written by the same run, hash). No artefact has a content hash or code-commit reference anywhere in the repo [C].

### C.1 Phishing text models

**`phishing_email`** — DATASET PROVENANCE UNVERIFIED
✖ source (README: "real phishing / legitimate emails"; no name, URL, licence or date) → ✔ `training/data/phishing_email_real.tsv` (18,634 records, 2-column TSV, multi-line quoted) → ✔ loader `pd.read_csv(sep="\t", header=None)` (`train_phishing.py:32-36`) → ~ preprocessing: lower-case, English stop-words, word 1–2-grams, `min_df=2`, `max_df=0.95`; the data itself is already lower-cased and tokenised in 65.7 % of rows [A] while inference receives raw e-mail text → ✔ `train_phishing.py` (stratified 80/20, seed 42) → ✖ run record (no metrics file; command line only implied by the docstring; file mtime 2026-09-20 01:49 UTC) → ✔ `models/phishing_email.joblib` (vectoriser parameters match the script [A]) → ✔ `email_pipeline/orchestrator.py:217` → `phishing.py:400`.
Freshness: 99.8 % of years mentioned ≤ 2010 (median 2001) [A]. Deployment match: **poor** (no headers, old corpora, no Indian context). Licence: unknown. Leakage: 288 of 3,727 reproduced-test texts also occur in the training part [A]; results on the unseen-only subset are similar (F1 0.976).

**`phishing_sms`** — DATASET PROVENANCE UNVERIFIED
✖ source (README: "SMS phishing corpus") → ✔ `training/data/phishing_sms_clean_v2.tsv` (77,891 rows; v1 `phishing_sms.tsv` 84,863 rows with 10,796 duplicates and 45 conflicting texts [A]) → ✔ loader (`train_sms_phishing.py:75-76`) → ✔ same TF-IDF preprocessing at train and inference → ✔ `train_sms_phishing.py` (stratified 80/20, seed 42, trap-set gate) → ✖ run record (no metrics; file mtime 2026-10-03 23:11 UTC, 3 min after the v2 data file) → ✔ `models/phishing_sms.joblib` → ✔ `phishing.py:24-29` (SMS subtopic), `known_contact_impersonation.py:258`.
Composition: 4,161 rows of v2 are not in v1 (3,940 genuine, 221 phishing; only 1,151 distinct texts after masking numbers), many of them templated synthetic transactional messages ("Dear Amit, your EMI of Rs 3771 was auto-debited …") as described in the script's docstring [A] → **mixture of real and synthetic**; the exact synthetic share is not recorded. Freshness unknown; mixes UK-style and Indian SMS.

**`phishing_pipeline`** (fallback for unexpected phishing subtopic ids) — verified
✔ UCI SMS Spam Collection (named in `training/data/README.md`) → ✔ `training/data/phishing_text_sample.tsv` (5,572 rows, 747 spam / 4,825 ham, 415 duplicates [A]) → ✔ `train_phishing.py` defaults → ✖ run record (no metrics) → ✔ `models/phishing_pipeline.joblib` → ~ only used when a phishing request reaches `analyze_text` with a subtopic not in `MODEL_FILES` (`phishing.py:42`). [A] reproduced split: F1 0.916, ROC-AUC 0.987, FPR 1.35 %.

**`phishing_social`** — partially verified
~ sources: UCI YouTube Spam Collection (URL + CC BY 4.0 recorded in metrics) ✔; SMS sample from the unverified SMS set ✖; hand-written curated DMs (synthetic) → ✔ local files (`youtube+spam+collection.zip` 1,956 raw comments, 1,005 spam [A]) → ✔ loaders/cleaning (`train_social_media_phishing.py:84-137`) → ✔ same preprocessing at inference → ✔ script (hold-out video "Shakira", SMS 80/20 seed 42, trap set) → ~ run record: metrics written by the same run, but the **saved model was re-fitted on all data** after evaluation (`train_social_media_phishing.py:198-202`), so the recorded test numbers do not describe the saved object [A] → ✔ `models/phishing_social.joblib` → ✔ `phishing.py` (social subtopic).

### C.2 Impersonation models (current artefacts from `retrain_impersonation_real.py`)

Common chain: ~ topic CSV (`source` column: "phish" / "synthetic-*" / "phishing_sms.tsv (real)") — the original origin of the "phish" template rows and of the real SMS is not recorded → ✔ local CSVs + `phishing_sms_clean_v2.tsv` (+ `phishing_email_real.tsv` for management/teacher) → ~ loaders: SMS read line-by-line; e-mail read with `quoting=3`, which keeps only the first physical line of 28 % of e-mails and leaves a leading quote on 45 % [A] (`retrain_impersonation_real.py:139-148`) → ✔ "confident learning" label cleaning (5-fold, drops 88 genuine + 13 scam rows) → ✔ 20 % of real messages held out by text hash; on-topic genuine messages the cleaner scores ≥ 0.8 are removed from **both** train and test (`:245-260`) → ~ run record: metrics written by the same run, but artefact mtimes are 2–6 min later than `trained_at` [A] and the pipelines carry no metadata → ✔ saved model → ✔ detector.

| Model | Topic CSV (rows; label × source) [A] | Templating [A] | Training rows [R] | Run `trained_at` [R] vs artefact mtime [A] |
|---|---|---|---|---|
| `government_official_impersonation` | 2,392: 750 "phish" + 192 real scam / 650 synthetic-casual + 800 synthetic-formal genuine | "phish" 120 templates; synthetic genuine 25 + 56 templates | 1,970 / 4,055 | 19:39:12 vs 19:44:10 (15 Oct) |
| `senior_management_impersonation` | 3,000: 1,400 "phish" / 700 + 900 synthetic | 137 / 141 / 137 templates | 1,679 / 4,013 | 04:30:40 vs 04:34:11 (17 Oct) |
| `teacher_university_impersonation` | 3,000: 1,400 "phish" / 700 + 900 synthetic | 192 / 227 / 207 templates | 1,592 / 6,812 | 04:30:56 vs 04:34:17 (17 Oct) |
| `financial_impersonation` | 5,097: 2,497 real scam / 2,600 synthetic | real 99 % unique; synthetic 308 templates | 5,543 / 8,174 | 19:38:57 vs 19:44:07 (15 Oct) |
| `brand_impersonation` | 3,989: 2,103 real scam / 286 real + 1,600 synthetic genuine | synthetic 545–661 templates | 4,565 / 6,269 | 19:41:24 vs 19:44:08 (15 Oct) |

In every topic CSV the class label is perfectly predicted by the `source` column (all genuine rows are synthetic or filtered real) [A]. The real-SMS retraining reduces, but does not remove, this confound.

**`impersonation_router`** — partially verified: built from the five topic sets + 23 real "known contact" scams (`known_contact_scams_real.tsv`, each row with a source URL ✔) + "none" messages from the SMS set (`train_impersonation_router.py`, 20 % by text hash) → metrics written by the run (18:25:47) vs artefact mtime 18:31:56 → `subtopic_router.py:359-404`. Training rows: financial 4,004, none 3,446, brand 2,623, management 2,299, teacher 2,272, government 1,797, contact 1,374 [R].

### C.3 Credential / account-takeover models

**`cred_failed-logins`, `cred_password-spraying`, `cred_unusual-location`, `cred_unknown-device`, `cred_session-activity`, `cred_behavior-changes`** — verified (six separate traces with the same upstream)
✔ "Login Data Set for Risk-Based Authentication", Wiefling et al., Kaggle `dasgroup/rba-dataset`, CC BY 4.0 (`extract_rba_subsets.py:11-13`) → ✖ full 9 GB file not in repo (git-ignored by design) → ✔ `training/data/rba_accounts_subset.csv.gz` (1,725,254 rows; 431,508 accounts; 8.45 % attack-IP rows; 141 ATO rows; no missing country/ASN/UA, 0 duplicate rows) and `rba_ip_subset.csv.gz` (2,957,596 rows; 351,308 IPs; 10.92 % attack-IP rows) [A] → ✔ loader + masking (`train_credential_subtopics.py:82-115`) → ✔ features from the **same** module used at inference (`app/detectors/credential_features.py`; feature list checked at load, `account_takeover.py:373-376`) → ✔ split by account/IP 70/10/20, seed 42, thresholds from calibration split → ✔ run record: `trained_at` embedded in each bundle equals the metrics file (e.g. behaviour-changes 2026-10-15T18:34:56 in both) [A] → ✔ `models/cred_<subtopic>.joblib` → ✔ `account_takeover.subtopic_assessment` (`:466-488`).
Labels: failed-logins and password-spraying = real "Is Attack IP" flag; the other four = **simulated attacker** contexts on real accounts. Freshness: Feb 2020 – Feb 2021. Deployment match: training uses full account histories with geo/ASN/UA; pasted logs at inference are short and often lack those fields (partly mitigated by masking).

**`ato_rba_model`** — partially verified
✔ same Kaggle source (recorded in the bundle's `card`) → ✖ 9 GB `rba-dataset.csv` not in repo → ✔ `train_ato_login.py` (user sample 0.1; RTT excluded as a label leak — good) → ✔ run record embedded (`trained_at` 2026-10-11T21:55:32 in bundle and metrics) → ✔ `models/ato_rba_model.joblib` → ✔ `account_takeover.model_assessment` (`:303-318`), router (`subtopic_router.py:539-552`), automation monitors. ATO rows: 141, **none in the test period**.

### C.4 URL / website models

**`url_domain_model`** — verified: ✔ PhiUSIIL (UCI #967, CC BY 4.0) + Tranco list → ✔ `phiusiil+phishing+url+dataset.zip` (235,795 URLs; label 1 = legitimate, correctly inverted at `train_url_domain.py:68,81`) + `tranco_8PXYV-1m.csv.zip` (1,000,000) [A] → ✔ registered-domain features shared with inference (`domain_model.py`) → ✔ run card embedded (2026-10-11T23:01:47) → ✔ `malicious_url._domain_indicators` → `domain_model.assess`.

**`lookalike_domain`** — verified: ✔ Tranco + dnstwist (generated at training time; positives are **synthetic**) + PhiUSIIL (test only) → ✔ split by protected brand 70/10/20 (`train_lookalike_domain.py:61-63`) → ✔ embedded `trained_at` = metrics (2026-10-16T09:19:09) → ✔ `malicious_url._lookalike`.

**`domain_spoofing`** — verified: ✔ PhiUSIIL + Tranco + wordfreq → ✔ split by domain name (`train_domain_spoofing.py:65-67`) → ✔ `trained_at` 2026-10-16T17:52:28 both → ✔ `malicious_url._spoofing`.

**`url_manipulation`** — DATASET PROVENANCE UNVERIFIED (locally): ~ DEPHIDES (github.com/ebubekirbbr/dephides, MIT) + Kaggle `sid321axn/malicious-urls-dataset` are documented in `training/data/README.md` but **not present** → ✖ cannot re-check counts/labels → ✔ split by registered domain (`train_url_manipulation.py:59-68`) → ✔ `trained_at` 2026-10-16T19:29:00 both; re-calibration file `url_manipulation.modern.json` (2026-10-21T13:41:47) now overrides both thresholds at load time → ✔ `malicious_url._manipulation`.

**`domain_age`** — verified: ✔ Phishing.Database ACTIVE list, OpenPhish via urlscan.io, Tranco (sources per row in `domain_age_sample.csv`, `urlscan_phish_domains.csv`) → ✔ RDAP facts collected by `collect_domain_facts.py` into `domain_facts.jsonl` (6,070 records, 3,501 usable) [A] → ✔ split by domain hash, separate calibration part → ✔ `trained_at` 2026-10-21T04:34:40 both → ✔ `malicious_url._registry_model`. Small: 343 test domains.

**`fake_login`** — verified: ✔ urlscan.io scans of OpenPhish/PhishTank links and real login pages, collected by `collect_urlscan.py` (22 Jul – 19 Oct 2026) → ✔ `urlscan/scans.jsonl` (6,849 records) + `urlscan/dom/` page copies → ✔ features from the shared `login_page_features.py` (feature list checked at load, `fake_login.py:30`) → ✔ grouped 5-fold (phishing kit / real site) + October time test → ~ thresholds from out-of-fold scores, **final model re-fitted on everything** (`train_fake_login.py:246-247`) → ✔ `trained_at` 2026-10-21T08:20:16 both → ✔ `malicious_url._login_page_model`. Licence: urlscan.io terms apply to redistributed page copies [I].

### C.5 Vision models

**`deepfake_video`** — partially verified: ~ Celeb-DF v2 (via the user's private Drive link) + DFDC sample (Kaggle competition data) — documented in the notebook, not in repo → ✔ frame/face code copied verbatim from `app/detectors/video_frames.py` into the notebook at build time (`build_deepfake_video_kaggle.py:10`) → ✔ split by person, official test list held out → ✔ model card with `trained_at` 2026-10-20T20:04:58 (artefact copied to the PC 2026-10-21 03:37 UTC) → ✔ `deepfake_video.py` → `deepfake.py:200-285`.

**`deepfake_image`** — DATASET PROVENANCE UNVERIFIED: ✖ notebook `docs/colab/CyberGuard_Deepfake_Image_Colab.ipynb` referenced in `deepfake_image.py:8` is absent → ✖ data absent → only the model card names "OpenForensics (Kaggle manjilkarki/deepfake-and-real-images)", 140,002 images, 4 epochs → ✔ `models/deepfake_image.onnx` (EfficientNet-B0, input 1×3×224×224, output 1 logit [A]) → ✔ `deepfake_image.assess_image`.

**`ai_image`** — DATASET PROVENANCE UNVERIFIED: ✖ notebook `docs/colab/CyberGuard_AI_Image_Colab.ipynb` (referenced at `ai_image.py:17`) absent → ✖ data absent ("modern-generators, shutterstock-pairs, stylegan-faces", 43,456 images per card) → ✖ artefact not loaded by the audit (1.2 GB) → ✔ `ai_image.assess` (`:229`).

---

## Phase 5 — Audit-measured results (read-only)

### 5.1 Reproduced hold-out evaluations of models that had no metrics file [A]
Same split as the training script (`train_test_split(test_size=0.2, random_state=42, stratify=y)`), threshold 0.5, saved model loaded unchanged.

| Model | Test n (pos) | Acc | Precision | Recall | F1 | ROC-AUC | PR-AUC | FPR | FNR | Test rows whose text is also in train | Unseen-only F1 / FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `phishing_email` | 3,727 (1,462) | 0.972 | 0.944 | 0.988 | 0.966 | 0.996 | 0.993 | 3.75 % | 1.23 % | 288 | 0.976 / 2.06 % |
| `phishing_sms` | 15,579 (4,550) | 0.946 | 0.866 | 0.963 | 0.912 | 0.988 | 0.966 | 6.15 % | 3.69 % | 200 | 0.911 / 6.22 % |
| `phishing_pipeline` | 1,115 (149) | 0.978 | 0.913 | 0.920 | 0.916 | 0.987 | 0.967 | 1.35 % | 8.05 % | 130 | 0.905 / 1.15 % |

These are **in-distribution** numbers. They are only as trustworthy as the unverified datasets they come from.

### 5.2 Robustness probes [A]
| Probe | Result |
|---|---|
| E-mail model alone on the 10 sample e-mails in `backend/tests/email_samples/` (6 attack, 4 genuine; synthetic samples made by `make_samples.py`) | P(phish): attacks 0.853, 0.656, 0.679, **0.386**, **0.458**, 0.854; genuine Amazon **0.716**, Google sign-in alert **0.689**, HDFC statement **0.720**, university notice 0.170 → AUC 0.50 (n=10, indicative only) |
| Strongest learned terms, e-mail model | legit: `enron, language, thanks, 2002, wrote, university, linguistics, edu, attached, vince, 2001, english, date, url, louise, url http, 2000, languages, questions, 713`; phish: `click, free, remove, 2005, money, email, online, 2004, life, removed, save, site, reply, best, info, offer, visit, low, viagra, spamassassin sightings` |
| Social model on its own recorded "unseen" test sets | YouTube video: acc 1.000 (recorded 0.931); SMS hold-out acc 0.974 (recorded 0.931) → saved model has seen the test data (refit) |
| Credential models on synthetic logs | brute force then success → failed-logins p 0.897 (high); 10-account spray → spraying p **0.0006** (low; rules give 75); python-requests UA on a known account → unknown-device p 0.745 (verify); RU login on an IN account → unusual-location p 0.947, behaviour-change p 0.999; normal history → 0 |
| Module 6 engine on synthetic logs | port scan 0, API login burst 0, flood 0, ransomware commands 0, beaconing 0, `requestsPerMinute=10000` 12, `dataTransferMb=50000` 18, rclone to mega.nz 40, 3,200 files to USB 30 |
| Audio via manual deepfake path | score 4, "safe", "No immediate action required" |
| File-only upload through `subtopic_router.route` | cyber-threat log file → routed *log-analysis*, **0 safe** (same text pasted: 100 critical); impersonation text file → routed *financial-impersonation*, **0 safe** (same text pasted: 80 high_risk) |
| Face-swap image model on face-less synthetic images (noise, flat grey, gradient) with `ai_image.onnx` absent | no face → whole image judged → scores 0, "safe" |

### 5.3 Inference latency (sandbox CPU, model only) [A]
TF-IDF+LR text models: 0.3–1.6 ms per message (load 13 ms – 2.1 s; `phishing_email` is the largest at 23.9 MB / 648k features). HGB models: 2–4.5 ms per row. EfficientNet-B0 ONNX: 8–10 ms per face crop (≈0.15 s for the 16 video frames, excluding decoding and face detection). Peak RSS with all text and HGB models loaded: ≈280 MB. Recorded end-to-end times [R] (`demo_check.txt`): 0.0–5.3 s per scan; URL scans with live checks median 1.3–2.3 s (`phase2_live_check.txt`). Latency is not a bottleneck; network checks are.

---

## Phase 6 — End-to-end integration

Common path for every scan [C]: `POST /api/analysis/scan` (`routes/analysis.py:68`) → length checks and upload allow-list (`:19-49`) → `subtopic_router.route` (auto) or `run_scan` (manual) → `response_playbook.apply` → `scan_store.save_result` (Scan, indicators, recommendations, `ThreatEvent` when not safe, IOC "seen before" memory, `scan_store.py:12-57`) → commit → `notifier.alert_for_scan` in the background when score ≥ 51 (`notifier.py:308`) → JSON to the frontend, which renders the backend's own `riskScore`, `classification`, `analysisEngine`, indicators and model blocks (`src/components/analysis/ResultView.tsx`). Exceptions inside a detector are caught and the scan falls back to rules (text models) or "no verdict" (vision/URL models); unhandled errors go to the global handler (`main.py:156`).

| Model | Loaded at | Invoked by | Same preprocessing as training | Input format match | Score interpretation / thresholds | On missing / broken model | Status |
|---|---|---|---|---|---|---|---|
| `phishing_email` | `phishing.py:34-59` (path from relative `MODELS_DIR`, `config.py:121`) | e-mail pipeline | ~ same vectoriser, but training text is pre-tokenised | ✖ training text has no headers, is old | `predict_proba[:,1]`, blended 0.6/0.4 with rules (`:409`); fusion trust discounts | rules-only, engine label changes (`:418-420`) | **Partial** (input mismatch) |
| `phishing_sms` | same | `analysis_service.py:94`; known-contact detector | ✔ | ✔ | as above; OTP-notice cap 20, pattern floors 71–75 | rules-only | **Verified** |
| `phishing_social` | same | `analysis_service.py:94` | ✔ | ~ (YouTube/SMS vs DMs) | as above + promotion cap 50 (`:439-443`) | rules-only | **Verified** |
| `phishing_pipeline` | same | fallback for other phishing ids | ✔ | ✔ | as above | rules-only | Verified (rarely reached) |
| 5 impersonation models | each detector's `_get_model()` (absolute path) | `analysis_service.py:101-131`, e-mail pipeline, "category unclear" runs all | ✔ (brand masking both sides) | ~ SMS-trained, used on e-mail too | blend 0.6/0.4 or 0.65/0.35 + floors; flagged at ≥51 | rules-only | **Verified** |
| `impersonation_router` | `subtopic_router.py:365-377` (kind check) | auto-detect only | ✔ (reads sender/subject/body) | ✔ | adds 3 × p when p ≥ 0.15 to rule votes; "generic" when unsure | rules-only routing | **Verified** |
| 6 × `cred_*` | `account_takeover.py:362-380` (kind, subtopic and feature-list check) | `analysis_service.py:133-137` with subtopic id | ✔ same feature code | ~ pasted logs are sparse | alert → 71–100, verify → 51–70 (`:646-651`), can only raise | `None` → RBA model fallback | **Verified** |
| `ato_rba_model` | `account_takeover.py:259-272` | fallback; router; login/Windows monitors | ✔ | ~ | percentile ≥ 99 → high; can only raise | `None` → rules only | **Verified** |
| `url_domain_model` | `domain_model.py:107-123` | every URL scan | ✔ | ✔ | up to +40 points | skipped | **Verified** |
| `lookalike_domain`, `domain_spoofing`, `url_manipulation` | detector `load_model()` | URL subtopics; all three on QR / general / malicious-url / fraudulent-website (`malicious_url.py:521-526`) | ✔ | ✔ | floors from `_model_points` (`:598-605`); shortener cap for manipulation | skipped | **Verified** |
| `domain_age` | `domain_age.py:78-106` | URL scans with network (RDAP) | ✔ | ✔ when RDAP answers | registry model floor | skipped (offline = no verdict) | **Verified** (network-dependent) |
| `fake_login` | `fake_login.py:21-34` (kind + feature check) | URL scans with live page fetch | ~ rendered DOM (train) vs raw HTML (live) | ~ JS shells → no verdict | alert/verify thresholds from OOF scores | skipped | **Partial** |
| `deepfake_image`, `ai_image` | `deepfake_image.py:26-56`, `ai_image.py:33-34,182` | `deepfake.analyze_media` (image) | ✔ (normalisation from the cards) | ✔ for `.png/.jpg/.jpeg` | strongest of provenance / AI / face decides | metadata-only result, still classified (can be "safe") | **Verified** |
| `deepfake_video` | `deepfake_video.py:23-42` | `deepfake.analyze_media` (video) | ✔ (shared frame code) | ✔ `.mp4/.mov/.avi/.mkv/.webm`; ✖ `.m4v` | mean face score; < 3 faces → "unverified" | "unverified", not "safe" | **Verified** |
| (audio) | — | `deepfake.analyze_media` (falls into image path) | — | ✖ | — | returns "safe" | **Broken** |
| (Module 6 files) | — | `analysis_service.py:144-147` ignores `file_path` | — | ✖ | — | returns "safe" | **Broken** |

Silent replacement risk [C]: every text and impersonation detector silently drops to rules-only when its `.joblib` is absent; because all model files are git-ignored (`.gitignore:19,33`) and the model tests are `skipif`-guarded, a fresh clone or a container built from git runs **without any model** while tests pass. The relative `MODELS_DIR` (`config.py:121`) also makes the four phishing models disappear if the server is started from a directory other than `backend/` (the other detectors use absolute paths).

---

## D. Model weakness report

Ranked by severity of the **demonstrated** problem (how wrong the model is on real data × how much it can move a verdict). Only models with recorded or audit-measured evidence are ranked; models without such evidence are listed afterwards, not ranked.

| Rank | Model | What is wrong | Evidence | Impact on detection | Additional testing needed | Recommended improvement |
|---|---|---|---|---|---|---|
| 1 | `cred_unknown-device`, `cred_behavior-changes`, `cred_session-activity` | Trained on simulated attackers; **below random** on real attacker logins | [R] real-label ROC-AUC 0.411 / 0.437 / 0.476 vs simulated 0.914 / 0.966 / 0.998; session model learns the injected 2–110-minute gap | Each can lift a score to 71–100 with an "attack pattern detected" explanation (`account_takeover.py:636-651`) while catching 1–5 % of real attackers at 1 % FA → mostly confident-sounding false alarms | Real takeover cases (even 50–100) or a lab with scripted attacker sessions; compare model vs rules | Cap model-only effect at "verify"; re-label from real data or replace with per-account rules (new UA family + MFA change, concurrent sessions from distant IPs) |
| 2 | `lookalike_domain` (look-alike, typosquatting, homoglyph) | Positives are dnstwist-generated; does not separate real phishing domains | [R] synthetic AUC 0.993 vs real PhiUSIIL near-brand AUC **0.507** (2.4 % caught), within one edit 0.579 | Real typosquats mostly missed by the model; one-typo rule partly compensates | Real typosquat set (CT logs + phishing feeds, Indian brands) | Mix real positives into training; evaluate on real only |
| 3 | `url_manipulation` | Statistical model does not separate 2026 phishing from real links | [R] modern re-calibration: **0.12 %** caught @alert, 0.55 % @verify on 1,624 phishing links; Kaggle part AUC 0.746 | Effectively rule-only; the README still quotes AUC 0.90 / 37 % | 2025–26 labelled links with paths | Retrain on current links; keep explicit-trick rules |
| 4 | `phishing_email` | Learned corpus artefacts from ~2000-era mail; input distribution unlike live mail | [A] top features `enron`, `2001`, `linguistics`, `spamassassin sightings`; 99.8 % of years ≤ 2010; 10-sample probe AUC 0.50 with 3/4 genuine at ≈0.7 | Inflates text evidence on genuine modern mail (Amazon/Google/HDFC samples ≈0.7) and under-scores some attacks; fusion trust rules mask part of it for authenticated senders | ≥500 modern labelled e-mails with headers (Indian banks/universities/government), time-split | Replace dataset; strip corpus-identifying tokens; save metrics |
| 5 | `deepfake_video` | Overfits Celeb-DF | [R] DFDC AUC **0.721**, 2.8 % caught @alert | Most real-world face-swaps outside Celeb-DF style get "no manipulation found" | Other datasets (FaceForensics++, DFDC full, in-the-wild clips) | Multi-dataset training; per-dataset calibration |
| 6 | `ai_image` | Does not generalise to an unseen generator family | [R] leave-one-source-out AUC 0.715 / 0.735 / 0.718; 1 %–51 % caught with up to 21 % FA | New generators slip through or real photos get flagged | Unseen-generator benchmark + recompressed real photos | Broader generator mix; report LOSO in README |
| 7 | `ato_rba_model` | Account-side score below random on real attacker-IP logins; ATO rows only in training period | [R] real 0.412; attacker side recall 12 % @1 % FA | Used by automation monitors and as fallback; weak signal presented as "RBA risk model" | Real ATO cases in a later time window | Treat as reputation hint only |
| 8 | `cred_password-spraying` | Low recall; misses a textbook spray | [R] ROC-AUC 0.773, 8.7 % @1.2 % FA; [A] 10-account spray p = 0.0006 | Rules carry spraying detection | Lab spraying logs (AD / SSH) | Demote; keep rule |
| 9 | `domain_spoofing` | Weak on independent data; high FA there | [R] independent AUC **0.666**, 48 % caught @**16.5 %** FA | False alarms on genuine brand-containing domains | Independent brand-abuse set with Indian brands | Add real negatives with brand names; recalibrate |
| 10 | `cred_unusual-location` | Simulated label; modest on real attackers | [R] real ROC-AUC 0.625, 5.7 % @1 % FA | Rules (new country, impossible travel) do the work | Real cases | As rank 1 |
| 11 | `cred_failed-logins` | Proxy label ("IP on attacker list"); low recall at operating point | [R] PR-AUC 0.399, 13.6 % @0.98 % FA | Brute-force rules carry detection | Real brute-force logs | Re-label by behaviour (bursts) not IP list |
| 12 | `url_domain_model` | Name-only model, weak separation | [R] ROC-AUC 0.783, 26.6 % @1 % FA | Adds ≤40 points; live checks carry URL verdicts | — | Keep as minor feature or retire |
| 13 | `teacher_university_impersonation` | Low recall on real scams | [R] 51.0 % of 49 real scams | Half of real academic scams scored < 51 by model+rules at training time (newer rules not measured) | ≥200 real academic scam messages | Collect data; re-measure detector including new rules |

Not ranked (no demonstrated weakness, but evidence gaps): `phishing_social` (no real DM test; deployed artefact differs from evaluated one), `senior_management_impersonation` (71 real scams), `deepfake_image` (no cross-dataset test; training code missing), `impersonation_router` (templated test parts), `phishing_pipeline` (fallback), and the verified models whose evidence is SMS-only.

Cross-cutting weaknesses [C][A]:
* **Selective reporting in README** (`README.md:58-74`): look-alike, spoofing, URL-manipulation, RBA and login-model rows quote synthetic or in-distribution numbers while the metrics files also contain the weaker real-world numbers (0.507, 0.666, 0.12 %, 0.41, 0.41–0.63). The README sentence that voice cloning is shown as "unverified, never real" (line 77) is false for the manual path.
* **Threshold/calibration**: `fake_login` thresholds come from out-of-fold predictions but are applied to a model re-fitted on all data; `deepfake_image` alert/verify thresholds sit at 0.9999999957 / 0.9999977 (saturated outputs, fragile to any preprocessing change); text models use a fixed 0.5 cut with no calibration.
* **Stale labels in results**: government engine name hard-codes "TF-IDF+LogReg (192 real + synthetic)" (`government_impersonation.py:254`); every phishing result says "TF-IDF+LogReg" regardless of the loaded file (`phishing.py:456`).

---

## E. Missing training checklist

Subtopics that lack a verified trained model, have incomplete training, or require validation. (Verified subtopics are listed at the end with the validation they still need.)

**Module 1 — Phishing**
- [ ] Email phishing — replace `phishing_email` (corpus artefacts, no metrics, no provenance)
- [ ] Social-media phishing — validate on real social DMs/comments; keep an untouched test set
- [ ] QR-code phishing — build a labelled QR evaluation set (rule layer + URL models)
- [ ] Fraudulent website — end-to-end labelled evaluation of the URL engine
- [ ] Malicious / deceptive URL — end-to-end labelled evaluation of the URL engine

**Module 2 — Deepfake**
- [ ] Deepfake image — commit training notebooks; cross-generator / cross-dataset validation
- [ ] Deepfake video — cross-dataset training and validation
- [ ] Deepfake audio — no model; fix the "safe" result first, then train and evaluate a voice-clone detector

**Module 3 — Impersonation**
- [ ] Senior management / executive — larger real BEC test set; fix e-mail loader
- [ ] Teacher / educational institution — real data collection; re-measure detector with the new rules
- [ ] Friend / family / trusted contact — labelled evaluation set; decide whether a dedicated model is needed

**Module 4 — Credential theft / ATO**
- [ ] Repeated failed login attempts — re-label by behaviour; validate on real logs
- [ ] Password spraying — validate/replace model; labelled spraying logs
- [ ] Brute-force login attempts — tune rule thresholds on labelled data
- [ ] Logins from unusual locations — real-label validation
- [ ] Login from new / unfamiliar devices — real-label validation (currently below random)
- [ ] Suspicious session activity — re-design label (currently below random)
- [ ] Account-takeover behaviour — real ATO case set; measure chain rules

**Module 5 — URL / website**
- [ ] Domain spoofing — independent real-world validation, recalibration
- [ ] Look-alike domains — real positives; real-world validation
- [ ] Typosquatting — real positives (shared model)
- [ ] Homoglyph attacks — real IDN homoglyph test
- [ ] Suspicious URL structures — retrain on current links
- [ ] Malicious website classification — end-to-end evaluation; fix rendered-vs-raw HTML gap
- [ ] Phishing URL detection — end-to-end evaluation

**Module 6 — Cyber threat**
- [ ] Malware indicators — file analysis path (or refusal); labelled command-line set
- [ ] Suspicious network traffic — not implemented
- [ ] API abuse — not implemented
- [ ] Data exfiltration — tune rules on labelled logs
- [ ] Insider threats — tune rules on labelled logs
- [ ] DDoS — not implemented
- [ ] Ransomware — not implemented

**Verified, still to validate beyond SMS**
- [ ] SMS phishing — fresh 2026 Indian SMS test; provenance record
- [ ] Government impersonation — e-mail / WhatsApp test set
- [ ] Bank / financial impersonation — e-mail / app-notification test set
- [ ] Brand impersonation — e-mail / social test set

---

## F. Remediation roadmap

No model in this repository should be called production-ready until the acceptance criteria below are met on data it has never seen.

### P0 — Critical (misleading detection claims)

| # | Task | Module | Required data | Expected code changes | Evaluation / acceptance criteria | Depends on |
|---|---|---|---|---|---|---|
| P0-1 | Never return "safe" for input the detector cannot read | M2, M3, M4, M6 | none | `analysis_service.run_scan`: if `module_id=="deepfake"` and the file is audio (or `subtopic_id=="audio-analysis"`) return `build_unverified_result`; in M3/M4/M6 read `.txt/.log` uploads into `text_input` (as the router already does) or reject file-only requests with 422; route M6 binaries/PDFs to `email_pipeline.attachments.scan_attachment` or 422 | New tests: audio upload → classification "unverified"; `.txt` log upload scores the same as pasted text; PDF in malware → attachment scan or 422; no "safe" for empty text | — |
| P0-2 | Remove claims for capabilities with no logic | M6 | none | Mark *network-traffic* and *api-abuse* as unavailable in `subtopic_router.DETECTORS` and `src/data/modules.ts` (or show "not supported"); state DDoS/ransomware unsupported | The five attack logs in §5.2 never return "safe" (either unverified or detected) | — |
| P0-3 | Correct the README results table | all | existing metrics files | Add real-world columns (look-alike 0.507, spoofing independent 0.666, URL-manipulation modern 0.12 %, login models real-label AUCs, RBA 0.41, DFDC 0.72, AI-image LOSO); fix line 77 | Every README number traceable to a metrics file key | P0-1 |

### P1 — High

| # | Task | Module | Required data | Expected code changes | Evaluation / acceptance criteria | Depends on |
|---|---|---|---|---|---|---|
| P1-1 | Model manifest and reproducibility | all | — | `models/MANIFEST.json`: file, SHA-256, training script + git commit, dataset file hashes, `trained_at`, metrics key, thresholds; detectors verify hash at load; embed `trained_at`/hash in TF-IDF bundles; make `MODELS_DIR` absolute (`config.py:121`); CI `--require-models` mode where model tests fail instead of skip | Fresh clone + model download reproduces every metrics file within ±0.01 AUC; startup log lists loaded models and hashes | — |
| P1-2 | Replace the e-mail text model | M1 | ≥10k modern e-mails with headers (mix of public modern phishing corpora + consented Indian institutional mail), source and date recorded | New loader keeping subject/from/body raw; group/time split; save `phishing_email.metrics.json` | Held-out (time-later) ROC-AUC ≥ 0.95 and FPR ≤ 2 % at the deployed threshold; no corpus-name tokens among top-50 features; ≥0.9 AUC on a 200-e-mail Indian test set | P1-1 |
| P1-3 | Contain the simulated-label login models | M4 | real ATO / attacker sessions (lab or partner logs) | Cap subtopic-model effect at "verify" (51–70) unless a rule also fires; label text "model unusual" not "attack pattern detected" | On real attacker logins ROC-AUC > 0.75 before the cap is lifted; FA on normal logins ≤ 1 % | — |
| P1-4 | Real-world URL validation set | M1, M5 | ≥1,000 fresh phishing URLs (OpenPhish/PhishTank/urlscan, last 30 days) + ≥1,000 real URLs incl. Indian banks/universities/government; real typosquats and IDN homoglyphs | Evaluation script running the whole `analyze_url` offline and online | Per subtopic: recall at ≤1 % FA reported; look-alike/spoofing models only kept as score-raising if real-data AUC ≥ 0.8 | P1-1 |
| P1-5 | Deepfake cross-dataset validation | M2 | FaceForensics++ / DFDC subset, unseen-generator image set, WhatsApp-recompressed real photos | Commit the two missing Colab notebooks; add an evaluation notebook | Cross-dataset AUC and recall @1 % FA reported in the model card and README | — |
| P1-6 | Module 6 minimal real detectors (if in scope for the demo) | M6 | labelled flow/API logs (e.g. CIC-IDS2017 subsets), ransomware command-line samples, CERT insider data | Parse access/firewall logs into per-source rates, distinct-port fan-out, periodicity; ransomware command patterns; raise exfil/insider weights | Each subtopic: ≥ 90 % of a labelled attack-log set flagged, ≤ 5 % of normal logs flagged | P0-2 |

### P2 — Medium

| # | Task | Module | Required data | Expected code changes | Evaluation / acceptance criteria | Depends on |
|---|---|---|---|---|---|---|
| P2-1 | Fix the impersonation e-mail loader | M3 | — | `retrain_impersonation_real.load_email`: use the same parser as `train_phishing.py` (no `quoting=3`) | Loaded e-mail count 18,634, median length ≈ 880 chars | — |
| P2-2 | Remove label/source confound | M3, M1 social | real genuine on-topic messages (bank, college, government) | Replace synthetic genuine rows; keep synthetic only as augmentation with a flag | Model trained without synthetic genuine rows keeps ≥ 95 % of its real-test recall | P2-1 |
| P2-3 | Untouched final test sets for refit models | M1 social, M5 fake-login | — | Hold a final test split outside the refit; recompute thresholds on the deployed model (calibration split) | Recorded metrics computed on the deployed artefact | P1-1 |
| P2-4 | Fake-login train/serve gap | M5 | — | Render live pages headlessly (or retrain on raw HTML) | Live real-site check: "no verdict" < 10 %; FA ≤ 1 % on 200 real login pages | — |
| P2-5 | SMS model threshold and provenance | M1 | fresh 2026 SMS | Calibrate threshold; record source/licence | FA ≤ 1 % on real transactional SMS at ≥ 90 % recall | — |
| P2-6 | Larger real tests for management / teacher / known-contact | M3 | ≥300 real BEC, ≥200 academic scams, ≥300 family-scam + genuine family chats | — | Detector recall ≥ 80 % at FA ≤ 2 % on each | P2-2 |
| P2-7 | `.m4v` and allow-list consistency | M2 | — | Align `deepfake.py:322`, `subtopic_router.VIDEO_EXT`, `routes/analysis.py:19` and UI accepted types | Test per extension | — |

### P3 — Low

| # | Task | Module | Expected change | Acceptance |
|---|---|---|---|---|
| P3-1 | Truthful engine labels | M1, M3 | Build engine names from the loaded artefact's metadata instead of hard-coded strings (`phishing.py:456`, `government_impersonation.py:254`) | Engine label shows model file + `trained_at` |
| P3-2 | Monitoring | all | Log per-model score distributions and alert rates per day; drift alarm | Weekly report |
| P3-3 | Dataset cards | all | One card per dataset: source URL, licence, collection date, rows, label meaning, known limits | Card exists for every file in `training/data/` |
| P3-4 | UI copy | M1, M5 | Remove "upload screenshot" from fraudulent-website / fake-login text until implemented (`modules.ts:78,141`) | — |

Suggested order when time is short: P0-1 → P0-2 → P0-3 (each is small and removes misleading output) → P1-1 → P1-3 → P1-2 → P1-4 → the rest.

---

## Appendix — How this audit was performed

1. Listed the repository on the user's computer and copied (read-only snapshots) all backend Python code, all 23 `.joblib` and 3 of 4 `.onnx` artefacts, all metrics/model cards, all datasets present in `backend/app/ml/training/data/` (except the `urlscan/dom/` page copies), the saved check outputs, tests, README/docs and the relevant frontend files into an isolated sandbox.
2. Created a throw-away Python environment **in the sandbox only** with the project's pinned versions (scikit-learn 1.5.2, numpy 2.1.1, joblib 1.4.2, pandas 2.2.3) plus onnxruntime, Pillow, OpenCV and the backend's network/parsing libraries, to load artefacts exactly as the application does. Nothing was installed on the user's computer.
3. Loaded every artefact, recorded its structure and parameters, and compared bundle `trained_at` values with metrics files and file timestamps.
4. Measured dataset sizes, label distributions, duplicates, conflicting labels, templating (unique texts after masking numbers/names), source composition, and train/test text overlap.
5. Re-ran only **inference** of saved models on (a) the training scripts' own reproducible hold-out splits where no metrics existed, (b) the repo's sample e-mails, (c) small synthetic benign probes for routing and Module 4/6 rules. No model was trained, re-fitted or saved; no file in the project was changed.
6. Traced each model from data to endpoint by reading the training scripts, detectors, router, analysis service, API route, scan store and frontend service code.

Files in the project changed by this audit: **only this report** (`docs/ML_MODEL_AUDIT.md`, new).
