# Training data

Datasets used by the CURRENT models. Big downloaded datasets are git-ignored (see `.gitignore`);
put them back in this folder to retrain.

| File | Source | Used by (training script -> model) |
|---|---|---|
| `tranco_*-1m.csv.zip` | Tranco top-1M list (tranco-list.eu) | `train_url_domain.py` -> `url_domain_model`, `train_lookalike_domain.py` -> `lookalike_domain`, `train_domain_spoofing.py` -> `domain_spoofing` |
| `phiusiil+phishing+url+dataset.zip` | PhiUSIIL Phishing URL Dataset (UCI) | `train_url_domain.py`, `train_lookalike_domain.py` (test only), `train_domain_spoofing.py` |
| `dephides/small_dataset/*.txt` (not kept here, 45 MB) | DEPHIDES, github.com/ebubekirbbr/dephides (PhishTank + CommonCrawl, MIT) | `train_url_manipulation.py` -> `url_manipulation` |
| `malicious_phish.csv` (not kept here, 45 MB) | Kaggle `sid321axn/malicious-urls-dataset` | `train_url_manipulation.py` (second source) |
| `phishing_email_real.tsv` | real phishing / legitimate emails | `train_phishing.py` -> `phishing_email`; results: `measure_text_models.py` |
| `phishing_text_sample.tsv` | UCI SMS Spam Collection | `train_phishing.py` (default) -> `phishing_pipeline` (fallback text model) |
| `phishing_sms.tsv`, `phishing_sms_clean_v2.tsv` | SMS phishing corpus | `train_sms_phishing.py` -> `phishing_sms`; impersonation retraining; results: `measure_text_models.py` (3,500 added template genuine messages are left out of the test) |
| `social_media_phishing.csv`, `youtube+spam+collection.zip` | social-media scam text, UCI YouTube Spam | `train_social_media_phishing.py` -> `phishing_social` |
| `brand_impersonation.csv`, `financial_institution_impersonation.csv`, `government_official_impersonation.csv`, `senior_management_impersonation.csv`, `teacher_university_impersonation.csv` | impersonation message sets | the `train_*_impersonation.py` scripts / `retrain_impersonation_real.py` |
| `known_contact_scams_real.tsv` | real reported 'Hi Mum, new number' / friend scam messages, each with its source link | `train_impersonation_router.py` -> `impersonation_router`; tests of the known-contact scam-script check |
| `financial_institutions.json` | bank / institution directory | used at run time by `financial_impersonation.py` and the email pipeline |
| `rba_accounts_subset.csv.gz`, `rba_ip_subset.csv.gz` | RBA login dataset (Wiefling et al.), made by `extract_rba_subsets.py` | `train_credential_subtopics.py` -> `cred_*` |
| `crux/current.csv.gz` (downloaded by the script, git-ignored) | Chrome UX Report top-1M websites, cached by github.com/zakird/crux-top-lists (real Chrome traffic, monthly) | `calibrate_url_domain.py` -> `url_domain_model.modern.json` (2026 'verify' level of the domain-name model) |
| `urlscan/scans.jsonl` (collected on this PC, git-ignored) | urlscan.io scans: 2026 phishing + real pages | `train_fake_login.py`, `calibrate_url_manipulation.py` -> `url_manipulation.modern.json`, `calibrate_url_domain.py` (report) |
| `api_abuse/*` (downloaded by `train_api_abuse.py --download`, SHA-256 checked, git-ignored) | CSIC 2010 HTTP dataset; HttpParams (MIT); DEPHIDES legitimate links (MIT); Fwaf (test only) | `train_api_abuse.py` -> `api_abuse` (API Abuse Detection) |
| `log_analysis/AIT-LDS-v1_1.zip` + `ait_v1_lines.jsonl.gz` (made by `prepare_ait_logs.py`, git-ignored) | AIT Log Data Set V1.1 (Austrian Institute of Technology, CC BY-NC-SA 4.0, zenodo.org/records/4264796): 4 attacked servers, every line labelled | `train_log_analysis.py` -> `log_analysis.json` (burst sizes of the whole-log incident detector) |
| `log_analysis/reference/`, `log_analysis/loghub/` (downloaded by `train_log_analysis.py`, SHA-256 checked) | Elastic's real Apache access logs (Apache 2.0) to set the web-scan level; LogHub 2k samples (16 systems) as outside test | `train_log_analysis.py` |
| `network/cicids2017_distrinet_dataset.zip` + `network_flows.csv.gz` (`download_network_data.py`, `prepare_network_data.py`; SHA-256 checked, git-ignored) | CIC-IDS2017 (Canadian Institute for Cybersecurity, UNB; cite Sharafaldin et al. 2018) re-processed and re-labelled by Engelen et al., KU Leuven (WTMC 2021): 2.1 million connections, Monday-Friday | `train_network_traffic.py` -> `network_traffic.json` (alert levels) + `network_flow.joblib` (supporting connection model) |
| `otrf/` (git clone, see `test_windows_rules.py`; git-ignored) | OTRF Security-Datasets (Open Threat Research Forge, MIT): real Windows Security / Sysmon / PowerShell logs recorded while 121 known attack techniques ran | `test_windows_rules.py` -> `windows_rules.json` (rule test results; the rules themselves are hand-written) |
| `indic/` (git clones, see `test_indic_scams.py`; git-ignored) | Real ordinary Hindi / Odia / Hinglish text: Universal Dependencies UD_Hindi-HDTB (CC BY-NC-SA 4.0), UD_Hindi-PUD and UD_Odia-ODTB (CC BY-SA), Google Hinglish-TOP (Apache-2.0) | `test_indic_scams.py` -> `indic_scams.json` (false alarms of the hand-written Hindi / Hinglish / Odia scam patterns; no training) |
| `malware/*_test.zip`, `challenge.zip` + `ember_scores.csv.gz` (`download_malware_data.py`, `calibrate_malware_model.py`; SHA-256 checked, git-ignored) | EMBER2024 (Joyce et al., KDD 2025; Hugging Face joyce8/EMBER2024 + joyce8/EMBER2024-benchmark-models, Apache-2.0): FEATURES of real files only - no programs | `EMBER2024_all.model` (the authors' LightGBM) + `malware_model.json` (CyberGuard's levels + test results) |
| `insider/r4.2.tar.bz2`, `answers.tar.bz2` + `insider_*.csv(.gz)`, `insider/demo/` (`download_insider_data.py`, `prepare_insider_data.py`, `make_insider_demo.py`; MD5 checked, git-ignored) | CERT Insider Threat Test Dataset r4.2 (CMU SEI CERT Division + ExactData, doi:10.1184/R1/12841247, KiltHub, CC BY 4.0; synthetic): 1,000 people, 70 insiders in 3 scenarios | `train_insider_risk.py` -> `insider_risk.joblib` + `insider_risk.json` (Insider Risk: exfiltration, abnormal activity, insider threat) |
| (Google Colab only - nothing stored on the PC) | ASVspoof 2019 LA (Edinburgh DataShare, ODC-By), MLAAD (CC BY-NC 4.0, optional), LibriSpeech dev/test-clean (CC BY 4.0), In-the-Wild (CC BY-SA 4.0, test only), SpeechBrain ECAPA + XLS-R 300M (Apache 2.0) | `docs/colab/CyberGuard_Voice_Colab.ipynb` -> `voice_ai.onnx/.json`, `voiceprint.onnx/.json`; In-the-Wild test: `docs/colab/CyberGuard_Voice_InTheWild_Kaggle.ipynb` -> `itw_results.json` -> `add_voice_itw_results.py` |
| `models/whisper-small/` (`fetch_whisper.py`, git-ignored) | Whisper small (OpenAI, MIT), faster-whisper conversion by Systran | speech-to-text for the voice scam check |
| `rba-dataset.csv` (optional, 9 GB) | Kaggle `dasgroup/rba-dataset` | only to retrain `ato_rba_model` (`train_ato_login.py`) or re-make the two subsets |

Training-only pip packages (not needed to run the app): `dnstwist` (look-alike domains), `wordfreq` (domain spoofing).

## Retraining (from `backend/`)
```bash
python -m app.ml.training.train_lookalike_domain
python -m app.ml.training.train_domain_spoofing
python -m app.ml.training.train_url_manipulation --data dephides/small_dataset/train.txt dephides/small_dataset/val.txt dephides/small_dataset/test.txt malicious_phish.csv
python -m app.ml.training.train_credential_subtopics
python -m app.ml.training.train_impersonation_router
# re-measure alert levels on 2026 links (no retraining; run again after retraining either model)
python -m app.ml.training.calibrate_url_manipulation
python -m app.ml.training.calibrate_url_domain
python -m app.ml.training.train_api_abuse --download   # once (~130 MB)
python -m app.ml.training.train_api_abuse
python -m app.ml.training.prepare_ait_logs --download   # once (3.4 GB)
python -m app.ml.training.prepare_ait_logs
python -m app.ml.training.train_log_analysis
python -I app\ml\training\download_network_data.py   # once (334 MB)
python -I app\ml\training\prepare_network_data.py
python -m app.ml.training.train_network_traffic
python -I app\ml\training\download_malware_data.py    # once (size printed first; features only)
python -I app\ml\training\calibrate_malware_model.py
python -I app\ml\training\download_insider_data.py   # once (4.8 GB)
python -I app\ml\training\prepare_insider_data.py    # about 40 min
python -I app\ml\training\train_insider_risk.py
python -I app\ml\training\make_insider_demo.py       # optional: real demo logs (about 40 min)
```
Every script prints its test results and writes `<model>.joblib` + `<model>.metrics.json` into `app/ml/models/`.
