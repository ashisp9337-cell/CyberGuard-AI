# Training data

Datasets used by the CURRENT models. Big downloaded datasets are git-ignored (see `.gitignore`);
put them back in this folder to retrain.

| File | Source | Used by (training script -> model) |
|---|---|---|
| `tranco_*-1m.csv.zip` | Tranco top-1M list (tranco-list.eu) | `train_url_domain.py` -> `url_domain_model`, `train_lookalike_domain.py` -> `lookalike_domain`, `train_domain_spoofing.py` -> `domain_spoofing` |
| `phiusiil+phishing+url+dataset.zip` | PhiUSIIL Phishing URL Dataset (UCI) | `train_url_domain.py`, `train_lookalike_domain.py` (test only), `train_domain_spoofing.py` |
| `dephides/small_dataset/*.txt` (not kept here, 45 MB) | DEPHIDES, github.com/ebubekirbbr/dephides (PhishTank + CommonCrawl, MIT) | `train_url_manipulation.py` -> `url_manipulation` |
| `malicious_phish.csv` (not kept here, 45 MB) | Kaggle `sid321axn/malicious-urls-dataset` | `train_url_manipulation.py` (second source) |
| `phishing_email_real.tsv` | real phishing / legitimate emails | `train_phishing.py` -> `phishing_email` |
| `phishing_text_sample.tsv` | UCI SMS Spam Collection | `train_phishing.py` (default) -> `phishing_pipeline` (fallback text model) |
| `phishing_sms.tsv`, `phishing_sms_clean_v2.tsv` | SMS phishing corpus | `train_sms_phishing.py` -> `phishing_sms`; impersonation retraining |
| `social_media_phishing.csv`, `youtube+spam+collection.zip` | social-media scam text, UCI YouTube Spam | `train_social_media_phishing.py` -> `phishing_social` |
| `brand_impersonation.csv`, `financial_institution_impersonation.csv`, `government_official_impersonation.csv`, `senior_management_impersonation.csv`, `teacher_university_impersonation.csv` | impersonation message sets | the `train_*_impersonation.py` scripts / `retrain_impersonation_real.py` |
| `known_contact_scams_real.tsv` | real reported 'Hi Mum, new number' / friend scam messages, each with its source link | `train_impersonation_router.py` -> `impersonation_router`; tests of the known-contact scam-script check |
| `financial_institutions.json` | bank / institution directory | used at run time by `financial_impersonation.py` and the email pipeline |
| `rba_accounts_subset.csv.gz`, `rba_ip_subset.csv.gz` | RBA login dataset (Wiefling et al.), made by `extract_rba_subsets.py` | `train_credential_subtopics.py` -> `cred_*` |
| `rba-dataset.csv` (optional, 9 GB) | Kaggle `dasgroup/rba-dataset` | only to retrain `ato_rba_model` (`train_ato_login.py`) or re-make the two subsets |

Training-only pip packages (not needed to run the app): `dnstwist` (look-alike domains), `wordfreq` (domain spoofing).

## Retraining (from `backend/`)
```bash
python -m app.ml.training.train_lookalike_domain
python -m app.ml.training.train_domain_spoofing
python -m app.ml.training.train_url_manipulation --data dephides/small_dataset/train.txt dephides/small_dataset/val.txt dephides/small_dataset/test.txt malicious_phish.csv
python -m app.ml.training.train_credential_subtopics
python -m app.ml.training.train_impersonation_router
```
Every script prints its test results and writes `<model>.joblib` + `<model>.metrics.json` into `app/ml/models/`.
