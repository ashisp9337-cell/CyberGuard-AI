# Training data

These are small, real, publicly-available demo datasets checked in so the
training pipeline runs out of the box. They are **not** sufficient for a
production phishing/security product — swap them out before relying on
this for real users.

## `phishing_text_sample.tsv`
The classic UCI SMS Spam Collection (ham/spam, 5,574 messages), used here
as a stand-in for phishing-style message text (many "spam" messages in this
set already contain phishing/scam patterns: urgency, prize claims, premium-
rate callbacks, credential/payment requests).

**For production**, replace with a real labeled phishing corpus, e.g.:
- Nazario Phishing Corpus (monkey.org)
- IWSPA-AP shared task datasets
- Your own labeled corpus of confirmed phishing emails/SMS + legitimate mail

## `malicious_url_sample.csv`
A 5,000-URL stratified sample (2,500 good / 2,500 bad) drawn from the public
"Using Machine Learning to Detect Malicious URLs" dataset (faizann24), which
aggregates benign URLs and known-malicious URLs from public blocklists.

**For production**, replace/augment with:
- PhishTank verified phishing feed
- OpenPhish feed
- URLhaus (abuse.ch) — also wired up live via `ThreatIntelService`

## Retraining
```bash
cd backend
python -m app.ml.training.train_phishing
python -m app.ml.training.train_url
```
Both scripts print full metrics (accuracy/precision/recall/F1/ROC-AUC +
confusion matrix) and save `model.joblib` + `vectorizer.joblib` (or
`pipeline.joblib`) into `app/ml/models/`.
