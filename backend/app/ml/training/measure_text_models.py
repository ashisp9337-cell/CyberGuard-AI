r"""Measure the E-mail and SMS phishing models on the messages they never saw, and SAVE the results, so that
`python show_auc.py` shows them without --recalc. The models are only read - nothing is trained into them or changed.

For each model (app/ml/models/phishing_email.joblib, phishing_sms.joblib):
  1. The same 80 / 20 split its training script used (train_test_split, test_size 0.2, random_state 42, stratified).
  2. PROOF the 20% was never trained on: a fresh copy with the same settings is trained in memory on the 80% part only;
     it must give the saved model's scores on the 20% (to 1e-3). A model that had seen the 20% would differ a lot.
     If the proof fails, the numbers are saved under "results_unconfirmed" instead, so show_auc.py never shows them.
  3. AUC and the model's own catch / false-alarm rates at 50% on:
       heldout                 - the whole 20%
       heldout_unseen_texts    - only messages unlike any training message (lower-cased, links / numbers / e-mail
                                 addresses blanked) - no near-copies of training messages
     SMS also: heldout_real_only and heldout_real_unseen_texts - without the 3,500 template "modern transactional"
       legitimate messages that phishing_sms_clean_v2.tsv added (rows whose text is not in the original
       phishing_sms.tsv), so the main SMS number is on real messages only.
Writes app/ml/models/phishing_email.metrics.json and phishing_sms.metrics.json. About 1 minute. From backend/:
    python -I app\ml\training\measure_text_models.py
"""
import hashlib
import json
import os
import re
import sys
import time
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.normpath(os.path.join(HERE, "..", "models"))
DATA = os.path.join(HERE, "data")
MODELS_TO_MEASURE = [
    # (name, model file, data file, positive label, original file the template rows are found against)
    ("Email", "phishing_email.joblib", "phishing_email_real.tsv", "phishing", None),
    ("SMS", "phishing_sms.joblib", "phishing_sms_clean_v2.tsv", "phishing", "phishing_sms.tsv"),
]
SAME_MODEL_TOLERANCE = 1e-3


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def normalise(text):
    """Lower-case, links / e-mail addresses / numbers blanked, punctuation removed - two messages that differ only in an
    amount, a date, a phone number or a link count as the same text."""
    t = str(text).lower()
    t = re.sub(r"(https?://|www\.)\S+", " url ", t)
    t = re.sub(r"\S+@\S+\.\S+", " email ", t)
    t = re.sub(r"\d[\d,.:/-]*\d|\d", "0", t)          # 1,840 / 25/09 / 10:30 / 9876543210 -> 0
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return " ".join(t.split())


def read_tsv(path):
    import pandas as pd
    return pd.read_csv(path, sep="\t", header=None, names=["label", "text"]).dropna(subset=["text"])


def original_texts(path):
    """Texts of the original (uncleaned) SMS file; its few broken lines are skipped."""
    import pandas as pd
    df = pd.read_csv(path, sep="\t", header=None, names=["label", "text"], on_bad_lines="skip", engine="python", quoting=3)
    return set(df["text"].dropna().astype(str))


def rates(y, p, mask):
    import numpy as np
    from sklearn.metrics import roc_auc_score
    y, p = np.asarray(y)[mask], np.asarray(p)[mask]
    out = {"messages": int(len(y)), "scam": int(y.sum()), "genuine": int((y == 0).sum())}
    if 0 < y.sum() < len(y):
        out["auc"] = round(float(roc_auc_score(y, p)), 4)
        out["caught_at_50pct"] = round(float((p[y == 1] >= 0.5).mean()), 4)
        out["false_alarms_at_50pct"] = round(float((p[y == 0] >= 0.5).mean()), 4)
    return out


def measure(name, model_file, data_file, pos_label, original_file, models=MODELS, data=DATA):
    import joblib
    import numpy as np
    import sklearn
    from sklearn.base import clone
    from sklearn.model_selection import train_test_split
    mp, dp = os.path.join(models, model_file), os.path.join(data, data_file)
    for p in (mp, dp):
        if not os.path.isfile(p):
            raise FileNotFoundError(f"{os.path.basename(os.path.dirname(p))}/{os.path.basename(p)} is missing")
    df = read_tsv(dp)
    df["y"] = (df["label"] == pos_label).astype(int)
    x_tr, x_te, y_tr, y_te = train_test_split(df["text"], df["y"], test_size=0.2, random_state=42, stratify=df["y"])
    model = joblib.load(mp)
    p = model.predict_proba(x_te)[:, 1]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")                   # solver notices from the in-memory copy only
        fresh = clone(model).fit(x_tr, y_tr)
    diff = float(np.abs(fresh.predict_proba(x_te)[:, 1] - p).max())
    seen = {normalise(t) for t in x_tr}
    unseen = np.array([normalise(t) not in seen for t in x_te])
    allrows = np.ones(len(x_te), bool)
    results = {"heldout": rates(y_te, p, allrows), "heldout_unseen_texts": rates(y_te, p, unseen)}
    template_note = None
    if original_file:
        op = os.path.join(data, original_file)
        if os.path.isfile(op):
            orig = original_texts(op)
            real = np.array([str(t) in orig for t in x_te])
            added = df[~df["text"].astype(str).isin(orig)]
            template_note = (f"{len(added):,} rows of {data_file} are not in {original_file} (added template messages, "
                             f"labels {added['label'].value_counts().to_dict()}); {int((~real).sum())} of them are in the 20%")
            results["heldout_real_only"] = rates(y_te, p, real)
            results["heldout_real_unseen_texts"] = rates(y_te, p, real & unseen)
        else:
            template_note = f"{original_file} not found - real-only results not measured"
    return {
        "model": name, "model_file": model_file, "model_sha256": sha256(mp), "data_file": data_file,
        "data_sha256": sha256(dp), "data_rows": int(len(df)), "scam_rows": int(df["y"].sum()),
        "split": "train_test_split(test_size=0.2, random_state=42, stratify=label) - the split the training script used",
        "held_out_confirmed": diff <= SAME_MODEL_TOLERANCE,
        "held_out_check": (f"a copy trained on the 80% part only gives the saved model's scores on the 20% "
                           f"(largest difference {diff:.1e}; limit {SAME_MODEL_TOLERANCE:g})"),
        "template_rows": template_note,
        "results" if diff <= SAME_MODEL_TOLERANCE else "results_unconfirmed": results,
        "rates_note": "the model alone at 50%; the app also adds its rules and link checks",
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "versions": {"scikit-learn": sklearn.__version__, "python": sys.version.split()[0]},
    }


def save(metrics, models=MODELS):
    out = os.path.join(models, metrics["model_file"].replace(".joblib", ".metrics.json"))
    tmp = out + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=1)
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return out


def main():
    failed = False
    for spec in MODELS_TO_MEASURE:
        t0 = time.time()
        try:
            m = measure(*spec)
        except (OSError, ValueError) as exc:
            print(f"{spec[0]}: not measured - {exc}")
            failed = True
            continue
        out = save(m)
        print(f"\n{m['model']} ({m['model_file']}, {m['data_rows']:,} messages, {time.time() - t0:.0f}s)")
        print(f"  never trained on the 20%: {'CONFIRMED' if m['held_out_confirmed'] else 'NOT CONFIRMED'} - {m['held_out_check']}")
        if m["template_rows"]:
            print(f"  {m['template_rows']}")
        for k, r in (m.get("results") or m["results_unconfirmed"]).items():
            print(f"  {k:26s} {r['messages']:6,} messages ({r['scam']:,} scams): AUC {r.get('auc', float('nan')):.4f}  "
                  f"caught {r.get('caught_at_50pct', float('nan')):.1%}  false alarms {r.get('false_alarms_at_50pct', float('nan')):.1%}")
        print(f"  saved -> app/ml/models/{os.path.basename(out)}")
    print("\nCheck: python show_auc.py")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
