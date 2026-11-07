r"""Install the new AI-voice classifier (voice_ai.json from docs/colab/CyberGuard_Voice_RealWorld_Kaggle.ipynb) - ONLY if
it is better than the installed one. voice_ai.onnx is not touched (the notebook keeps it unchanged). Nothing changes
if any check fails.

Checks, in this order:
  1. the file is a real Kaggle run (not the notebook's smoke test), made for THIS voice_ai.onnx (same SHA-256 as the
     installed voice_ai.json and the installed voice_ai.onnx file), with valid numbers and levels;
  2. it was compared in the notebook with exactly the classifier installed now (same trained_at);
  3. it works: the installed voice_ai.onnx + the new classifier give a score between 0 and 1;
  4. it is better on the SAME test recordings (each at its own levels):
       * In-the-Wild, celebrities never used for training: real voices wrongly flagged at alert at most 5% and at
         least 2 points fewer than now; AUC at most 0.005 lower; EER at most 0.005 higher
       * ASVspoof 2019 eval and MLAAD held-out + LibriSpeech test-clean: AUC at most 0.01 lower; real voices wrongly
         flagged at alert at most 1 point more
       * In-the-Wild after WhatsApp-style compression: AUC at most 0.01 lower
Then the installed voice_ai.json is kept as voice_ai.previous.json and the new one is copied in (one step). The app
picks it up by itself - no restart needed.

From the backend folder:
    python -I app\ml\training\install_voice_head.py %USERPROFILE%\Downloads\cg_new_voice
"""
import hashlib
import json
import math
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.normpath(os.path.join(HERE, "..", "models"))
ITW = "In-the-Wild (real-world, outside test)"
OPUS = "In-the-Wild after WhatsApp-style Opus 16 kbps"
ASV = "ASVspoof 2019 eval (11 of 13 attacks unseen)"
LAB = "MLAAD held-out English systems + LibriSpeech test-clean real"
FA = "real flagged at alert (false alarms)"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def _num(r, k):
    v = (r or {}).get(k)
    return v if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)) else None


def check(new, old, onnx_path):
    """-> list of reasons the new classifier cannot be used (empty = usable)."""
    p = []
    if new.get("smoke_test"):
        p.append("this voice_ai.json comes from a test run of the notebook, not a real one")
    if new.get("head_version") != 2:
        p.append("this voice_ai.json is not from the real-world voice notebook (CyberGuard_Voice_RealWorld_Kaggle)")
    if not new.get("onnx_sha256") or new.get("onnx_sha256") != old.get("onnx_sha256"):
        p.append("it was made for a different voice_ai.onnx than the one installed")
    elif _sha256(onnx_path) != new["onnx_sha256"]:
        p.append("the installed voice_ai.onnx is not the file this voice_ai.json was made for")
    n = len(old.get("coef") or [])
    for k in ("scaler_mean", "scaler_scale", "coef"):
        v = new.get(k)
        if not isinstance(v, list) or len(v) != n or not all(isinstance(x, (int, float)) and math.isfinite(x) for x in v):
            p.append(f"'{k}' is missing or does not fit the speech model")
    if not all(x > 0 for x in new.get("scaler_scale") or [0]):
        p.append("'scaler_scale' has zero or negative values")
    if not isinstance(new.get("intercept"), (int, float)) or not math.isfinite(new["intercept"]):
        p.append("'intercept' is missing")
    lv = new.get("levels") or {}
    if not (isinstance(lv.get("alert"), (int, float)) and isinstance(lv.get("verify"), (int, float))
            and 0 < lv["verify"] <= lv["alert"] < 1):
        p.append("the alert / check-carefully levels are not valid")
    same = new.get("installed_head_same_test") or {}
    if same.get("trained_at") != old.get("trained_at"):
        p.append("it was compared with a different classifier than the one installed now - run the notebook again "
                 "with your current voice_ai.onnx + voice_ai.json as Input")
    for k in (ITW, ASV, LAB):
        if _num((new.get("results") or {}).get(k), "AUC") is None or _num((same.get("results") or {}).get(k), "AUC") is None:
            p.append(f"no result for '{k}'")
    return p


def works(new, onnx_path):
    """The installed speech model + the new classifier give a score in [0, 1] for a short test sound."""
    import numpy as np
    import onnxruntime as ort
    getattr(ort, "disable_telemetry_events", lambda: None)()
    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    t = np.arange(64000) / 16000.0
    wav = (0.1 * np.sin(2 * np.pi * 150 * t) + 0.01 * np.random.default_rng(0).normal(size=t.size)).astype(np.float32)
    feats = sess.run(None, {"wav": wav[None]})[0]
    z = (feats - np.asarray(new["scaler_mean"])) / np.asarray(new["scaler_scale"])
    s = 1 / (1 + np.exp(-(z @ np.asarray(new["coef"]) + new["intercept"])))
    return bool(np.all(np.isfinite(s)) and np.all((s >= 0) & (s <= 1)))


def decide(new, old):
    """-> (keep?, reasons)."""
    n, o = new["results"], new["installed_head_same_test"]["results"]
    why, ok = [], True
    ni, oi = n[ITW], o[ITW]
    if _num(ni, FA) is None or _num(ni, FA) > 0.05 or _num(ni, FA) > (_num(oi, FA) or 0) - 0.02:
        ok = False
        why.append(f"In-the-Wild real voices wrongly flagged: {_num(oi, FA)} -> {_num(ni, FA)} (needs at most 5% and 2 points fewer)")
    if _num(ni, "AUC") < _num(oi, "AUC") - 0.005:
        ok = False
        why.append(f"In-the-Wild AUC dropped ({_num(oi, 'AUC')} -> {_num(ni, 'AUC')})")
    if _num(ni, "EER") is not None and _num(oi, "EER") is not None and _num(ni, "EER") > _num(oi, "EER") + 0.005:
        ok = False
        why.append(f"In-the-Wild EER rose ({_num(oi, 'EER')} -> {_num(ni, 'EER')})")
    for k in (ASV, LAB):
        if _num(n[k], "AUC") < _num(o[k], "AUC") - 0.01:
            ok = False
            why.append(f"{k}: AUC dropped too much ({_num(o[k], 'AUC')} -> {_num(n[k], 'AUC')})")
        if _num(n[k], FA) is not None and _num(o[k], FA) is not None and _num(n[k], FA) > _num(o[k], FA) + 0.01:
            ok = False
            why.append(f"{k}: more real voices wrongly flagged ({_num(o[k], FA)} -> {_num(n[k], FA)})")
    if OPUS in n and OPUS in o and _num(n[OPUS], "AUC") is not None and _num(o[OPUS], "AUC") is not None \
            and _num(n[OPUS], "AUC") < _num(o[OPUS], "AUC") - 0.01:
        ok = False
        why.append(f"after WhatsApp-style compression: AUC dropped ({_num(o[OPUS], 'AUC')} -> {_num(n[OPUS], 'AUC')})")
    if ok:
        why.append(f"In-the-Wild real voices wrongly flagged {_num(oi, FA)} -> {_num(ni, FA)}, "
                   f"AUC {_num(oi, 'AUC')} -> {_num(ni, 'AUC')}; the other tests held")
    return ok, why


def show(label, res):
    for k, name in ((ITW, "In-the-Wild (unseen people)"), (OPUS, "  same, WhatsApp-style"), (ASV, "ASVspoof 2019 eval"),
                    (LAB, "MLAAD + LibriSpeech")):
        r = res.get(k)
        if r:
            print(f"  {label:10s} {name:28s} AUC {_num(r, 'AUC')}  fakes caught at alert {_num(r, 'fake caught at alert')}  "
                  f"real wrongly flagged at alert {_num(r, FA)}")


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    folder = os.path.abspath(argv[1])
    new_path = os.path.join(folder, "voice_ai.json")
    cur_json, cur_onnx = os.path.join(MODELS, "voice_ai.json"), os.path.join(MODELS, "voice_ai.onnx")
    for path, what in ((new_path, "the new voice_ai.json"), (cur_json, "the installed voice_ai.json"),
                       (cur_onnx, "the installed voice_ai.onnx")):
        if not os.path.isfile(path):
            print(f"NOT INSTALLED - {what} was not found ({path}); nothing changed")
            return 2
    try:
        with open(new_path, encoding="utf-8") as f:
            new = json.load(f)
        with open(cur_json, encoding="utf-8") as f:
            old = json.load(f)
    except (OSError, ValueError) as e:
        print(f"NOT INSTALLED - a voice_ai.json cannot be read ({type(e).__name__}); nothing changed")
        return 2
    problems = check(new, old, cur_onnx)
    if not problems:
        try:
            if not works(new, cur_onnx):
                problems.append("the new classifier does not give a valid score with the installed voice_ai.onnx")
        except Exception as e:
            problems.append(f"test score failed ({type(e).__name__}: {str(e)[:120]})")
    if problems:
        print("NOT INSTALLED - nothing changed:")
        for p in problems:
            print("  -", p)
        return 2
    print("comparing on the same test recordings (each classifier at its own levels):")
    show("installed", new["installed_head_same_test"]["results"])
    show("new", new["results"])
    keep, why = decide(new, old)
    if not keep:
        print("NOT INSTALLED - not better on every count; nothing changed:")
        for w in why:
            print("  -", w)
        return 3
    shutil.copy2(cur_json, os.path.join(MODELS, "voice_ai.previous.json"))
    tmp = cur_json + ".new"
    shutil.copy2(new_path, tmp)
    os.replace(tmp, cur_json)
    print("INSTALLED - " + "; ".join(why))
    print(f"new levels: alert {new['levels']['alert']:.4f}, check carefully {new['levels']['verify']:.4f} "
          f"(were {old['levels']['alert']:.4f} / {old['levels']['verify']:.4f})")
    print("old classifier kept as voice_ai.previous.json (voice_ai.onnx unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
