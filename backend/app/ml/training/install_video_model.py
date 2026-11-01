r"""Install a deepfake-video model trained on Kaggle (docs/colab/CyberGuard_Deepfake_Video_Kaggle.ipynb) - ONLY if it is
better than the one installed now. Nothing changes if any check fails.

Checks, in this order:
  1. the folder has deepfake_video.onnx + deepfake_video.json, the .json is a CyberGuard video-model description and
     comes from a real Kaggle run (not the notebook's tiny smoke test);
  2. the .onnx opens with onnxruntime, takes faces of the size the .json says and gives finite numbers;
  3. it is better than the installed model on the SAME test videos (the notebook scores the installed model on them
     when you attach it; otherwise the numbers saved in the installed .json are used):
       * DFDC (a dataset neither model trained on): AUC higher, false alarms at the alert level at most 3 points more
       * Celeb-DF test half B: AUC at most 0.01 lower, false alarms at the alert level at most 2 points more
Then the installed files are kept as deepfake_video.previous.onnx / .json and the new ones are copied in (each file is
replaced in one step). The app picks the new model up by itself - no restart needed.

From the backend folder (the downloaded files can stay where you saved them):
    python -I app\ml\training\install_video_model.py %USERPROFILE%\Downloads\cg_new_models
"""
import json
import math
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.normpath(os.path.join(HERE, "..", "models"))
KIND = "cyberguard-deepfake-video"
NAMES = ("deepfake_video.onnx", "deepfake_video.json")
MIN_TRAIN_FACES = 5000             # a real Kaggle run trains on tens of thousands of faces; the smoke test on ~300
DFDC, CDF = "test_dfdc_independent", "test_celebdf_half_B_honest"


def _num(r, key):
    v = (r or {}).get(key)
    return v if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)) else None


def check_new(folder):
    """-> (meta, problems). Problems is a list of reasons the new files cannot be used."""
    problems = []
    paths = [os.path.join(folder, n) for n in NAMES]
    for p in paths:
        if not os.path.isfile(p):
            problems.append(f"{os.path.basename(p)} is not in {folder}")
    if problems:
        return None, problems
    try:
        with open(paths[1], encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError) as e:
        return None, [f"deepfake_video.json cannot be read ({type(e).__name__})"]
    if meta.get("kind") != KIND:
        problems.append("deepfake_video.json is not a CyberGuard deepfake-video model description")
    for k in ("thr_alert", "thr_verify", "mean", "std", "input_size", "results"):
        if k not in meta:
            problems.append(f"deepfake_video.json has no '{k}'")
    if problems:
        return meta, problems
    if int((meta.get("training") or {}).get("faces", 0)) < MIN_TRAIN_FACES:
        problems.append("these files come from a test run of the notebook (too few training faces), not a real one")
    if not 0 < float(meta["thr_verify"]) <= float(meta["thr_alert"]) < 1:
        problems.append("the alert / verify levels in deepfake_video.json are not valid")
    res = meta["results"]
    for k in (DFDC, CDF):
        if _num(res.get(k), "auc") is None:
            problems.append(f"deepfake_video.json has no result for '{k}' (was DFDC attached in Kaggle?)")
    try:
        import numpy as np
        import onnxruntime as ort
        getattr(ort, "disable_telemetry_events", lambda: None)()
        sess = ort.InferenceSession(paths[0], providers=["CPUExecutionProvider"])
        size = int(meta["input_size"])
        out = sess.run(None, {sess.get_inputs()[0].name: np.zeros((2, 3, size, size), np.float32)})[0]
        if out.reshape(-1).shape[0] != 2 or not np.all(np.isfinite(out)):
            problems.append("deepfake_video.onnx does not give one finite score per face")
    except Exception as e:
        problems.append(f"deepfake_video.onnx cannot be run ({type(e).__name__}: {str(e)[:120]})")
    return meta, problems


def installed_results(new_meta):
    """The installed model's numbers on the same test videos: from the new .json if the notebook scored exactly the
    model installed now, else the installed .json's own saved results."""
    path = os.path.join(MODELS, NAMES[1])
    if not os.path.exists(path):
        return None, "no model installed"
    with open(path, encoding="utf-8") as f:
        old = json.load(f)
    same = new_meta.get("installed_model_same_test") or {}
    if same and same.get("trained_at") == old.get("trained_at"):
        return same, "installed model scored by the notebook on the same faces"
    return old.get("results") or {}, "installed model's saved results (same test lists)"


def decide(new_res, old_res):
    """-> (keep?, reasons)."""
    if old_res is None:
        return True, ["no model installed yet"]
    why, ok = [], True
    nd, od = new_res.get(DFDC), old_res.get(DFDC)
    nc, oc = new_res.get(CDF), old_res.get(CDF)
    if _num(od, "auc") is not None:
        if not _num(nd, "auc") > _num(od, "auc"):
            ok = False
            why.append(f"DFDC AUC not higher ({_num(od, 'auc')} -> {_num(nd, 'auc')})")
        fa_n, fa_o = _num(nd, "false_alarms_at_alert"), _num(od, "false_alarms_at_alert")
        if fa_n is not None and fa_o is not None and fa_n > fa_o + 0.03:
            ok = False
            why.append(f"more false alarms on real DFDC videos ({fa_o} -> {fa_n})")
    if _num(oc, "auc") is not None:
        if _num(nc, "auc") is None or _num(nc, "auc") < _num(oc, "auc") - 0.01:
            ok = False
            why.append(f"Celeb-DF AUC dropped too much ({_num(oc, 'auc')} -> {_num(nc, 'auc')})")
        fa_n, fa_o = _num(nc, "false_alarms_at_alert"), _num(oc, "false_alarms_at_alert")
        if fa_n is not None and fa_o is not None and fa_n > fa_o + 0.02:
            ok = False
            why.append(f"more false alarms on real Celeb-DF videos ({fa_o} -> {fa_n})")
    if ok:
        why.append(f"DFDC AUC {_num(od, 'auc')} -> {_num(nd, 'auc')}, Celeb-DF held "
                   f"({_num(oc, 'auc')} -> {_num(nc, 'auc')}), false alarms within the limits")
    return ok, why


def install(folder):
    for n in NAMES:
        cur = os.path.join(MODELS, n)
        if os.path.exists(cur):
            base, ext = os.path.splitext(n)
            shutil.copy2(cur, os.path.join(MODELS, f"{base}.previous{ext}"))
    for n in NAMES:                       # the .onnx first, then the .json (the app reloads when either changes)
        tmp = os.path.join(MODELS, n + ".new")
        shutil.copy2(os.path.join(folder, n), tmp)
        os.replace(tmp, os.path.join(MODELS, n))


def show(name, r):
    for k, label in ((CDF, "Celeb-DF test (half B)"), (DFDC, "DFDC (never trained on)"), ("test_ffpp_official_test", "FaceForensics++ test")):
        x = (r or {}).get(k)
        if x:
            print(f"  {name:10s} {label:26s} AUC {_num(x, 'auc')}  caught at alert {_num(x, 'caught_at_alert')}  "
                  f"false alarms at alert {_num(x, 'false_alarms_at_alert')}")


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    folder = os.path.abspath(argv[1])
    meta, problems = check_new(folder)
    if problems:
        print("NOT INSTALLED - nothing changed:")
        for p in problems:
            print("  -", p)
        return 2
    old, how = installed_results(meta)
    print(f"comparing with: {how}")
    show("installed", old)
    show("new", meta["results"])
    keep, why = decide(meta["results"], old)
    if not keep:
        print("NOT INSTALLED - not better on every count; nothing changed:")
        for w in why:
            print("  -", w)
        return 3
    install(folder)
    print("INSTALLED - " + "; ".join(why))
    print("old model kept as deepfake_video.previous.onnx / deepfake_video.previous.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
