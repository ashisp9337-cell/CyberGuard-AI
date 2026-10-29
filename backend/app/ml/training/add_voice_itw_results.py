r"""Add the In-the-Wild test results (itw_results.json from docs/colab/CyberGuard_Voice_InTheWild_Kaggle.ipynb) to the
installed AI-voice model's voice_ai.json.

Checks first, changes nothing if any check fails:
  * the results were made with THIS model: the SHA-256 in itw_results.json = voice_ai.json's onnx_sha256 = the SHA-256
    of the installed voice_ai.onnx;
  * they were judged at the same alert / check-carefully levels the app uses;
  * they are a real run (not the notebook's smoke test) and the numbers are complete and in range.
Only two entries of voice_ai.json "results" are added or replaced (plus a short "in_the_wild_test" note about how they
were measured); the model numbers are not touched. The file is replaced in one step, so it is never half-written.
From the backend folder (the downloaded file can stay in Downloads):
    python -I app\ml\training\add_voice_itw_results.py <your Downloads folder>\itw_results.json
"""
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.normpath(os.path.join(HERE, "..", "models"))
KEYS = ("In-the-Wild (real-world, outside test)", "In-the-Wild after WhatsApp-style Opus 16 kbps")
COUNTS = ("recordings", "real", "fake")
RATES = ("fake caught at alert", "fake caught at verify", "real flagged at alert (false alarms)",
         "real flagged at verify", "AUC", "EER")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def _check_result(name, r):
    if not isinstance(r, dict):
        raise ValueError(f"{name}: not a result")
    for k in COUNTS:
        if not isinstance(r.get(k), int) or isinstance(r.get(k), bool) or r[k] < 0:
            raise ValueError(f"{name}: '{k}' is missing or not a whole number")
    if r["recordings"] != r["real"] + r["fake"] or r["real"] == 0 or r["fake"] == 0:
        raise ValueError(f"{name}: needs real and deepfake recordings, and recordings = real + fake")
    for k in RATES:
        v = r.get(k)
        if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) or not 0 <= v <= 1:
            raise ValueError(f"{name}: '{k}' is missing or not between 0 and 1")


def merge(itw_path, models=MODELS):
    """-> the updated voice_ai.json content (already written). Raises ValueError with a plain reason on any problem."""
    onnx_path, json_path = os.path.join(models, "voice_ai.onnx"), os.path.join(models, "voice_ai.json")
    if not (os.path.isfile(onnx_path) and os.path.isfile(json_path)):
        raise ValueError(f"voice_ai.onnx and voice_ai.json must be installed in {models} first")
    with open(itw_path, encoding="utf-8") as f:
        itw = json.load(f)
    with open(json_path, encoding="utf-8") as f:
        meta = json.load(f)
    if not isinstance(itw, dict) or not isinstance(itw.get("results"), dict):
        raise ValueError(f"{os.path.basename(itw_path)} is not an itw_results.json from the In-the-Wild notebook")
    if itw.get("smoke_test") is not False:
        raise ValueError("these are smoke-test results, not a real run")
    installed = _sha256(onnx_path)
    if meta.get("onnx_sha256") != installed:
        raise ValueError("the installed voice_ai.onnx does not belong to voice_ai.json - copy both from the same run")
    if itw.get("model_onnx_sha256") != installed:
        raise ValueError("these results were made with a different voice_ai.onnx than the one installed")
    lv, mlv = itw.get("levels") or {}, meta.get("levels") or {}
    if lv.get("alert") != mlv.get("alert") or lv.get("verify") != mlv.get("verify"):
        raise ValueError("these results used different alert / check-carefully levels than the installed model")
    if KEYS[0] not in itw["results"]:
        raise ValueError(f"'{KEYS[0]}' is missing from the results")
    new = {k: itw["results"][k] for k in KEYS if k in itw["results"]}
    for k, r in new.items():
        _check_result(k, r)

    meta.setdefault("results", {}).update(new)
    ds = itw.get("dataset") or {}
    meta["in_the_wild_test"] = {
        "dataset": {k: ds[k] for k in ("repo", "file", "revision", "sha256", "licence") if k in ds},
        "labels_from": itw.get("labels_from"), "opus_test_recordings": itw.get("opus_test_recordings"),
        "scored_with": itw.get("onnx_provider"), "gpu_vs_cpu_largest_score_difference": itw.get("gpu_vs_cpu_largest_score_difference"),
        "tested_at": itw.get("tested_at"), "versions": itw.get("versions"),
    }
    tmp = json_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=1)                 # the same layout the notebook writes
        os.replace(tmp, json_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return meta


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python -I app\\ml\\training\\add_voice_itw_results.py <path to itw_results.json>")
    try:
        meta = merge(sys.argv[1])
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        sys.exit(f"Nothing was changed: {exc}")
    print("Added to voice_ai.json:")
    for k in KEYS:
        r = meta["results"].get(k)
        if r:
            print(f"  {k}: AUC {r['AUC']:.4f}, EER {r['EER']:.2%}, deepfakes caught at alert {r['fake caught at alert']:.1%}, "
                  f"real wrongly flagged at alert {r['real flagged at alert (false alarms)']:.1%} "
                  f"({r['real']:,} real + {r['fake']:,} deepfake recordings)")
    print("Check: python show_auc.py")


if __name__ == "__main__":
    main()
