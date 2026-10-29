"""In-the-Wild voice test: the merge script that adds its results to voice_ai.json, and the Kaggle notebook builder."""
import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

from app.ml.training import add_voice_itw_results as M

HERE = os.path.dirname(os.path.abspath(__file__))
BUILDER = os.path.join(HERE, "..", "..", "docs", "colab", "build_voice_itw_notebook.py")
AUDIO = os.path.join(HERE, "..", "app", "detectors", "voice_audio.py")
LEVELS = {"alert": 0.6040378093363481, "verify": 0.2189429649987808, "rule": "alert: 1%; verify: 5%"}
ITW_KEY, OPUS_KEY = M.KEYS


def _result(real=1000, fake=600, auc=0.91):
    return {"recordings": real + fake, "real": real, "fake": fake, "fake caught at alert": 0.62,
            "fake caught at verify": 0.81, "real flagged at alert (false alarms)": 0.03, "real flagged at verify": 0.09,
            "AUC": auc, "EER": 0.16, "not scored (unreadable or under 1 s of speech)": 4, "speakers": 58}


@pytest.fixture
def models(tmp_path):
    onnx = tmp_path / "voice_ai.onnx"
    onnx.write_bytes(b"not a real model, only bytes to hash")
    sha = hashlib.sha256(onnx.read_bytes()).hexdigest()
    meta = {"model": "x", "onnx_sha256": sha, "coef": [0.5, -0.25], "intercept": 3.45, "levels": LEVELS,
            "results": {"val": {"AUC": 0.9987}, "ASVspoof 2019 eval (11 of 13 attacks unseen)": {"AUC": 0.9883}},
            "trained_at": "2026-10-25T19:08:02Z"}
    (tmp_path / "voice_ai.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return tmp_path, sha, meta


def _itw(tmp_path, sha, **change):
    d = {"model_onnx_sha256": sha, "levels": dict(LEVELS), "smoke_test": False, "onnx_provider": "CUDAExecutionProvider",
         "dataset": {"repo": "mueller91/In-The-Wild", "file": "release_in_the_wild.zip", "sha256": "ab" * 32,
                     "licence": "CC BY-SA 4.0 (Hugging Face dataset card)", "bytes": 8_160_000_000},
         "results": {ITW_KEY: _result(), OPUS_KEY: _result(1900, 1100, 0.88)}, "tested_at": "2026-10-27T10:00:00Z"}
    d.update(change)
    p = tmp_path / "itw_results.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    return p


def test_results_are_added_and_nothing_else_changes(models):
    tmp, sha, before = models
    raw_before = (tmp / "voice_ai.json").read_text(encoding="utf-8")
    meta = M.merge(_itw(tmp, sha), str(tmp))
    saved = json.loads((tmp / "voice_ai.json").read_text(encoding="utf-8"))
    assert saved == meta
    assert saved["results"][ITW_KEY]["AUC"] == 0.91 and saved["results"][OPUS_KEY]["AUC"] == 0.88
    assert list(saved["results"])[:2] == list(before["results"])                    # old results kept, in order
    for k in ("onnx_sha256", "coef", "intercept", "levels", "trained_at"):        # the model itself untouched
        assert saved[k] == before[k]
    assert saved["in_the_wild_test"]["dataset"]["repo"] == "mueller91/In-The-Wild"
    assert "bytes" not in saved["in_the_wild_test"]["dataset"]
    assert raw_before.startswith('{\n "model"')                                   # same layout as the notebook writes
    assert (tmp / "voice_ai.json").read_text(encoding="utf-8").startswith('{\n "model"')
    assert not (tmp / "voice_ai.json.tmp").exists()
    M.merge(_itw(tmp, sha), str(tmp))                                             # running it twice is harmless
    assert json.loads((tmp / "voice_ai.json").read_text(encoding="utf-8")) == saved


@pytest.mark.parametrize("change, reason", [
    ({"model_onnx_sha256": "0" * 64}, "different voice_ai.onnx"),
    ({"smoke_test": True}, "smoke-test"),
    ({"levels": {"alert": 0.5, "verify": 0.2189429649987808}}, "different alert"),
    ({"results": {OPUS_KEY: _result()}}, "missing"),
    ({"results": {ITW_KEY: dict(_result(), AUC=1.7)}}, "AUC"),
    ({"results": {ITW_KEY: dict(_result(), recordings=5)}}, "recordings = real + fake"),
    ({"results": {ITW_KEY: dict(_result(), fake=0, recordings=1000)}}, "real and deepfake"),
    ({"results": {ITW_KEY: dict(_result(), EER=float("nan"))}}, "EER"),
])
def test_wrong_or_incomplete_results_change_nothing(models, change, reason):
    tmp, sha, _ = models
    raw = (tmp / "voice_ai.json").read_bytes()
    with pytest.raises(ValueError, match=re.escape(reason)):
        M.merge(_itw(tmp, sha, **change), str(tmp))
    assert (tmp / "voice_ai.json").read_bytes() == raw


def test_a_model_that_does_not_match_its_json_is_refused(models):
    tmp, sha, _ = models
    (tmp / "voice_ai.onnx").write_bytes(b"another model")
    raw = (tmp / "voice_ai.json").read_bytes()
    with pytest.raises(ValueError, match="does not belong"):
        M.merge(_itw(tmp, sha), str(tmp))
    assert (tmp / "voice_ai.json").read_bytes() == raw


def test_missing_model_files_are_said_plainly(tmp_path):
    p = _itw(tmp_path, "0" * 64)
    with pytest.raises(ValueError, match="must be installed"):
        M.merge(p, str(tmp_path / "nothing_here"))


def test_show_auc_reads_the_merged_numbers(models, monkeypatch):
    tmp, sha, _ = models
    M.merge(_itw(tmp, sha), str(tmp))
    sys.path.insert(0, os.path.join(HERE, ".."))
    import show_auc
    monkeypatch.setattr(show_auc, "MODELS", str(tmp))
    row = next(items for _, sub, items, _ in show_auc.ROWS if sub == "Voice: AI / cloned voice")
    got = {path[-2]: show_auc.saved(file, *path) for _, file, *path in row}
    assert got[ITW_KEY] == 0.91 and got[OPUS_KEY] == 0.88


@pytest.mark.skipif(not os.path.isfile(BUILDER), reason="docs/colab is not next to the backend here")
def test_kaggle_notebook_builds_and_contains_the_app_audio_code_word_for_word(tmp_path):
    out = tmp_path / "itw.ipynb"
    subprocess.run([sys.executable, "-I", BUILDER, AUDIO, str(out)], check=True, capture_output=True)
    nb = json.loads(out.read_text(encoding="utf-8"))
    code = [c["source"] for c in nb["cells"] if c["cell_type"] == "code"]
    for k, src in enumerate(code):
        compile(src, f"cell{k}", "exec")                                          # every cell is valid Python
    with open(AUDIO, encoding="utf-8") as f:
        assert f.read() in code[2]
    joined = "\n".join(code)
    assert "1 / (1 + np.exp(-(z @ COEF + INTERCEPT)))" in joined                  # the app's classifier formula
    assert "HF_TOKEN" in joined and "print(tok" not in joined and "print(hf_token" not in joined
    assert "extractall" not in joined                                             # audio is read from the zip
