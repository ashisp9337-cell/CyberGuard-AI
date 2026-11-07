"""2 Nov: the real-world voice classifier is installed only if it is better on the same test recordings, made for the
installed voice_ai.onnx, and compared with the classifier installed now; otherwise nothing changes."""
import copy
import hashlib
import json

import numpy as np
import pytest

onnx = pytest.importorskip("onnx")
pytest.importorskip("onnxruntime")

from app.ml.training import install_voice_head as I  # noqa: E402

DIM = 16


def _onnx(path):
    from onnx import TensorProto, helper, numpy_helper
    W = numpy_helper.from_array(np.random.default_rng(0).normal(size=(64, DIM)).astype(np.float32), "W")
    shape = numpy_helper.from_array(np.array([0, 1000, 64], np.int64), "shape")
    g = helper.make_graph([helper.make_node("Reshape", ["wav", "shape"], ["r"]),
                           helper.make_node("ReduceMean", ["r"], ["m"], axes=[1], keepdims=0),
                           helper.make_node("MatMul", ["m", "W"], ["feats"])], "g",
                          [helper.make_tensor_value_info("wav", TensorProto.FLOAT, ["batch", 64000])],
                          [helper.make_tensor_value_info("feats", TensorProto.FLOAT, ["batch", DIM])], [W, shape])
    onnx.save(helper.make_model(g, opset_imports=[helper.make_opsetid("", 13)], ir_version=8), str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _res(itw_fa, itw_auc=0.967, asv_auc=0.988, lab_auc=0.999, lab_fa=0.007):
    return {I.ITW: {"AUC": itw_auc, "EER": 0.087, "fake caught at alert": 0.9, I.FA: itw_fa},
            I.OPUS: {"AUC": 0.97, I.FA: itw_fa},
            I.ASV: {"AUC": asv_auc, I.FA: 0.02},
            I.LAB: {"AUC": lab_auc, I.FA: lab_fa}}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    models = tmp_path / "models"
    models.mkdir()
    sha = _onnx(models / "voice_ai.onnx")
    old = {"onnx_sha256": sha, "scaler_mean": [0.0] * DIM, "scaler_scale": [1.0] * DIM, "coef": [0.1] * DIM,
           "intercept": 0.0, "levels": {"alert": 0.6, "verify": 0.2}, "trained_at": "2026-10-25T19:08:02Z",
           "results": _res(0.238)}
    (models / "voice_ai.json").write_text(json.dumps(old))
    monkeypatch.setattr(I, "MODELS", str(models))
    new = copy.deepcopy(old)
    new.update(head_version=2, coef=[0.2] * DIM, levels={"alert": 0.8, "verify": 0.5}, trained_at="2026-11-02T00:00:00Z",
               results=_res(0.02), installed_head_same_test={"trained_at": old["trained_at"], "results": _res(0.238)})
    return models, new, tmp_path / "new"


def _write(folder, meta):
    folder.mkdir(exist_ok=True)
    (folder / "voice_ai.json").write_text(json.dumps(meta))
    return str(folder)


def _digest(models):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(models.iterdir())}


def test_better_classifier_is_installed_and_the_old_one_kept(setup):
    models, new, folder = setup
    assert I.main(["x", _write(folder, new)]) == 0
    assert json.loads((models / "voice_ai.json").read_text())["levels"]["alert"] == 0.8
    assert json.loads((models / "voice_ai.previous.json").read_text())["levels"]["alert"] == 0.6


@pytest.mark.parametrize("change", [
    {"results": _res(0.10)},                                   # still too many false alarms on real voices
    {"results": _res(0.02, itw_auc=0.95)},                     # real-world AUC dropped
    {"results": _res(0.02, asv_auc=0.96)},                     # ASVspoof got worse
    {"results": _res(0.02, lab_fa=0.05)},                      # more false alarms on studio speech
    {"smoke_test": True},                                      # the notebook's test run
    {"onnx_sha256": "0" * 64},                                 # made for another speech model
    {"installed_head_same_test": {"trained_at": "2026-01-01", "results": _res(0.238)}},   # compared with another one
    {"coef": [0.1] * (DIM - 1)},                               # does not fit the speech model
    {"levels": {"alert": 0.3, "verify": 0.5}},                 # invalid levels
])
def test_otherwise_nothing_changes(setup, change):
    models, new, folder = setup
    before = _digest(models)
    new.update(change)
    assert I.main(["x", _write(folder, new)]) in (2, 3)
    assert _digest(models) == before
