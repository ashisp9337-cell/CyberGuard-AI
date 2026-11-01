"""1 Nov: a deepfake-video model from Kaggle is installed only if it is better than the installed one; a test-run model,
a broken file or a worse model changes nothing."""
import hashlib
import json

import pytest

onnx = pytest.importorskip("onnx")
pytest.importorskip("onnxruntime")

from app.ml.training import install_video_model as I  # noqa: E402


def _onnx(path, size=8):
    from onnx import TensorProto, helper
    x = helper.make_tensor_value_info("input", TensorProto.FLOAT, ["batch", 3, size, size])
    y = helper.make_tensor_value_info("logit", TensorProto.FLOAT, ["batch", 1])
    shape = helper.make_tensor("shape", TensorProto.INT64, [2], [-1, 1])
    g = helper.make_graph([helper.make_node("ReduceMean", ["input"], ["m"], axes=[1, 2, 3], keepdims=1),
                           helper.make_node("Reshape", ["m", "shape"], ["logit"])], "g", [x], [y], [shape])
    m = helper.make_model(g, opset_imports=[helper.make_opsetid("", 13)], ir_version=8)   # readable by any onnxruntime
    onnx.save(m, str(path))


def _model(folder, dfdc_auc, cdf_auc, faces=50000, trained="2026-11-01", fa=0.01):
    folder.mkdir(parents=True, exist_ok=True)
    _onnx(folder / "deepfake_video.onnx")
    r = lambda auc: {"auc": auc, "caught_at_alert": 0.5, "false_alarms_at_alert": fa}
    meta = {"kind": I.KIND, "version": 2, "thr_alert": 0.9, "thr_verify": 0.6, "mean": [0.5] * 3, "std": [0.5] * 3,
            "input_size": 8, "training": {"faces": faces}, "trained_at": trained,
            "results": {I.DFDC: r(dfdc_auc), I.CDF: r(cdf_auc)}}
    (folder / "deepfake_video.json").write_text(json.dumps(meta))
    return folder


def _digest(folder):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.iterdir())}


@pytest.fixture
def models(tmp_path, monkeypatch):
    m = _model(tmp_path / "models", dfdc_auc=0.72, cdf_auc=0.996, trained="2026-10-20")
    monkeypatch.setattr(I, "MODELS", str(m))
    return m


def test_a_better_model_is_installed_and_the_old_one_kept(tmp_path, models):
    new = _model(tmp_path / "new", dfdc_auc=0.80, cdf_auc=0.99)
    assert I.main(["x", str(new)]) == 0
    assert json.loads((models / "deepfake_video.json").read_text())["results"][I.DFDC]["auc"] == 0.80
    assert json.loads((models / "deepfake_video.previous.json").read_text())["trained_at"] == "2026-10-20"
    assert (models / "deepfake_video.previous.onnx").exists()


@pytest.mark.parametrize("dfdc,cdf,faces,fa", [(0.70, 0.996, 50000, 0.01),    # worse on DFDC
                                               (0.80, 0.97, 50000, 0.01),     # Celeb-DF dropped too much
                                               (0.80, 0.996, 50000, 0.08),    # many more false alarms
                                               (0.80, 0.996, 300, 0.01)])     # the notebook's smoke test
def test_otherwise_nothing_changes(tmp_path, models, dfdc, cdf, faces, fa):
    before = _digest(models)
    new = _model(tmp_path / "new", dfdc_auc=dfdc, cdf_auc=cdf, faces=faces, fa=fa)
    assert I.main(["x", str(new)]) in (2, 3)
    assert _digest(models) == before


def test_a_broken_onnx_is_refused(tmp_path, models):
    before = _digest(models)
    new = _model(tmp_path / "new", dfdc_auc=0.9, cdf_auc=0.999)
    (new / "deepfake_video.onnx").write_bytes(b"not a model")
    assert I.main(["x", str(new)]) == 2
    assert _digest(models) == before


def test_uses_the_notebooks_score_of_the_same_installed_model(tmp_path, models):
    new = _model(tmp_path / "new", dfdc_auc=0.80, cdf_auc=0.99)
    meta = json.loads((new / "deepfake_video.json").read_text())
    meta["installed_model_same_test"] = {"trained_at": "2026-10-20", I.DFDC: {"auc": 0.85}, I.CDF: {"auc": 0.996}}
    (new / "deepfake_video.json").write_text(json.dumps(meta))
    before = _digest(models)
    assert I.main(["x", str(new)]) == 3          # 0.80 is not better than 0.85 on the same faces
    assert _digest(models) == before
