"""Builds docs/colab/CyberGuard_Voice_InTheWild_Kaggle.ipynb (run: python build_voice_itw_notebook.py).

Tests the ALREADY TRAINED AI-voice model (voice_ai.onnx + voice_ai.json) on the In-the-Wild dataset, exactly the way
the scanner on the PC scores a recording. Nothing is trained or changed. The audio code is copied word for word from
backend/app/detectors/voice_audio.py. SMOKE=1 (environment) runs it on a tiny fake zip on CPU - used only to test the
notebook before it is given to the user. Optional arguments: [voice_audio.py] [output .ipynb]."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIO_SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "backend", "app", "detectors", "voice_audio.py")
OUT_NB = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "CyberGuard_Voice_InTheWild_Kaggle.ipynb")
AUDIO_PY = open(AUDIO_SRC, encoding="utf-8").read()
assert "'''" not in AUDIO_PY

cells = []


def md(s):
    cells.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n")})


def code(s):
    cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": s.strip("\n")})


md(r"""
# CyberGuard - **Voice: In-the-Wild test** (Kaggle) - the honest real-world number for the AI-voice model

Tests the AI-voice model you already trained (`voice_ai.onnx` + `voice_ai.json`) on **In-the-Wild**: real and
deepfake recordings of 58 celebrities and politicians collected from the internet (Müller et al., *Does Audio
Deepfake Detection Generalize?*, Interspeech 2022; about 20.8 h real + 17.2 h deepfake). The model never saw any of
it. **Nothing is trained and the model is not changed** - this only measures it.

Every recording is scored **exactly like the scanner on your PC does it**: the same audio code (`voice_audio.py`,
copied in word for word), the same ONNX file, the same classifier numbers and the same alert / check-carefully levels.
A second test passes 3,000 of the recordings through WhatsApp-style Opus compression (16 kbps) first.

Output: **`itw_results.json`** (small) - you add it to `voice_ai.json` on your PC with one command.
`itw_scores.csv.gz` (every recording's score) is optional, for checking.

**Before you start**
1. Kaggle -> **Create -> New Notebook** -> **File -> Import Notebook** -> upload this `.ipynb`.
2. **The model files** - one of these:
   * **Add Input -> Your Work -> Notebooks** -> your voice training notebook (if its version finished and its
     *Output* tab shows `voice_ai.onnx`), **or**
   * **Add Input -> Upload -> New Dataset** -> upload `voice_ai.onnx` and `voice_ai.json` from your PC's
     `backend\app\ml\models\` folder, keep it **Private**, create it.
   The notebook finds them by itself and checks that they belong together (SHA-256).
3. Right panel -> **Session options**: **Accelerator: GPU T4 x2** (about 30-45 minutes; without a GPU it also
   works, about 3-4 hours), **Internet: On**.
4. *(Optional)* **Add-ons -> Secrets**: `HF_TOKEN` (the same Hugging Face *Read* token as before), ticked for this
   notebook. The dataset is public; the token only helps if Hugging Face asks for a login. It is never printed.
5. **Save Version -> Save & Run All (Commit)**. You can close the browser. Then open the version's **Output** tab
   and download `itw_results.json`.

**Data:** `mueller91/In-The-Wild` on Hugging Face (one zip, about 8.2 GB; licence shown there: CC BY-SA 4.0). The
zip is checked against its published SHA-256 and the audio is read straight out of it - nothing is unpacked.
""")

md("## 1. Settings")
code(r"""
import os, sys, glob, json, time, random, shutil, subprocess, hashlib, io, csv, posixpath, zipfile
from collections import Counter
import numpy as np
SMOKE = os.environ.get('SMOKE') == '1'          # only for testing this notebook on a tiny fake dataset
KAGGLE = os.path.isdir('/kaggle/working')
def _roomiest(paths):                                         # the 8 GB zip goes where there is most space
    ok = []
    for p in paths:
        try:
            os.makedirs(p, exist_ok=True); ok.append((shutil.disk_usage(p).free, p))
        except OSError:
            pass
    return max(ok)[1]
WORK = os.environ.get('CG_WORK') or (_roomiest(['/kaggle/temp/cg', '/tmp/cg']) if KAGGLE else '/content/cg')  # temporary
OUT = os.environ.get('CG_OUT') or ('/kaggle/working' if KAGGLE else '/content/cg_out')   # the result files
os.makedirs(WORK, exist_ok=True); os.makedirs(OUT, exist_ok=True)
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '1'
REPO, ZIP_NAME = 'mueller91/In-The-Wild', 'release_in_the_wild.zip'
OPUS_N = 20 if SMOKE else 3000          # recordings for the WhatsApp-style test
MAX_MEMBER = 200_000_000                # no single recording in the zip may be bigger than this (200 MB)
GPU_BATCH = int(os.environ.get('CG_GPU_BATCH', '16'))   # 4-second clips per GPU batch (about 2-3 GB of GPU memory)
SEED = 42
GPU = (not SMOKE) and shutil.which('nvidia-smi') is not None and \
      subprocess.run(['nvidia-smi', '-L'], capture_output=True).returncode == 0
print('SMOKE TEST' if SMOKE else 'REAL RUN', '| Kaggle' if KAGGLE else '| Colab/other', '| GPU' if GPU else '| no GPU (CPU)',
      '| work:', WORK, '| free disk:', round(shutil.disk_usage(WORK).free / 1e9), 'GB')
""")

md("## 2. Tools (fixed versions)")
code(r"""
if not SMOKE:
    pip = [sys.executable, '-m', 'pip', '-q']
    pyav = 'av==19.0.2' if sys.version_info >= (3, 12) else 'av==17.0.0'     # 19.x needs Python 3.12+ (same results)
    subprocess.run(pip + ['install', pyav, 'huggingface_hub', 'scikit-learn', 'pandas'], check=True)   # no upgrades
    ort_gpu = False
    if GPU:                     # onnxruntime-gpu 1.23.2 = CUDA 12 (Kaggle's PyTorch brings the CUDA 12 libraries)
        subprocess.run(pip + ['uninstall', '-y', 'onnxruntime'], check=False)
        ort_gpu = subprocess.run(pip + ['install', 'onnxruntime-gpu==1.23.2']).returncode == 0
    if not ort_gpu:
        subprocess.run(pip + ['install', 'onnxruntime==1.23.2'], check=True)
import av, sklearn, onnxruntime as ort
if 'CUDAExecutionProvider' in ort.get_available_providers():
    try:
        import torch                   # loads the CUDA / cuDNN libraries onnxruntime-gpu needs
    except Exception:
        try:
            ort.preload_dlls()
        except Exception as e:
            print('CUDA libraries not preloaded:', type(e).__name__)
print('PyAV', av.__version__, '| onnxruntime', ort.__version__, ort.get_available_providers(), '| scikit-learn', sklearn.__version__)
""")

md("## 3. The audio code (identical to CyberGuard's `voice_audio.py`)")
code("VOICE_AUDIO = r'''" + AUDIO_PY + "'''\n" + r"""
with open(os.path.join(WORK, 'voice_audio.py'), 'w', encoding='utf-8') as f:
    f.write(VOICE_AUDIO)
sys.path.insert(0, WORK)
import importlib, voice_audio as V
importlib.reload(V)
print('voice_audio ready: clips of', V.CLIP_S, 's at', V.SR, 'Hz, at most', V.MAX_CLIPS, 'clips per recording')
""")

md(r"""
## 4. Find and check the model files
`voice_ai.json` stores the SHA-256 of the `voice_ai.onnx` it was made with; both must match (the PC checks the same).
""")
code(r'''
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 22), b''):
            h.update(b)
    return h.hexdigest()

def find_model():
    if os.environ.get('CG_MODEL_DIR'):
        cands = [os.path.join(os.environ['CG_MODEL_DIR'], 'voice_ai.onnx')]
    else:
        cands = (glob.glob('/kaggle/input/**/voice_ai.onnx', recursive=True)
                 + glob.glob('/content/voice_ai.onnx') + glob.glob('/content/*/voice_ai.onnx')
                 + glob.glob('/content/*/*/voice_ai.onnx'))
    pairs, problems = {}, []
    for o in cands:
        j = os.path.join(os.path.dirname(o), 'voice_ai.json')
        if not (os.path.isfile(o) and os.path.isfile(j)):
            problems.append(f'{o}: voice_ai.json is not next to it'); continue
        with open(j, encoding='utf-8') as f:
            m = json.load(f)
        s = sha256_file(o)
        if m.get('onnx_sha256') != s:
            problems.append(f'{o}: does not belong to the voice_ai.json next to it'); continue
        pairs.setdefault(s, (o, m))
    for p in problems:
        print('skipped:', p)
    if not pairs:
        raise RuntimeError('voice_ai.onnx + voice_ai.json not found. Add them as Input (see the top of this notebook).')
    if len(pairs) > 1:
        raise RuntimeError('Different trained models were found - keep only one as Input: '
                           + ', '.join(p[0] for p in pairs.values()))
    s, (o, m) = next(iter(pairs.items()))
    return o, m, s

ONNX_PATH, META, MODEL_SHA = find_model()
if META.get('smoke_test') and not SMOKE:
    raise RuntimeError('This voice_ai.json comes from a smoke test, not from the real training run.')
LEVELS = META['levels']
ALERT, VERIFY = float(LEVELS['alert']), float(LEVELS['verify'])
MEAN, SCALE = np.asarray(META['scaler_mean']), np.asarray(META['scaler_scale'])
COEF, INTERCEPT = np.asarray(META['coef']), META['intercept']
print('model:', ONNX_PATH, '| SHA-256', MODEL_SHA[:16] + '...', '| trained', META.get('trained_at'))
print(f'alert level {ALERT:.4f} | check-carefully level {VERIFY:.4f} | layer {META.get("layer")}')
print('results already in voice_ai.json:', list(META.get('results', {})))

def clip_probs(feats):
    """the classifier on top of the speech features - the same formula as ai_voice_score() in app/detectors/voice.py"""
    z = (feats - MEAN) / SCALE
    return 1 / (1 + np.exp(-(z @ COEF + INTERCEPT)))

CPU_SESS = ort.InferenceSession(ONNX_PATH, providers=['CPUExecutionProvider'])
GPU_SESS = None
if 'CUDAExecutionProvider' in ort.get_available_providers():
    try:
        g = ort.InferenceSession(ONNX_PATH, providers=[('CUDAExecutionProvider', {'use_tf32': 0}), 'CPUExecutionProvider'])
        if g.get_providers()[0] == 'CUDAExecutionProvider':
            GPU_SESS = g
    except Exception as e:
        print('GPU session not available:', type(e).__name__, str(e)[:200])
print('GPU session ready (checked against the CPU below)' if GPU_SESS else 'running on the CPU, like the PC')
''')

md(r"""
## 5. Download In-the-Wild and check it
The exact file published on Hugging Face (its SHA-256 is compared after the download). About 8.2 GB; on Kaggle this
takes a few minutes.
""")
code(r'''
def hf_token():
    """Kaggle Secrets, Colab Secrets or the HF_TOKEN environment variable (never printed)."""
    try:
        from kaggle_secrets import UserSecretsClient
        return UserSecretsClient().get_secret('HF_TOKEN')
    except Exception:
        pass
    try:
        from google.colab import userdata
        return userdata.get('HF_TOKEN')
    except Exception:
        return os.environ.get('HF_TOKEN')

if SMOKE:
    ZIP = os.environ['CG_ITW_ZIP']
    DATASET = {'repo': 'SMOKE TEST (fake zip)', 'file': os.path.basename(ZIP), 'sha256': sha256_file(ZIP)}
else:
    from huggingface_hub import HfApi, hf_hub_download
    tok = hf_token() or None
    try:
        api = HfApi()
        REV = api.dataset_info(REPO, token=tok).sha
        pi = api.get_paths_info(REPO, [ZIP_NAME], repo_type='dataset', revision=REV, token=tok)[0]
        lfs = pi.lfs
        WANT_SHA = lfs.sha256 if hasattr(lfs, 'sha256') else lfs['sha256']
        WANT_SIZE = int(pi.size)
        need = WANT_SIZE + 1_000_000_000
        if shutil.disk_usage(WORK).free < need and not os.path.exists(os.path.join(WORK, 'itw', ZIP_NAME)):
            raise RuntimeError(f'not enough disk space in {WORK}: {need / 1e9:.1f} GB needed')
        t0 = time.time()
        ZIP = hf_hub_download(REPO, ZIP_NAME, repo_type='dataset', revision=REV, token=tok,
                              local_dir=os.path.join(WORK, 'itw'))
    except Exception as e:
        print('Download failed:', type(e).__name__, str(e)[:300])
        print('If it mentions 401 / 403 / gated: open https://huggingface.co/datasets/mueller91/In-The-Wild, log in, '
              'accept the terms if asked, add your HF_TOKEN secret (Add-ons -> Secrets), then run again.')
        raise
    size = os.path.getsize(ZIP)
    print(f'downloaded {size / 1e9:.2f} GB in {time.time() - t0:.0f}s - checking SHA-256 ...')
    got = sha256_file(ZIP)
    if size != WANT_SIZE or got != WANT_SHA:
        os.remove(ZIP)
        raise RuntimeError('The download is not the published file (size or SHA-256 differs) - it was deleted; run again.')
    print('SHA-256 matches the published file')
    DATASET = {'repo': REPO, 'file': ZIP_NAME, 'revision': REV, 'sha256': got, 'bytes': size,
               'licence': 'CC BY-SA 4.0 (Hugging Face dataset card)'}
''')

md(r"""
## 6. Read the labels (straight from the zip, nothing unpacked)
`meta.csv` lists every recording with its speaker and label (`bona-fide` = real, `spoof` = deepfake).
""")
code(r'''
ZF = zipfile.ZipFile(ZIP)
MEMBERS = {i.filename: i for i in ZF.infolist()
           if not i.is_dir() and '__MACOSX' not in i.filename and not posixpath.basename(i.filename).startswith('._')}

def itw_label(v):
    v = str(v).strip().lower()
    if v in ('spoof', 'fake', 'deepfake', '1'):
        return 1
    if v in ('bona-fide', 'bonafide', 'bona fide', 'real', 'genuine', '0'):
        return 0
    return None

ROWS, META_CSV, UNKNOWN, MISSING = [], None, Counter(), 0
for m in [n for n in MEMBERS if posixpath.basename(n).lower() == 'meta.csv']:
    rd = csv.DictReader(io.StringIO(ZF.read(MEMBERS[m]).decode('utf-8-sig')))
    cols = {c.strip().lower(): c for c in (rd.fieldnames or [])}
    fcol = cols.get('file') or cols.get('path') or cols.get('filename')
    lcol, scol = cols.get('label'), cols.get('speaker')
    if not (fcol and lcol):
        continue
    base = posixpath.dirname(m)
    rows, unknown, missing, seen = [], Counter(), 0, set()
    for r in rd:
        lab = itw_label(r[lcol])
        if lab is None:
            unknown[str(r[lcol])] += 1; continue
        name = posixpath.normpath(posixpath.join(base, str(r[fcol]).strip()))
        if name not in MEMBERS:
            missing += 1; continue
        if name in seen:
            continue
        seen.add(name)
        rows.append({'file': name, 'label': lab, 'speaker': str(r[scol]).strip() if scol else '?'})
    if len(rows) > len(ROWS):
        ROWS, META_CSV, UNKNOWN, MISSING = rows, m, unknown, missing
if not ROWS:                                                       # no meta.csv: labels as folder names (fake/ real/)
    for n in sorted(MEMBERS):
        if n.lower().endswith(('.wav', '.flac', '.mp3')):
            lab = next((itw_label(q) for q in reversed(n.lower().split('/')[:-1]) if itw_label(q) is not None), None)
            if lab is not None:
                ROWS.append({'file': n, 'label': lab, 'speaker': '?'})
    META_CSV = 'folder names'
if not ROWS:
    raise RuntimeError('No labelled recordings found. Files in the zip: ' + ', '.join(sorted(MEMBERS)[:15]))
print(f'labels from {META_CSV}: {sum(1 - r["label"] for r in ROWS):,} real + {sum(r["label"] for r in ROWS):,} deepfake '
      f'recordings, {len({r["speaker"] for r in ROWS})} speakers')
if UNKNOWN or MISSING:
    print(f'not used: {sum(UNKNOWN.values())} rows with an unknown label {dict(UNKNOWN.most_common(5))}, '
          f'{MISSING} rows whose file is not in the zip')
''')

md(r"""
## 7. Score every recording - exactly like the PC
recording -> 16 kHz mono, silent ends trimmed -> up to 15 clips of 4 s -> ONNX speech model -> classifier ->
**the recording's score = the average of its clips**. Recordings with less than 1 second of speech get no score on the
PC either ("could not be judged"); they are counted, not hidden. If a GPU is used, it is first checked to give the
same scores as the CPU (the PC runs on the CPU).
""")
code(r'''
def read_speech(row, mode):
    info = MEMBERS[row['file']]
    if info.file_size > MAX_MEMBER:
        raise ValueError('too big')
    x = V.speech(ZF.read(info))                         # the zip checks each file's CRC while reading
    if mode == 'opus16':
        x = V.codec_roundtrip(x, 'opus', 16000)
    return x

def score_rows(rows, mode, name, sess, batch, flush_at):
    """-> (score per recording (nan = no score), clips per recording). flush_at=1 and batch=4 is exactly the PC's way
    (each recording on its own, 4 clips at a time); on the GPU many recordings share one batch."""
    sums, n = np.zeros(len(rows)), np.zeros(len(rows), int)
    buf, owner = [], []
    def flush():
        if buf:
            X = np.stack(buf).astype(np.float32)
            f = np.concatenate([sess.run(None, {'wav': X[k:k + batch]})[0] for k in range(0, len(X), batch)])
            np.add.at(sums, owner, clip_probs(f)); buf.clear(); owner.clear()
    t0 = time.time()
    for i, r in enumerate(rows):
        try:
            cl = V.clips(read_speech(r, mode))
        except Exception:
            cl = []
        n[i] = len(cl); buf.extend(cl); owner.extend([i] * len(cl))
        if len(buf) >= flush_at:
            flush()
        if i and i % 2000 == 0:
            el = time.time() - t0
            print(f'  {name}: {i:,} / {len(rows):,} recordings ({el / 60:.0f} min, about {el / i * (len(rows) - i) / 60:.0f} min left)', flush=True)
    flush()
    s = np.full(len(rows), np.nan); ok = n > 0
    s[ok] = sums[ok] / n[ok]
    return s, n

SESS, BATCH, FLUSH_AT, PROVIDER, GPU_DIFF = CPU_SESS, 4, 1, 'CPUExecutionProvider', None
if GPU_SESS is not None:
    probe = random.Random(SEED).sample(ROWS, min(40, len(ROWS)))
    try:
        a, _ = score_rows(probe, 'eval', 'CPU check', CPU_SESS, 4, 1)
        b, _ = score_rows(probe, 'eval', 'GPU check', GPU_SESS, GPU_BATCH, 2 * GPU_BATCH)
        ok = ~np.isnan(a)
        GPU_DIFF = float(np.max(np.abs(a[ok] - b[ok]))) if ok.any() else None
        if GPU_DIFF is not None and GPU_DIFF < 0.002:
            SESS, BATCH, FLUSH_AT, PROVIDER = GPU_SESS, GPU_BATCH, 2 * GPU_BATCH, 'CUDAExecutionProvider'
        print(f'GPU vs CPU on {int(ok.sum())} recordings: largest score difference {GPU_DIFF}')
    except Exception as e:
        print('GPU check failed:', type(e).__name__, str(e)[:200])
print('scoring with', PROVIDER)

t0 = time.time()
SCORES, NCLIPS = score_rows(ROWS, 'eval', 'In-the-Wild', SESS, BATCH, FLUSH_AT)
print(f'In-the-Wild: {len(ROWS):,} recordings, {int(NCLIPS.sum()):,} clips, {int((NCLIPS == 0).sum())} without a score, '
      f'{(time.time() - t0) / 60:.0f} min')
OPUS_IDX = sorted(random.Random(SEED).sample(range(len(ROWS)), min(OPUS_N, len(ROWS))))
t0 = time.time()
OPUS_SCORES, OPUS_NCLIPS = score_rows([ROWS[i] for i in OPUS_IDX], 'opus16', 'Opus 16 kbps', SESS, BATCH, FLUSH_AT)
print(f'Opus test: {len(OPUS_IDX):,} recordings, {(time.time() - t0) / 60:.0f} min')
''')

md(r"""
## 8. Results
Same measures as the training notebook: **AUC** (1.0 = perfect ranking), **EER** (missed fakes = false alarms),
deepfakes caught and real recordings wrongly flagged at the **alert** and **check-carefully** levels the PC uses.
""")
code(r'''
from sklearn.metrics import roc_auc_score, roc_curve

def eer(y, s):
    fpr, tpr, _ = roc_curve(y, s); fnr = 1 - tpr
    i = np.nanargmin(np.abs(fnr - fpr)); return float((fpr[i] + fnr[i]) / 2)

def summarize(s, y, speakers):
    ok = ~np.isnan(s); s, y = s[ok], y[ok]
    r = {'recordings': int(len(y)), 'real': int((y == 0).sum()), 'fake': int((y == 1).sum())}
    if (y == 1).any():
        r['fake caught at alert'] = round(float((s[y == 1] >= ALERT).mean()), 4)
        r['fake caught at verify'] = round(float((s[y == 1] >= VERIFY).mean()), 4)
    if (y == 0).any():
        r['real flagged at alert (false alarms)'] = round(float((s[y == 0] >= ALERT).mean()), 4)
        r['real flagged at verify'] = round(float((s[y == 0] >= VERIFY).mean()), 4)
    if (y == 0).any() and (y == 1).any():
        r['AUC'] = round(float(roc_auc_score(y, s)), 4); r['EER'] = round(eer(y, s), 4)
    r['not scored (unreadable or under 1 s of speech)'] = int((~ok).sum())
    r['speakers'] = len(set(np.asarray(speakers)[ok]))
    return r

Y = np.asarray([r['label'] for r in ROWS]); SPK = [r['speaker'] for r in ROWS]
RESULTS = {
    'In-the-Wild (real-world, outside test)': summarize(SCORES, Y, SPK),
    'In-the-Wild after WhatsApp-style Opus 16 kbps': summarize(OPUS_SCORES, Y[OPUS_IDX], [SPK[i] for i in OPUS_IDX]),
}
for k, v in RESULTS.items():
    print(f'\n{k}'); [print(f'   {a}: {b}') for a, b in v.items()]
''')

md(r"""
## 9. Save
* **`itw_results.json`** -> download it (Output tab; it can stay in Downloads) and run, from your `backend` folder:
  `python -I app\ml\training\add_voice_itw_results.py <your Downloads folder>\itw_results.json` - it checks that
  the results belong to your installed model and adds them to `voice_ai.json`. Then `python show_auc.py` shows them
  and every voice scan explains the model with the In-the-Wild numbers.
* `itw_scores.csv.gz` - every recording's score (optional, only for checking).
""")
code(r'''
import gzip
out = {
    'what': 'CyberGuard AI-voice model tested on In-the-Wild, scored exactly like app/detectors/voice.py',
    'model_onnx_sha256': MODEL_SHA, 'levels': LEVELS, 'model_trained_at': META.get('trained_at'),
    'dataset': DATASET, 'labels_from': META_CSV, 'opus_test_recordings': len(OPUS_IDX), 'seed': SEED,
    'onnx_provider': PROVIDER, 'gpu_vs_cpu_largest_score_difference': GPU_DIFF,
    'results': RESULTS, 'smoke_test': SMOKE, 'tested_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'versions': {'python': sys.version.split()[0], 'onnxruntime': ort.__version__, 'av': av.__version__,
                 'scikit-learn': sklearn.__version__},
}
with open(os.path.join(OUT, 'itw_results.json'), 'w', encoding='utf-8') as f:
    json.dump(out, f, indent=1)
opus = dict(zip(OPUS_IDX, OPUS_SCORES))
with gzip.open(os.path.join(OUT, 'itw_scores.csv.gz'), 'wt', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['file', 'speaker', 'label', 'score', 'clips', 'score_after_opus16'])
    for i, r in enumerate(ROWS):
        w.writerow([r['file'], r['speaker'], 'deepfake' if r['label'] else 'real',
                    '' if np.isnan(SCORES[i]) else round(float(SCORES[i]), 5), int(NCLIPS[i]),
                    '' if i not in opus or np.isnan(opus[i]) else round(float(opus[i]), 5)])
ZF.close()
for fn in ('itw_results.json', 'itw_scores.csv.gz'):
    print(f'{fn:20s} {os.path.getsize(os.path.join(OUT, fn)) / 1e3:8.1f} KB')
print('Kaggle: download itw_results.json from the Output tab of this version.' if KAGGLE else 'Files are in ' + OUT)
''')

nb = {"cells": cells, "metadata": {"accelerator": "GPU", "kernelspec": {"display_name": "Python 3", "name": "python3"},
                                    "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 0}
with open(OUT_NB, "w", encoding="utf-8") as fh:
    json.dump(nb, fh, indent=1, ensure_ascii=False)
print("cells:", len(cells))
