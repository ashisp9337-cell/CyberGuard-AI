"""Builds docs/colab/CyberGuard_Voice_Colab.ipynb (cells below; the shared audio code is copied in word for word)."""
import json
import sys

AUDIO_PY = open(sys.argv[1], encoding="utf-8").read()
OUT = sys.argv[2]
assert "'''" not in AUDIO_PY

cells = []


def md(s):
    cells.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n")})


def code(s):
    cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": s.strip("\n")})


md(r"""
# CyberGuard - **Voice** models (Kaggle or Google Colab): AI-voice / clone detector + voiceprint

Trains the models behind **Deepfake -> Voice & Audio Analysis**. Output: **4 files** for your PC.

| File | What it is |
|---|---|
| `voice_ai.onnx` | speech model (XLS-R 300M, frozen, cut after the best layer) - runs on the PC's CPU |
| `voice_ai.json` | the small classifier on top + alert levels + **every honest test result** |
| `voiceprint.onnx` | speaker voiceprint model (SpeechBrain ECAPA, VoxCeleb) for "is this really my contact?" |
| `voiceprint.json` | the voice-match level + its test results |

**How the AI-voice detector works** (research: frozen large speech models + a simple classifier generalise far better
than models trained from scratch - Pascu et al. 2023): every recording -> 16 kHz mono, silent ends trimmed -> 4-second
clips -> XLS-R speech features (averaged over time) -> logistic regression -> the recording's score is the average of its
clips. Training clips are randomly passed through phone / messenger codecs (Opus = WhatsApp, MP3, AAC, phone band) -
real **and** fake alike, so compression can never be the shortcut.

**Data** (all public; nothing large is stored on your PC)
* **Train / validation:** ASVspoof 2019 LA (Edinburgh DataShare, ODC-By; 2019-era TTS and voice-conversion attacks
  A01-A06) + MLAAD English (many modern TTS / cloning systems; CC BY-NC 4.0, *optional*: needs your free Hugging Face
  token) + LibriSpeech train-clean-100 / dev-clean real speech (CC BY 4.0).
* **Tests, never trained on:** ASVspoof 2019 LA **eval** (13 attack systems, 11 of them unseen), MLAAD systems held
  out by model, LibriSpeech test-clean (real speakers never seen -> false alarms),
  **In-the-Wild** (real vs deepfake recordings of 58 celebrities and politicians from the internet, CC BY-SA 4.0 on
  Hugging Face) - the honest real-world test - and In-the-Wild after WhatsApp-style Opus compression.

**Before you start - Kaggle** (recommended: a "Save & Run All" run keeps going even if you close the browser)
1. Right panel -> *Session options*: **Accelerator: GPU T4 x2**, **Internet: On** (needs a phone-verified account).
2. *(Optional, recommended)* accept MLAAD's terms on https://huggingface.co/datasets/mueller91/MLAAD and make a *Read*
   token; then *Add-ons -> Secrets -> Add Secret*: label `HF_TOKEN`, value = the token, and tick it for this notebook.
   Without it, MLAAD is skipped and everything else still runs.
3. **Save Version -> Save & Run All (Commit)**. About 3.5-5 hours (you can close the browser). Then open the version's
   **Output** tab and download the 4 files.

**Or Google Colab:** *Runtime -> Change runtime type -> T4 GPU*; token in the **key icon (Secrets)** as `HF_TOKEN`
with *Notebook access* on; *Runtime -> Run all*; the last cell downloads the 4 files. Your token is never printed.
""")

md("## 1. Settings and GPU check")
code(r"""
import os, sys, glob, json, time, random, shutil, subprocess, hashlib, math, re
import numpy as np
SMOKE = os.environ.get('SMOKE') == '1'          # only for testing this notebook on a tiny fake dataset
KAGGLE = os.path.isdir('/kaggle/working')
def _roomiest(paths):                                         # big temporary files go where there is most space
    ok = []
    for p in paths:
        try:
            os.makedirs(p, exist_ok=True); ok.append((shutil.disk_usage(p).free, p))
        except OSError:
            pass
    return max(ok)[1]
WORK = os.environ.get('CG_WORK') or (_roomiest(['/kaggle/temp/cg', '/tmp/cg']) if KAGGLE else '/content/cg')  # temporary
OUT = os.environ.get('CG_OUT') or ('/kaggle/working' if KAGGLE else '/content/cg_out')   # the 4 result files
os.makedirs(WORK, exist_ok=True); os.makedirs(OUT, exist_ok=True)
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '1'                 # one progress line per 1,000 files instead of a flood
SEED = 42
random.seed(SEED); np.random.seed(SEED)
print('SMOKE TEST' if SMOKE else 'REAL RUN', '| Kaggle' if KAGGLE else '| Colab/other', '| work:', WORK, '| free disk:', round(shutil.disk_usage(WORK).free / 1e9), 'GB')
if not SMOKE:
    r = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total', '--format=csv,noheader'], capture_output=True, text=True)
    assert r.returncode == 0, 'No GPU: Runtime -> Change runtime type -> T4 GPU, then Run all again'
    print('GPU:', r.stdout.strip())
""")

md("## 2. Tools (fixed versions, the same ones this notebook was tested with)")
code(r"""
if not SMOKE:
    pyav = 'av==19.0.2' if sys.version_info >= (3, 12) else 'av==17.0.0'     # 19.x needs Python 3.12+ (same results)
    subprocess.run([sys.executable, '-m', 'pip', '-q', 'install', 'transformers==5.20.2', 'speechbrain==1.1.2',
                    pyav, 'onnx', 'onnxruntime', 'onnxscript', 'huggingface_hub', 'scikit-learn'], check=True)
import torch, transformers, speechbrain, av, onnxruntime, sklearn
DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'
print('torch', torch.__version__, '| transformers', transformers.__version__, '| speechbrain', speechbrain.__version__,
      '| PyAV', av.__version__, '| onnxruntime', onnxruntime.__version__, '| device', DEVICE)
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
## 4. Data
Every download is checked; anything optional that fails is reported and skipped, never silently.
""")
code(r'''
def run(cmd):
    print('$', ' '.join(cmd) if isinstance(cmd, list) else cmd)
    subprocess.run(cmd, check=True, shell=isinstance(cmd, str))

def fetch(urls, dest, min_bytes):
    """Download with resume (wget -c), trying each mirror; checks the size."""
    if os.path.exists(dest) and os.path.getsize(dest) >= min_bytes:
        return dest
    for u in urls:
        try:
            run(['wget', '-q', '-c', '--tries=3', '-O', dest + '.part', u])
            if os.path.getsize(dest + '.part') >= min_bytes:
                os.replace(dest + '.part', dest)
                return dest
            print('  too small, trying the next mirror')
        except subprocess.CalledProcessError:
            print('  failed, trying the next mirror')
        if os.path.exists(dest + '.part') and os.path.getsize(dest + '.part') < 1e6:
            os.remove(dest + '.part')
    raise RuntimeError(f'Could not download {os.path.basename(dest)} - run this cell again')

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
''')

md("### 4a. ASVspoof 2019 LA (required, 7.1 GB)")
code(r'''
def smoke_audio(path, fake, seed, seconds=None):
    """SMOKE only: a fake 'voice' (harmonics + noise) so the pipeline can run without real data."""
    import soundfile as sf
    r = np.random.default_rng(seed)
    sec = seconds or r.uniform(2.0, 6.0)
    t = np.arange(int(V.SR * sec)) / V.SR
    f0 = r.uniform(90, 220)
    s = sum(np.sin(2 * np.pi * f0 * k * t + r.uniform(0, 6)) / k for k in range(1, 8))
    s *= 0.5 + 0.5 * np.sin(2 * np.pi * r.uniform(2, 5) * t) ** 2
    s += r.normal(0, 0.02 if fake else 0.2, t.size)
    sil = np.zeros(int(V.SR * r.uniform(0.1, 0.6)))
    sf.write(path, (0.2 * np.concatenate([sil, s, sil]) / np.abs(s).max()).astype(np.float32), V.SR)

LA = os.path.join(WORK, 'LA')
if SMOKE and not os.path.isdir(LA):
    import soundfile as sf
    os.makedirs(os.path.join(LA, 'ASVspoof2019_LA_cm_protocols'))
    for split, sysids, tag in (('train', ['A01', 'A02'], 'trn'), ('dev', ['A01', 'A02'], 'trl'), ('eval', ['A07', 'A16'], 'trl')):
        d = os.path.join(LA, f'ASVspoof2019_LA_{split}', 'flac'); os.makedirs(d)
        lines = []
        for i in range(40):
            fake = i % 2 == 1
            name = f'LA_{split[0].upper()}_{i:07d}'
            smoke_audio(os.path.join(d, name + '.flac'), fake, hash((split, i)) % 10000)
            lines.append(f'LA_{i % 5:04d} {name} - {sysids[i % 2] if fake else "-"} {"spoof" if fake else "bonafide"}')
        open(os.path.join(LA, 'ASVspoof2019_LA_cm_protocols', f'ASVspoof2019.LA.cm.{split}.{tag}.txt'), 'w').write('\n'.join(lines) + '\n')
elif not os.path.isdir(os.path.join(LA, 'ASVspoof2019_LA_train')):
    z = fetch(['https://datashare.ed.ac.uk/bitstream/handle/10283/3336/LA.zip',
               'https://datashare.is.ed.ac.uk/bitstream/handle/10283/3336/LA.zip'], os.path.join(WORK, 'LA.zip'), 7.0e9)
    run(['unzip', '-q', '-o', z, '-d', WORK])
    os.remove(z)                                                     # free 7 GB

def la_protocol(split):
    tag = 'trn' if split == 'train' else 'trl'
    rows = []
    for line in open(os.path.join(LA, 'ASVspoof2019_LA_cm_protocols', f'ASVspoof2019.LA.cm.{split}.{tag}.txt')):
        p = line.split()
        if len(p) == 5:
            path = os.path.join(LA, f'ASVspoof2019_LA_{split}', 'flac', p[1] + '.flac')
            rows.append({'path': path, 'label': int(p[4] == 'spoof'), 'system': p[3] if p[3] != '-' else 'bonafide',
                         'group': 'asvspoof19', 'speaker': p[0]})
    assert rows and all(os.path.exists(r['path']) for r in rows[:50]), f'ASVspoof {split} files missing'
    return rows

LA_ROWS = {s: la_protocol(s) for s in ('train', 'dev', 'eval')}
for s, rows in LA_ROWS.items():
    print(f'ASVspoof 2019 LA {s}: {sum(1 - r["label"] for r in rows):,} real, {sum(r["label"] for r in rows):,} fake, '
          f'systems {sorted({r["system"] for r in rows} - {"bonafide"})}')
''')

md("### 4b. LibriSpeech real speech (train-clean-100 + dev-clean for training/validation, test-clean for tests and voiceprint)")
code(r'''
def librispeech(part):
    root = os.path.join(WORK, 'LibriSpeech', part)
    if SMOKE and not os.path.isdir(root):
        for spk in range(8):
            d = os.path.join(root, str(100 + spk), '1'); os.makedirs(d)
            for u in range(6):
                smoke_audio(os.path.join(d, f'{100 + spk}-1-{u:04d}.flac'), False, 1000 + spk * 10 + u)
    elif not os.path.isdir(root):
        z = fetch([f'https://www.openslr.org/resources/12/{part}.tar.gz', f'https://us.openslr.org/resources/12/{part}.tar.gz',
                   f'https://openslr.elda.org/resources/12/{part}.tar.gz'], os.path.join(WORK, part + '.tar.gz'), 3.0e8)
        run(['tar', '-xzf', z, '-C', WORK]); os.remove(z)
    rows = [{'path': p, 'label': 0, 'system': 'bonafide', 'group': 'librispeech', 'speaker': p.split(os.sep)[-3]}
            for p in sorted(glob.glob(os.path.join(root, '*', '*', '*.flac')))]
    assert rows, f'LibriSpeech {part} has no audio'
    print(f'LibriSpeech {part}: {len(rows):,} recordings, {len({r["speaker"] for r in rows})} speakers')
    return rows

LS_DEV, LS_TEST = librispeech('dev-clean'), librispeech('test-clean')
LS_TRAIN = librispeech('train-clean-100')      # 251 more real speakers for training (6.3 GB) - balances the many fakes
''')

md(r"""
### 4c. MLAAD - modern TTS / voice-cloning systems (optional; needs `HF_TOKEN` and the dataset's *Agree* click)
Only the folders needed are listed (never the whole dataset): the English systems, then up to `PER_MODEL` clips of
each. English systems are split **by system** into train / validation / test, so the test systems were never seen.
Downloads run 64 at a time; if they take longer than `MLAAD_MAX_MINUTES`, training continues with what arrived.
""")
code(r'''
MLAAD = []
PER_MODEL = 6 if SMOKE else 140          # 143 English systems x 140 = about 20,000 recordings
MLAAD_MAX_MINUTES = 120
if not SMOKE:
    tok = hf_token()
    if not tok:
        print('No HF_TOKEN secret - MLAAD skipped (the model is then trained on ASVspoof 2019 only).')
    else:
        try:
            from huggingface_hub import HfApi, hf_hub_download
            from huggingface_hub.hf_api import RepoFolder
            from concurrent.futures import ThreadPoolExecutor, as_completed
            api = HfApi(token=tok)
            REPO = 'mueller91/MLAAD'
            def ls(path):
                """One folder only (not the whole dataset): -> (folders, audio files)."""
                items = list(api.list_repo_tree(REPO, path_in_repo=path or None, repo_type='dataset', recursive=False))
                return ([i.path for i in items if isinstance(i, RepoFolder)],
                        [i.path for i in items if not isinstance(i, RepoFolder)
                         and i.path.lower().endswith(('.wav', '.flac', '.mp3'))])
            t0 = time.time()
            root_dirs, _ = ls('')
            fake = next((d for d in root_dirs if d.rstrip('/').split('/')[-1] == 'fake'), None)
            if fake is None:                                       # e.g. a version folder first: look one level down
                for d in root_dirs:
                    sub, _ = ls(d)
                    fake = next((s for s in sub if s.rstrip('/').split('/')[-1] == 'fake'), None)
                    if fake:
                        break
            assert fake, f'no "fake" folder found; top level: {root_dirs[:10]}'
            langs_found, _ = ls(fake)
            en = next((l for l in langs_found if l.rstrip('/').split('/')[-1] == 'en'), None)
            assert en, f'no English folder; languages: {[l.split("/")[-1] for l in langs_found]}'
            systems, _ = ls(en)
            print(f'MLAAD: {len(systems)} English systems found under {en} ({time.time() - t0:.0f}s)', flush=True)
            rng = random.Random(SEED)
            pick = []
            for s in sorted(systems):
                sub, files = ls(s)
                if not files and sub:                              # audio one folder deeper
                    files = [f for d in sub[:3] for f in ls(d)[1]]
                files = sorted(files); rng.shuffle(files)
                pick += [(s.rstrip('/').split('/')[-1], f) for f in files[:PER_MODEL]]
            print(f'MLAAD: downloading {len(pick):,} files from {len(systems)} systems ({time.time() - t0:.0f}s) ...', flush=True)
            local = os.path.join(WORK, 'mlaad')
            def _get(sf):
                p = os.path.join(local, sf[1])
                if os.path.exists(p) and os.path.getsize(p) > 0:   # already here (an earlier run)
                    return p
                try:
                    return hf_hub_download(REPO, sf[1], repo_type='dataset', token=tok, local_dir=local)
                except Exception:
                    return None
            got, t1, stopped = {}, time.time(), False
            ex = ThreadPoolExecutor(64)
            futs = {ex.submit(_get, sf): sf for sf in pick}
            try:
                for k, fu in enumerate(as_completed(futs), 1):
                    if not fu.cancelled():                             # a cancelled (never started) download is skipped
                        got[futs[fu]] = fu.result()
                    if k % 1000 == 0:
                        print(f'  MLAAD: {k:,} / {len(pick):,} files ({(time.time() - t1) / 60:.0f} min)', flush=True)
                    if not stopped and time.time() - t1 > MLAAD_MAX_MINUTES * 60:
                        stopped = True
                        for f2 in futs:
                            f2.cancel()                                 # queued downloads are dropped, running ones finish
                        print(f'  MLAAD: time limit reached - continuing with the files already downloaded', flush=True)
            finally:
                ex.shutdown(wait=True, cancel_futures=True)     # no download keeps running after this cell
            for (system, f) in pick:
                p = got.get((system, f))
                if p and os.path.exists(p):
                    MLAAD.append({'path': p, 'label': 1, 'system': system, 'group': 'mlaad', 'lang': 'en', 'speaker': system})
            print(f'MLAAD: {len(MLAAD):,} of {len(pick):,} files downloaded ({(time.time() - t0) / 60:.0f} min)')
        except Exception as e:                                     # optional source: never stop the run
            print('MLAAD skipped:', type(e).__name__, str(e)[:300])
            MLAAD = []
else:
    for m in [f'tts_model_{i}' for i in range(7)]:
        d = os.path.join(WORK, 'mlaad', 'fake', 'en', m); os.makedirs(d, exist_ok=True)
        for u in range(PER_MODEL):
            p = os.path.join(d, f'{m}_{u}.wav'); smoke_audio(p, True, hash((m, u)) % 10000)
            MLAAD.append({'path': p, 'label': 1, 'system': m, 'group': 'mlaad', 'lang': 'en', 'speaker': m})
print(f'MLAAD used: {len(MLAAD):,} fake recordings, {len({r["system"] for r in MLAAD})} English systems')
''')

md("### 4d. In-the-Wild (outside test only - never used for training or choosing anything)")
code(r'''
ITW = []
def itw_label(v):
    v = str(v).strip().lower()
    if v in ('spoof', 'fake', 'deepfake', '1'):
        return 1
    if v in ('bona-fide', 'bonafide', 'bona fide', 'real', 'genuine', '0'):
        return 0
    return None

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 22), b''):
            h.update(b)
    return h.hexdigest()

def safe_unzip(zpath, dest):
    """Unpack a downloaded zip; no name inside it may point outside `dest` (no absolute paths, no '..')."""
    import zipfile
    root = os.path.realpath(dest)
    with zipfile.ZipFile(zpath) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        for i in infos:
            if not os.path.realpath(os.path.join(root, i.filename)).startswith(root + os.sep):
                raise RuntimeError(f'unsafe name in the zip: {i.filename!r}')
        need = sum(i.file_size for i in infos) + 1_000_000_000
        if shutil.disk_usage(root).free < need:
            raise RuntimeError(f'not enough disk space to unpack it ({need / 1e9:.1f} GB needed)')
        z.extractall(root)

# the dataset is ONE zip (release_in_the_wild.zip, about 8.2 GB): download, check its SHA-256, unpack, delete the zip
itw_root, zpath = os.path.join(WORK, 'itw'), None
os.makedirs(itw_root, exist_ok=True)
if SMOKE:
    import zipfile
    d = os.path.join(WORK, 'itw_smoke'); os.makedirs(d, exist_ok=True)
    lines = ['file,speaker,label']
    for i in range(30):
        smoke_audio(os.path.join(d, f'{i}.wav'), i % 3 == 0, 5000 + i)
        lines.append(f'{i}.wav,Person {i % 4},{"spoof" if i % 3 == 0 else "bona-fide"}')
    open(os.path.join(d, 'meta.csv'), 'w').write('\n'.join(lines) + '\n')
    zpath = os.path.join(WORK, 'release_in_the_wild.zip')            # packed like the real download
    with zipfile.ZipFile(zpath, 'w') as z:
        for f in sorted(os.listdir(d)):
            z.write(os.path.join(d, f), 'release_in_the_wild/' + f)
elif not glob.glob(os.path.join(itw_root, '**', 'meta.csv'), recursive=True):
    try:
        from huggingface_hub import HfApi, hf_hub_download
        tok = hf_token() or None
        pi = HfApi().get_paths_info('mueller91/In-The-Wild', ['release_in_the_wild.zip'], repo_type='dataset', token=tok)[0]
        want = pi.lfs.sha256 if hasattr(pi.lfs, 'sha256') else pi.lfs['sha256']
        zpath = hf_hub_download('mueller91/In-The-Wild', 'release_in_the_wild.zip', repo_type='dataset', token=tok,
                                local_dir=os.path.join(WORK, 'itw_zip'))
        if sha256_file(zpath) != want:
            os.remove(zpath)
            raise RuntimeError('the download is not the published file (SHA-256 differs) - deleted')
    except Exception as e:
        zpath = None
        print('In-the-Wild download failed:', type(e).__name__, str(e)[:300])
if zpath:
    try:
        safe_unzip(zpath, itw_root)
        print('In-the-Wild unpacked')
    except Exception as e:
        print('In-the-Wild could not be unpacked:', type(e).__name__, str(e)[:300])
    if not SMOKE:
        os.remove(zpath)                                                 # free 8 GB
if glob.glob(os.path.join(itw_root, '**', '*'), recursive=True):
    import pandas as pd
    metas = [p for p in glob.glob(os.path.join(itw_root, '**', '*.csv'), recursive=True)]
    for m in metas:
        df = pd.read_csv(m)
        cols = {c.lower(): c for c in df.columns}
        if 'label' in cols and ('file' in cols or 'path' in cols or 'filename' in cols):
            fcol = cols.get('file') or cols.get('path') or cols.get('filename')
            for _, r in df.iterrows():
                lab = itw_label(r[cols['label']])
                p = os.path.join(os.path.dirname(m), str(r[fcol]))
                if lab is not None and os.path.exists(p):
                    ITW.append({'path': p, 'label': lab, 'system': 'itw', 'group': 'itw',
                                'speaker': str(r[cols['speaker']]) if 'speaker' in cols else '?'})
            if ITW:
                print('In-the-Wild labels from', os.path.relpath(m, itw_root)); break
    if not ITW:                                                        # parquet layout: audio bytes + label column
        for pq in sorted(glob.glob(os.path.join(itw_root, '**', '*.parquet'), recursive=True)):
            t = pd.read_parquet(pq)
            lab_col = next((c for c in t.columns if c.lower() in ('label', 'labels', 'class', 'is_fake')), None)
            if lab_col is None or 'audio' not in t.columns:
                continue
            names = None
            try:
                import pyarrow.parquet as papq
                feats = json.loads(papq.read_schema(pq).metadata[b'huggingface'])['info']['features']
                names = feats[lab_col].get('names')
            except Exception:
                pass
            d = os.path.join(WORK, 'itw_wav'); os.makedirs(d, exist_ok=True)
            for i, r in t.iterrows():
                v = r[lab_col]
                lab = itw_label(names[int(v)] if names and str(v).isdigit() else v)
                a = r['audio']
                b = a.get('bytes') if isinstance(a, dict) else None
                if lab is None or not b:
                    continue
                p = os.path.join(d, f'{os.path.basename(pq)}_{i}.wav'); open(p, 'wb').write(b)
                ITW.append({'path': p, 'label': lab, 'system': 'itw', 'group': 'itw', 'speaker': '?'})
    if not ITW:                                                        # labels as folder names (fake/ real/)
        for p in glob.glob(os.path.join(itw_root, '**', '*'), recursive=True):
            if not p.lower().endswith(('.wav', '.flac', '.mp3')):
                continue
            parts = [q.lower() for q in os.path.relpath(p, itw_root).split(os.sep)[:-1]]
            lab = next((itw_label(q) for q in reversed(parts) if itw_label(q) is not None), None)
            if lab is not None:
                ITW.append({'path': p, 'label': lab, 'system': 'itw', 'group': 'itw', 'speaker': '?'})
    if not ITW:
        print('In-the-Wild: no labels found. Files seen:', [os.path.relpath(p, itw_root) for p in
              glob.glob(os.path.join(itw_root, '**', '*'), recursive=True)[:15]])
print(f'In-the-Wild: {sum(1 - r["label"] for r in ITW):,} real, {sum(r["label"] for r in ITW):,} deepfake recordings'
      + ('' if ITW else '  -> this test will be SKIPPED (training is not affected)'))
''')

md(r"""
## 5. Splits
* **train:** ASVspoof train (all real + a balanced sample of fakes per attack system), MLAAD English *train* systems,
  LibriSpeech dev-clean (75% of its speakers) + 8,000 LibriSpeech train-clean-100 recordings (251 other speakers)
* **validation** (chooses the layer, the classifier strength and the alert levels): ASVspoof dev, MLAAD English
  *validation* systems, the other 25% of LibriSpeech dev-clean speakers
* **tests:** everything else (see the top of the notebook)
""")
code(r'''
rng = random.Random(SEED)
def sample(rows, n):
    rows = list(rows); rng.shuffle(rows); return rows[:n]
def per_system(rows, n_each):
    out = []
    for s in sorted({r['system'] for r in rows}):
        out += sample([r for r in rows if r['system'] == s], n_each)
    return out

N_TRAIN_FAKE_PER_SYS = 10 if SMOKE else 1300           # 6 attacks x 1,300 = 7,800 fakes vs 2,580 real (+ LibriSpeech)
la_tr, la_dv, la_ev = LA_ROWS['train'], LA_ROWS['dev'], LA_ROWS['eval']
en_systems = sorted({r['system'] for r in MLAAD if r['lang'] == 'en'})
sys_split = {s: ('test' if i % 7 == 0 else 'val' if i % 7 == 1 else 'train') for i, s in
             enumerate(sorted(en_systems, key=lambda s: hashlib.md5(s.encode()).hexdigest()))}
ls_spk = sorted({r['speaker'] for r in LS_DEV}, key=lambda s: hashlib.md5(s.encode()).hexdigest())
ls_val_spk = set(ls_spk[: max(1, len(ls_spk) // 4)])

SPLITS = {
    'train': [r for r in la_tr if r['label'] == 0] + per_system([r for r in la_tr if r['label'] == 1], N_TRAIN_FAKE_PER_SYS)
             + [r for r in MLAAD if r['lang'] == 'en' and sys_split[r['system']] == 'train']
             + [r for r in LS_DEV if r['speaker'] not in ls_val_spk] + sample(LS_TRAIN, 40 if SMOKE else 8000),
    'val': [r for r in la_dv if r['label'] == 0] + per_system([r for r in la_dv if r['label'] == 1], 10 if SMOKE else 500)
           + [r for r in MLAAD if r['lang'] == 'en' and sys_split[r['system']] == 'val']
           + [r for r in LS_DEV if r['speaker'] in ls_val_spk],
}
TESTS = {
    'ASVspoof 2019 eval (11 of 13 attacks unseen)': sample([r for r in la_ev if r['label'] == 0], 40 if SMOKE else 3000)
        + per_system([r for r in la_ev if r['label'] == 1], 10 if SMOKE else 450),
    'MLAAD held-out English systems + LibriSpeech test-clean real': [r for r in MLAAD if r['lang'] == 'en' and sys_split[r['system']] == 'test']
        + sample(LS_TEST, 40 if SMOKE else 1500),
    'In-the-Wild (real-world, outside test)': ITW,
}
for k, v in list(SPLITS.items()) + list(TESTS.items()):
    print(f'{k:62s} {sum(1 - r["label"] for r in v):6,} real {sum(r["label"] for r in v):6,} fake')
print('MLAAD English systems ->', {k: sum(1 for s in sys_split.values() if s == k) for k in ('train', 'val', 'test')})
''')

md(r"""
## 6. Audio -> clips -> XLS-R features
Training recordings: one random 4-second clip each, passed through a random codec (none / Opus 8-24 kbps / MP3 /
AAC / phone band) - the same chances for real and fake. Validation and test recordings: exactly what the PC does
(up to 15 clips spread over the recording, no codec added). Features: the average over time of every layer 0-12.
""")
code(r'''
from concurrent.futures import ProcessPoolExecutor
from transformers import Wav2Vec2Config, Wav2Vec2Model
MAX_LAYERS = 12

def augment(x, r):
    u = r.random()
    if u < 0.40:
        return x
    try:
        if u < 0.65:
            return V.codec_roundtrip(x, 'opus', int(r.choice([8000, 12000, 16000, 24000])))
        if u < 0.80:
            return V.codec_roundtrip(x, 'mp3', 32000)
        if u < 0.92:
            return V.codec_roundtrip(x, 'aac', 32000)
        return V.telephone(x)
    except Exception:
        return x

def prepare(job):
    """(index, path, mode, seed) -> (index, [clips]) - runs in worker processes."""
    i, path, mode, seed = job
    try:
        x = V.speech(path)
    except Exception:
        return i, []
    if mode == 'train':
        r = random.Random(seed)
        if x.size > V.CLIP:
            s = r.randrange(0, x.size - V.CLIP + 1); x = x[s: s + V.CLIP]
        x = augment(x.astype(np.float32), r)
        return i, V.clips(V.trim_silence(x) if x.size else x, max_clips=1)
    if mode == 'opus16':
        x = V.codec_roundtrip(x, 'opus', 16000)
    return i, V.clips(x)

if SMOKE:
    cfg = Wav2Vec2Config(hidden_size=64, num_hidden_layers=MAX_LAYERS, num_attention_heads=2, intermediate_size=128,
                         conv_dim=(32,) * 7, conv_stride=(5, 2, 2, 2, 2, 2, 2), conv_kernel=(10, 3, 3, 3, 3, 2, 2),
                         conv_bias=True, feat_extract_norm='layer', do_stable_layer_norm=True,
                         num_conv_pos_embeddings=16, num_conv_pos_embedding_groups=2)
    torch.manual_seed(0); XLSR = Wav2Vec2Model(cfg)
else:
    XLSR = Wav2Vec2Model.from_pretrained('facebook/wav2vec2-xls-r-300m')
assert XLSR.config.do_stable_layer_norm, 'expected the XLS-R layout (stable layer norm)'

class Pooled(torch.nn.Module):
    """wav (batch, 64000) -> per-layer time-average (batch, n+1, hidden). Written out step by step (not the
    library's hidden_states option) so training and the exported ONNX are exactly the same computation."""
    def __init__(self, model, n_layers, only_last=False):
        super().__init__()
        self.fe, self.fp, self.enc = model.feature_extractor, model.feature_projection, model.encoder
        self.layers = torch.nn.ModuleList(list(model.encoder.layers)[:n_layers])
        self.only_last = only_last
    def forward(self, wav):
        h = self.fe(wav).transpose(1, 2)
        h = self.fp(h)[0]
        h = h + self.enc.pos_conv_embed(h)
        outs = [h.mean(1)]
        for layer in self.layers:
            o = layer(h)
            h = o[0] if isinstance(o, tuple) else o
            outs.append(h.mean(1))
        return outs[-1] if self.only_last else torch.stack(outs, 1)

POOLED = Pooled(XLSR, MAX_LAYERS).eval().to(DEVICE)
WORKERS = max(1, os.cpu_count() or 1)

def featurize(rows, mode, name):
    """-> (features float16 (clips, 13, hidden), clip->recording index, labels per recording)"""
    t0 = time.time()
    feats, owner, batch, bowner = [], [], [], []
    def flush():
        if batch:
            with torch.no_grad():
                f = POOLED(torch.from_numpy(np.stack(batch)).to(DEVICE)).float().cpu().numpy()
            feats.append(f.astype(np.float16)); owner.extend(bowner); batch.clear(); bowner.clear()
    jobs = [(i, r['path'], mode, SEED * 100003 + i) for i, r in enumerate(rows)]
    with ProcessPoolExecutor(WORKERS) as ex:
        for k in range(0, len(jobs), 512):        # 512 recordings at a time: decoded audio never piles up in memory
            for i, cl in ex.map(prepare, jobs[k:k + 512], chunksize=8):
                for c in cl:
                    batch.append(c); bowner.append(i)
                    if len(batch) == 32:
                        flush()
            if k and k % 5120 == 0:
                print(f'  {name}: {k:,} / {len(jobs):,} recordings ({time.time() - t0:.0f}s)', flush=True)
    flush()
    F = np.concatenate(feats) if feats else np.zeros((0, MAX_LAYERS + 1, XLSR.config.hidden_size), np.float16)
    used = len(set(owner))
    print(f'{name}: {len(rows):,} recordings -> {len(owner):,} clips ({len(rows) - used} unreadable / too short) '
          f'in {time.time() - t0:.0f}s')
    return F, np.asarray(owner), np.asarray([r['label'] for r in rows])

DATA = {}
for split in ('train', 'val'):
    DATA[split] = featurize(SPLITS[split], 'train' if split == 'train' else 'eval', split)
for name, rows in TESTS.items():
    if rows:
        DATA[name] = featurize(rows, 'eval', name)
if ITW:
    sub = sample(ITW, 60 if SMOKE else 3000)
    TESTS['In-the-Wild after WhatsApp-style Opus 16 kbps'] = sub
    DATA['In-the-Wild after WhatsApp-style Opus 16 kbps'] = featurize(sub, 'opus16', 'In-the-Wild Opus 16 kbps')
''')

md(r"""
## 7. Choose the layer and the classifier (on validation only)
Recording score = average of its clips' probabilities. EER = the error rate where missed fakes = false alarms.
""")
code(r'''
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, roc_curve

def eer(y, s):
    fpr, tpr, _ = roc_curve(y, s); fnr = 1 - tpr
    i = np.nanargmin(np.abs(fnr - fpr)); return float((fpr[i] + fnr[i]) / 2)

def recording_scores(clip_p, owner, n):
    s = np.full(n, np.nan); sums = np.zeros(n); cnt = np.zeros(n)
    np.add.at(sums, owner, clip_p); np.add.at(cnt, owner, 1)
    ok = cnt > 0; s[ok] = sums[ok] / cnt[ok]; return s

def clip_labels(owner, labels):
    return labels[owner]

Ftr, Otr, Ytr = DATA['train']; Fva, Ova, Yva = DATA['val']
ytr = clip_labels(Otr, Ytr)
best = None
print('layer   C      val AUC   val EER')
for layer in range(MAX_LAYERS + 1):
    sc = StandardScaler().fit(Ftr[:, layer].astype(np.float32))
    Xtr, Xva = sc.transform(Ftr[:, layer].astype(np.float32)), sc.transform(Fva[:, layer].astype(np.float32))
    for C in (0.001, 0.01, 0.1):
        lr = LogisticRegression(C=C, max_iter=3000, class_weight='balanced').fit(Xtr, ytr)
        s = recording_scores(lr.predict_proba(Xva)[:, 1], Ova, len(Yva)); ok = ~np.isnan(s)
        auc, e = roc_auc_score(Yva[ok], s[ok]), eer(Yva[ok], s[ok])
        print(f'{layer:5d} {C:6.3f}   {auc:.4f}   {e:.4f}')
        if best is None or e < best[0] - 1e-9 or (abs(e - best[0]) < 1e-9 and layer < best[1]):
            best = (e, layer, C, sc, lr)
VAL_EER, LAYER, C_BEST, SCALER, CLF = best
print(f'\nChosen: layer {LAYER}, C={C_BEST} (validation EER {VAL_EER:.2%})')
''')

md(r"""
## 8. Alert levels (validation) and the honest tests
* **alert** = the score that only 1% of *real* validation recordings reach
* **verify** ("check carefully") = the score that 5% of real validation recordings reach
""")
code(r'''
def scores_for(name):
    F, O, Y = DATA[name]
    s = recording_scores(CLF.predict_proba(SCALER.transform(F[:, LAYER].astype(np.float32)))[:, 1], O, len(Y))
    ok = ~np.isnan(s); return s[ok], Y[ok]

s_val, y_val = scores_for('val')
ALERT = float(np.quantile(s_val[y_val == 0], 0.99))
VERIFY = float(np.quantile(s_val[y_val == 0], 0.95))
print(f'alert level {ALERT:.4f} | verify level {VERIFY:.4f}')

RESULTS = {}
for name in ['val'] + [k for k in TESTS if k in DATA]:
    s, y = scores_for(name)
    r = {'recordings': int(len(y)), 'real': int((y == 0).sum()), 'fake': int((y == 1).sum())}
    if (y == 1).any():
        r['fake caught at alert'] = round(float((s[y == 1] >= ALERT).mean()), 4)
        r['fake caught at verify'] = round(float((s[y == 1] >= VERIFY).mean()), 4)
    if (y == 0).any():
        r['real flagged at alert (false alarms)'] = round(float((s[y == 0] >= ALERT).mean()), 4)
        r['real flagged at verify'] = round(float((s[y == 0] >= VERIFY).mean()), 4)
    if (y == 0).any() and (y == 1).any():
        r['AUC'] = round(float(roc_auc_score(y, s)), 4); r['EER'] = round(eer(y, s), 4)
    RESULTS[name] = r
    print(f'\n{name}'); [print(f'   {k}: {v}') for k, v in r.items()]
''')

md("## 9. Export the AI-voice model (ONNX) and check it gives the same scores")
code(r'''
import onnxruntime as ort
export = Pooled(XLSR, LAYER, only_last=True).eval().cpu()
dummy = torch.randn(2, V.CLIP)
onnx_path = os.path.join(OUT, 'voice_ai.onnx')
torch.onnx.export(export, (dummy,), onnx_path, input_names=['wav'], output_names=['pooled'],
                  dynamic_axes={'wav': {0: 'batch'}, 'pooled': {0: 'batch'}}, opset_version=17, dynamo=False)
sess = ort.InferenceSession(onnx_path, providers=['CPUExecutionProvider'])
# same clips through PyTorch (training path) and ONNX (PC path)
rows = sample(SPLITS['val'], 40)
clips_ = [c for r in rows for c in prepare((0, r['path'], 'eval', 0))[1]][:64]
X = np.stack(clips_)
with torch.no_grad():
    ref = POOLED.cpu()(torch.from_numpy(X))[:, LAYER].numpy()
got = sess.run(None, {'wav': X})[0]
p_ref = CLF.predict_proba(SCALER.transform(ref))[:, 1]; p_got = CLF.predict_proba(SCALER.transform(got))[:, 1]
diff = float(np.abs(p_ref - p_got).max())
print(f'ONNX vs PyTorch on {len(X)} clips: largest score difference {diff:.6f}')
assert diff < 1e-3, 'ONNX export does not match - not saving'
POOLED.to(DEVICE)
def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()
meta = {
    'model': 'facebook/wav2vec2-xls-r-300m (frozen, cut after layer %d) + logistic regression' % LAYER,
    'onnx_sha256': sha(onnx_path), 'layer': LAYER, 'sample_rate': V.SR, 'clip_seconds': V.CLIP_S,
    'max_clips': V.MAX_CLIPS, 'aggregation': 'mean of clip probabilities',
    'scaler_mean': SCALER.mean_.tolist(), 'scaler_scale': SCALER.scale_.tolist(),
    'coef': CLF.coef_[0].tolist(), 'intercept': float(CLF.intercept_[0]), 'C': C_BEST,
    'levels': {'alert': ALERT, 'verify': VERIFY,
               'rule': 'alert: 1% of real validation recordings reach it; verify: 5%'},
    'results': RESULTS, 'validation_eer': VAL_EER,
    'training_data': {'ASVspoof 2019 LA train': 'all real + up to %d fakes per attack' % N_TRAIN_FAKE_PER_SYS,
                      'MLAAD English systems (train split)': sum(1 for s in sys_split.values() if s == 'train'),
                      'LibriSpeech dev-clean speakers': len(ls_spk) - len(ls_val_spk),
                      'LibriSpeech train-clean-100 recordings': min(len(LS_TRAIN), 8000)},
    'smoke_test': SMOKE, 'trained_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'versions': {'torch': torch.__version__, 'transformers': transformers.__version__},
}
json.dump(meta, open(os.path.join(OUT, 'voice_ai.json'), 'w'), indent=1)
print('saved voice_ai.onnx (%.0f MB) + voice_ai.json' % (os.path.getsize(onnx_path) / 1e6))
''')

md(r"""
## 10. Voiceprint model ("is this really my contact?")
SpeechBrain's ECAPA speaker model (trained on VoxCeleb). Its spectrogram step is rewritten as a plain convolution
(ONNX cannot export complex numbers) and checked against the original. Tested on LibriSpeech test-clean speakers it
never saw. **Mismatch level** = the similarity that only 1% of same-speaker pairs fall below. A clone can *match* -
so a match never proves a voice is real; a mismatch is a strong warning.
""")
code(r'''
from speechbrain.lobes.features import Fbank
from speechbrain.processing.features import InputNormalization
from speechbrain.lobes.models.ECAPA_TDNN import ECAPA_TDNN

class ConvSTFT(torch.nn.Module):
    """speechbrain's STFT (center=True, constant padding, onesided) as a convolution: same numbers, exportable."""
    def __init__(self, stft):
        super().__init__()
        n_fft, win, self.hop = stft.n_fft, stft.win_length, stft.hop_length
        assert stft.center and stft.pad_mode == 'constant' and stft.onesided and not stft.normalized_stft
        w = torch.zeros(n_fft); off = (n_fft - win) // 2; w[off:off + win] = stft.window
        n = torch.arange(n_fft, dtype=torch.float64); k = torch.arange(n_fft // 2 + 1, dtype=torch.float64)[:, None]
        ang = 2 * math.pi * k * n / n_fft
        self.register_buffer('kernel', torch.cat([(torch.cos(ang) * w.double()).float(),
                                                  (-torch.sin(ang) * w.double()).float()])[:, None, :])
        self.n_fft = n_fft
    def forward(self, x):
        x = torch.nn.functional.pad(x[:, None, :], (self.n_fft // 2, self.n_fft // 2))
        y = torch.nn.functional.conv1d(x, self.kernel, stride=self.hop)
        f = self.kernel.shape[0] // 2
        return torch.stack([y[:, :f], y[:, f:]], -1).transpose(1, 2)

class Voiceprint(torch.nn.Module):
    def __init__(self, fbank, norm, emb):
        super().__init__(); self.fbank, self.norm, self.emb = fbank, norm, emb
    def forward(self, wav):                                  # (1, samples) 16 kHz -> (1, 192)
        lens = torch.ones(wav.shape[0])
        return self.emb(self.norm(self.fbank(wav), lens), lens).squeeze(1)

if SMOKE:
    torch.manual_seed(1)
    fb, nrm = Fbank(n_mels=80), InputNormalization(norm_type='sentence', std_norm=False)
    emb = ECAPA_TDNN(input_size=80, channels=[64, 64, 64, 64, 192], kernel_sizes=[5, 3, 3, 3, 1], dilations=[1, 2, 3, 4, 1],
                     attention_channels=16, lin_neurons=32).eval()
    original = lambda w: Voiceprint(fb, nrm, emb)(w)
else:
    from speechbrain.inference.speaker import EncoderClassifier
    sb = EncoderClassifier.from_hparams('speechbrain/spkrec-ecapa-voxceleb', savedir=os.path.join(WORK, 'ecapa'))
    fb, nrm, emb = sb.mods.compute_features, sb.mods.mean_var_norm, sb.mods.embedding_model
    original = lambda w: sb.encode_batch(w).squeeze(1)
vp_ref_in = [V.speech(r['path']) for r in LS_TEST[:12]]
with torch.no_grad():
    ref = [original(torch.from_numpy(x[None]).float()).cpu().numpy()[0] for x in vp_ref_in]
fb.compute_STFT = ConvSTFT(fb.compute_STFT)
VP = Voiceprint(fb, nrm, emb).eval().cpu()
vp_path = os.path.join(OUT, 'voiceprint.onnx')
torch.onnx.export(VP, (torch.randn(1, V.SR * 3) * 0.1,), vp_path, input_names=['wav'], output_names=['emb'],
                  dynamic_axes={'wav': {1: 'samples'}}, opset_version=17, dynamo=False)
vps = ort.InferenceSession(vp_path, providers=['CPUExecutionProvider'])
def vp_emb(x):
    e = vps.run(None, {'wav': x[None].astype(np.float32)})[0][0]
    return e / (np.linalg.norm(e) + 1e-9)
cos_check = [float(np.dot(vp_emb(x), r / np.linalg.norm(r))) for x, r in zip(vp_ref_in, ref)]
print('ONNX voiceprint vs original SpeechBrain: lowest cosine', round(min(cos_check), 6))
assert min(cos_check) > 0.999, 'voiceprint export does not match - not saving'

# speaker test: LibriSpeech test-clean, speakers never seen; one recording vs another
by_spk = {}
for r in LS_TEST:
    by_spk.setdefault(r['speaker'], []).append(r)
spk = sorted(by_spk)
emb_cache = {}
def E(r, opus=False):
    key = (r['path'], opus)
    if key not in emb_cache:
        x = V.speech(r['path'])[: V.SR * 8]
        emb_cache[key] = vp_emb(V.codec_roundtrip(x, 'opus', 16000) if opus else x)
    return emb_cache[key]
rr = random.Random(SEED); same, diff, same_op = [], [], []
for _ in range(60 if SMOKE else 800):
    a = rr.choice(spk); u1, u2 = rr.sample(by_spk[a], 2)
    same.append(float(E(u1) @ E(u2))); same_op.append(float(E(u1) @ E(u2, opus=True)))
    b = rr.choice([s for s in spk if s != a])
    diff.append(float(E(rr.choice(by_spk[a])) @ E(rr.choice(by_spk[b]))))
same, diff, same_op = map(np.asarray, (same, diff, same_op))
MISMATCH = float(np.quantile(same, 0.01))
y = np.r_[np.ones(len(same)), np.zeros(len(diff))]; s = np.r_[same, diff]
vp_res = {'speakers': len(spk), 'same-speaker pairs': int(len(same)), 'different-speaker pairs': int(len(diff)),
          'EER': round(eer(y, s), 4), 'AUC': round(float(roc_auc_score(y, s)), 4),
          'different speakers below the mismatch level': round(float((diff < MISMATCH).mean()), 4),
          'same speaker wrongly below it': round(float((same < MISMATCH).mean()), 4),
          'same speaker, one side WhatsApp-Opus, wrongly below it': round(float((same_op < MISMATCH).mean()), 4)}
print(json.dumps(vp_res, indent=1))
json.dump({'model': 'speechbrain/spkrec-ecapa-voxceleb (ECAPA-TDNN), spectrogram as convolution', 'sample_rate': V.SR,
           'max_seconds': 30, 'onnx_sha256': sha(vp_path), 'mismatch_level': MISMATCH,
           'rule': 'cosine similarity below this = only 1% of same-speaker pairs (LibriSpeech test-clean)',
           'results': vp_res, 'smoke_test': SMOKE, 'trained_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
          open(os.path.join(OUT, 'voiceprint.json'), 'w'), indent=1)
print('saved voiceprint.onnx (%.0f MB) + voiceprint.json' % (os.path.getsize(vp_path) / 1e6))
''')

md(r"""
## 11. Download the 4 files
Put all four into `backend\app\ml\models\` on your PC.
* **Kaggle:** open the saved version -> **Output** tab -> download each of the 4 files.
* **Colab:** they download automatically; if one does not start, open the **Files** panel (folder icon) ->
  `/content/cg_out` -> the file's **⋮** menu -> **Download**.
""")
code(r'''
for f in ('voice_ai.onnx', 'voice_ai.json', 'voiceprint.onnx', 'voiceprint.json'):
    p = os.path.join(OUT, f); print(f'{f:18s} {os.path.getsize(p) / 1e6:8.1f} MB')
if not SMOKE and not KAGGLE:
    try:
        from google.colab import files
        for f in ('voice_ai.json', 'voiceprint.json', 'voiceprint.onnx', 'voice_ai.onnx'):
            files.download(os.path.join(OUT, f))
    except ImportError:
        print('Not on Colab: copy the 4 files from', OUT)
elif KAGGLE:
    print('Kaggle: the 4 files are in the Output tab of this version.')
print(json.dumps({k: v for k, v in RESULTS.items()}, indent=1))
''')

nb = {"cells": cells, "metadata": {"accelerator": "GPU", "colab": {"provenance": [], "gpuType": "T4"},
                                    "kernelspec": {"display_name": "Python 3", "name": "python3"},
                                    "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 0}
json.dump(nb, open(OUT, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print("cells:", len(cells))
