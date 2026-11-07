"""Builds docs/colab/CyberGuard_Voice_RealWorld_Kaggle.ipynb (run: python build_voice_realworld_notebook.py).

Voice upgrade 2 (1 Nov): the AI-voice model wrongly flagged 23.8% of REAL real-world recordings (In-the-Wild) at its
alert level, because its classifier and levels were made on clean studio speech only. This notebook keeps the speech
model (voice_ai.onnx) exactly as it is and retrains only the small classifier on top + its levels (they live in
voice_ai.json), with half of the In-the-Wild celebrities added to training. It is tested on the OTHER celebrities
(voices it never heard) and on the old tests, and the installed classifier is scored on exactly the same recordings.

The data cells are taken word for word from the two tested voice notebooks (build_voice_itw_notebook.py and
build_voice_notebook.py), so downloads, checks and audio handling are identical. SMOKE=1 (environment) runs the
notebook on tiny fake data on CPU - used only to test it before it is given to the user."""
import json
import os
import runpy
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIO_SRC = os.path.join(HERE, "..", "..", "backend", "app", "detectors", "voice_audio.py")
OUT_NB = os.path.join(HERE, "CyberGuard_Voice_RealWorld_Kaggle.ipynb")


def cells_of(builder, argv):
    """Run another builder (into a temporary file) and return its cells."""
    old = sys.argv
    try:
        sys.argv = [builder] + argv
        return runpy.run_path(os.path.join(HERE, builder))["cells"]
    finally:
        sys.argv = old


def src(c):
    return c["source"] if isinstance(c["source"], str) else "".join(c["source"])


def section(cells, heading):
    """The markdown cell whose text starts with `heading` and the code cell right after it."""
    for i, c in enumerate(cells):
        if c["cell_type"] == "markdown" and src(c).lstrip().startswith(heading):
            assert cells[i + 1]["cell_type"] == "code", heading
            return [cells[i], cells[i + 1]]
    raise KeyError(heading)


tmp = tempfile.mkdtemp()
ITW = cells_of("build_voice_itw_notebook.py", [AUDIO_SRC, os.path.join(tmp, "itw.ipynb")])
TRAIN = cells_of("build_voice_notebook.py", [AUDIO_SRC, os.path.join(tmp, "train.ipynb")])

cells = []


def md(s):
    cells.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n")})


def code(s):
    cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": s.strip("\n")})


md(r"""
# CyberGuard - **Voice: real-world upgrade** (Kaggle) - fewer false alarms on real voices

On **In-the-Wild** (real recordings of 58 celebrities and politicians from the internet) your AI-voice model has a
good AUC (0.967) but wrongly flags **23.8% of the REAL recordings** at its alert level: its small classifier and its
levels were made on clean studio speech only. This notebook fixes exactly that part.

* `voice_ai.onnx` (the big speech model) is **not changed** - its features are used as they are.
* The small classifier on top and the alert / check-carefully levels (all inside `voice_ai.json`) are trained again on
  the same data as before (ASVspoof 2019, MLAAD English, LibriSpeech) **plus half of the In-the-Wild celebrities**.
* The levels are set so that only 1% (alert) / 5% (check carefully) of **each** kind of real voice reaches them -
  studio speech, ASVspoof speakers **and** real-world recordings.
* **Honest test:** the other In-the-Wild celebrities (their voices were never heard in training or for choosing
  anything), ASVspoof 2019 eval, MLAAD held-out systems + LibriSpeech test-clean, and In-the-Wild after WhatsApp-style
  Opus compression. Your **installed** classifier is scored on exactly the same recordings.

Output: one file, **`voice_ai.json`**. On your PC, `install_voice_head.py` installs it only if it is better.

**Before you start (Kaggle)**
1. **Add Input -> Your Work / Datasets ->** your private dataset with `voice_ai.onnx` + `voice_ai.json`
   (e.g. `cyberguard-voice-model` from the In-the-Wild test).
2. Right panel -> **Session options: Accelerator GPU T4 x2, Internet On**.
3. **Add-ons -> Secrets: `HF_TOKEN`** (your Hugging Face *Read* token; MLAAD needs it) - tick it for this notebook.
4. **Save Version -> Save & Run All (Commit)**. About 3-5 hours (downloads ~1-2 h, features ~1.5-2 h). You can close
   the browser. Then download `voice_ai.json` from the version's **Output** tab.
""")

# --- word for word from the tested In-the-Wild notebook: settings, tools, audio code, model, download, labels
for h in ("## 1. Settings", "## 2. Tools", "## 3. The audio code", "## 4. Find and check the model files",
          "## 5. Download In-the-Wild", "## 6. Read the labels"):
    cells.extend(section(ITW, h))

# --- word for word from the tested training notebook: download helpers, ASVspoof 2019, LibriSpeech, MLAAD
md("## 7. The training notebook's data (the same sources the installed classifier was made with)")
for h in ("## 4. Data", "### 4a. ASVspoof", "### 4b. LibriSpeech", "### 4c. MLAAD"):
    cells.extend(section(TRAIN, h))

md(r"""
## 8. Splits
* **ASVspoof / MLAAD / LibriSpeech:** exactly the same rules as the training notebook (MLAAD systems split by system,
  LibriSpeech by speaker).
* **In-the-Wild: split by celebrity** (each person's real AND deepfake recordings stay together): about 50% of the
  people -> training, 15% -> validation (chooses the classifier and the levels), 35% -> **test** (never used for anything).
""")
code(r'''
import hashlib
rng = random.Random(SEED)
def sample(rows, n):
    rows = list(rows); rng.shuffle(rows); return rows[:n]
def per_system(rows, n_each):
    out = []
    for s in sorted({r['system'] for r in rows}):
        out += sample([r for r in rows if r['system'] == s], n_each)
    return out
def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

N_TRAIN_FAKE_PER_SYS = 10 if SMOKE else 1300
la_tr, la_dv, la_ev = LA_ROWS['train'], LA_ROWS['dev'], LA_ROWS['eval']
en_systems = sorted({r['system'] for r in MLAAD if r['lang'] == 'en'})
sys_split = {s: ('test' if i % 7 == 0 else 'val' if i % 7 == 1 else 'train') for i, s in enumerate(sorted(en_systems, key=md5))}
ls_spk = sorted({r['speaker'] for r in LS_DEV}, key=md5)
ls_val_spk = set(ls_spk[: max(1, len(ls_spk) // 4)])

ITW_ROWS = [dict(r, group='itw', system='itw') for r in ROWS]
itw_spk = sorted({r['speaker'] for r in ITW_ROWS}, key=md5)
assert SMOKE or len(itw_spk) >= 20, f'In-the-Wild speakers not found ({len(itw_spk)}) - the split by person needs them'
ITW_PART = {s: ('train' if i < 0.50 * len(itw_spk) else 'val' if i < 0.65 * len(itw_spk) else 'test')
            for i, s in enumerate(itw_spk)}
ITW_SPLIT = {p: [r for r in ITW_ROWS if ITW_PART[r['speaker']] == p] for p in ('train', 'val', 'test')}

SPLITS = {
    'train': [r for r in la_tr if r['label'] == 0] + per_system([r for r in la_tr if r['label'] == 1], N_TRAIN_FAKE_PER_SYS)
             + [r for r in MLAAD if r['lang'] == 'en' and sys_split[r['system']] == 'train']
             + [r for r in LS_DEV if r['speaker'] not in ls_val_spk] + sample(LS_TRAIN, 40 if SMOKE else 8000)
             + ITW_SPLIT['train'],
    'val': [r for r in la_dv if r['label'] == 0] + per_system([r for r in la_dv if r['label'] == 1], 10 if SMOKE else 500)
           + [r for r in MLAAD if r['lang'] == 'en' and sys_split[r['system']] == 'val']
           + [r for r in LS_DEV if r['speaker'] in ls_val_spk] + ITW_SPLIT['val'],
}
ITW_KEY, OPUS_KEY = 'In-the-Wild (real-world, outside test)', 'In-the-Wild after WhatsApp-style Opus 16 kbps'
TESTS = {
    'ASVspoof 2019 eval (11 of 13 attacks unseen)': sample([r for r in la_ev if r['label'] == 0], 40 if SMOKE else 3000)
        + per_system([r for r in la_ev if r['label'] == 1], 10 if SMOKE else 450),
    'MLAAD held-out English systems + LibriSpeech test-clean real': [r for r in MLAAD if r['lang'] == 'en' and sys_split[r['system']] == 'test']
        + sample(LS_TEST, 40 if SMOKE else 1500),
    ITW_KEY: ITW_SPLIT['test'],
}
OPUS_ROWS = sample(ITW_SPLIT['test'], 20 if SMOKE else 3000)
for k, v in list(SPLITS.items()) + list(TESTS.items()) + [(OPUS_KEY, OPUS_ROWS)]:
    print(f'{k:62s} {sum(1 - r["label"] for r in v):6,} real {sum(r["label"] for r in v):6,} fake')
print('In-the-Wild people ->', {p: sum(1 for v in ITW_PART.values() if v == p) for p in ('train', 'val', 'test')})
''')

md(r"""
## 9. Recordings -> 4-second clips -> speech features (with YOUR installed `voice_ai.onnx`)
Training recordings: one random 4-second clip each, passed through a random codec (none / Opus 8-24 kbps / MP3 /
AAC / phone band) - the same as the training notebook, for real and fake alike. Validation and test recordings:
exactly what the PC does (up to 15 clips spread over the recording). The GPU is first checked to give the same
features as the CPU (the PC runs on the CPU).
""")
code(r'''
from concurrent.futures import ThreadPoolExecutor

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

def speech_of(r):
    if r.get('group') == 'itw':
        info = MEMBERS[r['file']]
        if info.file_size > MAX_MEMBER:
            raise ValueError('too big')
        return V.speech(ZF.read(info))             # the zip checks each file's CRC while reading
    return V.speech(r['path'])

def prepare(job):
    i, r, mode, seed = job
    try:
        x = speech_of(r)
    except Exception:
        return i, []
    if mode == 'train':
        g = random.Random(seed)
        if x.size > V.CLIP:
            s = g.randrange(0, x.size - V.CLIP + 1); x = x[s: s + V.CLIP]
        x = augment(x.astype(np.float32), g)
        return i, V.clips(V.trim_silence(x) if x.size else x, max_clips=1)
    if mode == 'opus16':
        x = V.codec_roundtrip(x, 'opus', 16000)
    return i, V.clips(x)

def run_feats(sess, X, batch):
    return np.concatenate([sess.run(None, {'wav': X[k:k + batch]})[0] for k in range(0, len(X), batch)])

SESS, BATCH = CPU_SESS, 4
if GPU_SESS is not None:
    g = random.Random(SEED)
    probe = [c for r in g.sample(SPLITS['val'], min(12, len(SPLITS['val']))) for c in prepare((0, r, 'eval', 0))[1]][:24]
    if probe:
        X = np.stack(probe).astype(np.float32)
        a, b = clip_probs(run_feats(CPU_SESS, X, 4)), clip_probs(run_feats(GPU_SESS, X, GPU_BATCH))
        diff = float(np.max(np.abs(a - b)))
        print(f'GPU vs CPU on {len(X)} clips: largest score difference {diff:.6f}')
        if diff < 0.002:
            SESS, BATCH = GPU_SESS, GPU_BATCH
print('features with', SESS.get_providers()[0])

THREADS = max(2, min(16, (os.cpu_count() or 2) * 2))
def featurize(rows, mode, name):
    """-> (features float32 (clips, dim), clip -> recording index, labels per recording, group per recording)"""
    t0 = time.time()
    feats, owner, buf, bown = [], [], [], []
    def flush():
        if buf:
            feats.append(run_feats(SESS, np.stack(buf).astype(np.float32), BATCH)); owner.extend(bown); buf.clear(); bown.clear()
    jobs = [(i, r, mode, SEED * 100003 + i) for i, r in enumerate(rows)]
    with ThreadPoolExecutor(THREADS) as ex:
        for k in range(0, len(jobs), 256):
            for i, cl in ex.map(prepare, jobs[k:k + 256]):
                for c in cl:
                    buf.append(c); bown.append(i)
                    if len(buf) >= 4 * BATCH:
                        flush()
            if k and k % 4096 == 0:
                el = time.time() - t0
                print(f'  {name}: {k:,} / {len(jobs):,} recordings ({el / 60:.0f} min, about {el / k * (len(jobs) - k) / 60:.0f} min left)', flush=True)
    flush()
    F = np.concatenate(feats).astype(np.float32) if feats else np.zeros((0, len(MEAN)), np.float32)
    print(f'{name}: {len(rows):,} recordings -> {len(owner):,} clips ({len(rows) - len(set(owner))} unreadable / too short) '
          f'in {(time.time() - t0) / 60:.1f} min', flush=True)
    return F, np.asarray(owner, int), np.asarray([r['label'] for r in rows]), np.asarray([r.get('group', '?') for r in rows])

DATA = {'train': featurize(SPLITS['train'], 'train', 'train'), 'val': featurize(SPLITS['val'], 'eval', 'validation')}
for name, rows in TESTS.items():
    DATA[name] = featurize(rows, 'eval', name)
DATA[OPUS_KEY] = featurize(OPUS_ROWS, 'opus16', OPUS_KEY)
''')

md(r"""
## 10. Train the classifier again (chosen on validation only)
Logistic regression on the same speech features. Tried: strength C x how much the In-the-Wild training voices count.
Chosen by the **average EER of the three kinds of validation voice** (ASVspoof, studio TTS + LibriSpeech, real-world),
so no kind is sacrificed for another. Levels: the highest of the three kinds' 99% (alert) / 95% (verify) real scores.
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

KIND = {'asvspoof19': 'ASVspoof', 'mlaad': 'studio', 'librispeech': 'studio', 'itw': 'real-world'}
Ftr, Otr, Ytr, Gtr = DATA['train']; Fva, Ova, Yva, Gva = DATA['val']
ytr, gtr = Ytr[Otr], Gtr[Otr]
kva = np.asarray([KIND.get(g, g) for g in Gva])

def head_scores(sc, lr, name):
    F, O, Y, G = DATA[name]
    return recording_scores(lr.predict_proba(sc.transform(F))[:, 1], O, len(Y))

best = None
print('    C  ITW weight   ASVspoof EER  studio EER  real-world EER   mean')
for C in (0.001, 0.01, 0.1):
    sc = StandardScaler().fit(Ftr)
    Xtr = sc.transform(Ftr)
    for w in (1.0, 3.0, 10.0):
        sw = np.where(gtr == 'itw', w, 1.0)
        lr = LogisticRegression(C=C, max_iter=3000, class_weight='balanced').fit(Xtr, ytr, sample_weight=sw)
        s = head_scores(sc, lr, 'val')
        e = {}
        for k in ('ASVspoof', 'studio', 'real-world'):
            m = (kva == k) & ~np.isnan(s)
            if len(set(Yva[m])) == 2:
                e[k] = eer(Yva[m], s[m])
        mean = float(np.mean(list(e.values())))
        print(f'{C:6.3f} {w:6.0f}        ' + '   '.join(f'{e.get(k, float("nan")):10.4f}' for k in ('ASVspoof', 'studio', 'real-world'))
              + f'   {mean:.4f}')
        if best is None or mean < best[0] - 1e-9:
            best = (mean, C, w, sc, lr, e)
VAL_MEAN_EER, C_BEST, W_ITW, SCALER, CLF, VAL_EERS = best
print(f'\nChosen: C={C_BEST}, In-the-Wild weight {W_ITW} (validation mean EER {VAL_MEAN_EER:.2%})')

s_val = head_scores(SCALER, CLF, 'val')
LEVEL_BY_KIND = {}
for k in ('ASVspoof', 'studio', 'real-world'):
    real = s_val[(kva == k) & (Yva == 0) & ~np.isnan(s_val)]
    if len(real):
        LEVEL_BY_KIND[k] = (float(np.quantile(real, 0.99)), float(np.quantile(real, 0.95)), int(len(real)))
NEW_ALERT = max(v[0] for v in LEVEL_BY_KIND.values())
NEW_VERIFY = min(max(v[1] for v in LEVEL_BY_KIND.values()), NEW_ALERT)
print('real validation voices per kind (99% / 95% score):', {k: (round(a, 4), round(b, 4), n) for k, (a, b, n) in LEVEL_BY_KIND.items()})
print(f'new alert level {NEW_ALERT:.4f} | check-carefully level {NEW_VERIFY:.4f}   (installed: {ALERT:.4f} / {VERIFY:.4f})')
''')

md(r"""
## 11. Honest tests - new classifier vs your INSTALLED one, on exactly the same recordings
Each at its own levels. **AUC** (1.0 = perfect ranking), **EER**, deepfakes caught and real recordings wrongly flagged.
""")
code(r'''
def summarize(s, y, alert, verify):
    ok = ~np.isnan(s); s, y = s[ok], y[ok]
    r = {'recordings': int(len(y)), 'real': int((y == 0).sum()), 'fake': int((y == 1).sum())}
    if (y == 1).any():
        r['fake caught at alert'] = round(float((s[y == 1] >= alert).mean()), 4)
        r['fake caught at verify'] = round(float((s[y == 1] >= verify).mean()), 4)
    if (y == 0).any():
        r['real flagged at alert (false alarms)'] = round(float((s[y == 0] >= alert).mean()), 4)
        r['real flagged at verify'] = round(float((s[y == 0] >= verify).mean()), 4)
    if (y == 0).any() and (y == 1).any():
        r['AUC'] = round(float(roc_auc_score(y, s)), 4); r['EER'] = round(eer(y, s), 4)
    r['not scored (unreadable or under 1 s of speech)'] = int((~ok).sum())
    return r

def installed_scores(name):
    F, O, Y, G = DATA[name]
    return recording_scores(clip_probs(F), O, len(Y))

NEW, OLD = {}, {}
for name in ['val'] + list(TESTS) + [OPUS_KEY]:
    Y = DATA[name][2]
    NEW[name] = summarize(head_scores(SCALER, CLF, name), Y, NEW_ALERT, NEW_VERIFY)
    OLD[name] = summarize(installed_scores(name), Y, ALERT, VERIFY)
for k in (ITW_KEY, OPUS_KEY):
    spk = {r['speaker'] for r in (TESTS[k] if k in TESTS else OPUS_ROWS)}
    NEW[k]['speakers'] = OLD[k]['speakers'] = len(spk)
    NEW[k]['note'] = OLD[k]['note'] = ('celebrities never used for training or for choosing anything (the other '
                                       'In-the-Wild celebrities were used for training)')
for name in ['val'] + list(TESTS) + [OPUS_KEY]:
    print(f'\n{name}')
    for m in ('AUC', 'EER', 'fake caught at alert', 'real flagged at alert (false alarms)', 'fake caught at verify', 'real flagged at verify'):
        if m in NEW[name]:
            print(f'   {m:38s} installed {OLD[name].get(m)!s:>8}   new {NEW[name].get(m)!s:>8}')
''')

md(r"""
## 12. The new `voice_ai.json`
Everything about the speech model stays as it is (same `onnx_sha256`); only the classifier, the levels and the results
change. The installed classifier's results on the same recordings are stored in it, so the PC can compare fairly.
""")
code(r'''
import datetime, copy
new_meta = copy.deepcopy(META)
new_meta.update({
    'scaler_mean': SCALER.mean_.tolist(), 'scaler_scale': SCALER.scale_.tolist(),
    'coef': CLF.coef_[0].tolist(), 'intercept': float(CLF.intercept_[0]), 'C': C_BEST,
    'levels': {'alert': NEW_ALERT, 'verify': NEW_VERIFY,
               'rule': 'alert: 1% of real validation recordings of EACH kind (ASVspoof, studio, real-world) reach it; verify: 5%',
               'by_kind': {k: {'alert_99': a, 'verify_95': b, 'real_recordings': n} for k, (a, b, n) in LEVEL_BY_KIND.items()}},
    'validation_eer': VAL_MEAN_EER, 'validation_eer_by_kind': VAL_EERS,
    'results': NEW,
    'head_version': 2,
    'head_upgrade': {'what': 'classifier + levels trained again with half of the In-the-Wild celebrities; voice_ai.onnx unchanged',
                     'itw_weight': W_ITW,
                     'itw_people': {p: sum(1 for v in ITW_PART.values() if v == p) for p in ('train', 'val', 'test')},
                     'itw_dataset': DATASET},
    'installed_head_same_test': {'trained_at': META.get('trained_at'), 'levels': {'alert': ALERT, 'verify': VERIFY}, 'results': OLD},
    'smoke_test': bool(SMOKE),
    'trained_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
})
td = dict(META.get('training_data') or {})
td['In-the-Wild celebrities (training half, real + deepfake recordings)'] = len(ITW_SPLIT['train'])
new_meta['training_data'] = td
new_meta['versions'] = dict(META.get('versions') or {}, head_upgrade={'onnxruntime': ort.__version__, 'scikit-learn': sklearn.__version__})
assert new_meta['onnx_sha256'] == MODEL_SHA
with open(os.path.join(OUT, 'voice_ai.json'), 'w', encoding='utf-8') as f:
    json.dump(new_meta, f, indent=1)
print('wrote', os.path.join(OUT, 'voice_ai.json'))
print('\nDONE - download voice_ai.json from the Output tab (voice_ai.onnx is unchanged - do not download it again).')
''')

nb = {"cells": cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                                   "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
with open(OUT_NB, "w", encoding="utf-8") as fh:
    json.dump(nb, fh, indent=1, ensure_ascii=False)
print("wrote", OUT_NB, len(cells), "cells")
