"""Builds CyberGuard_Deepfake_Video_Kaggle.ipynb (run: python build_deepfake_video_kaggle.py).

The face/frame code is copied word for word from backend/app/detectors/video_frames.py, so training and the scanner
on the PC prepare faces identically. SMOKE=1 (environment) makes the notebook run on a tiny fake dataset on CPU -
used only to test the notebook before it is given to the user."""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMES_SRC = open(os.path.join(HERE, "..", "..", "backend", "app", "detectors", "video_frames.py"), encoding="utf-8").read()
cells = []


def md(s):
    cells.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n").splitlines(True)})


def code(s):
    cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
                  "source": s.strip("\n").splitlines(True)})


md("""
# CyberGuard - Deepfake **Video** model (Kaggle) - face-swap videos

Trains the face model behind **Deepfake -> Video Analysis**. Output: 2 files for your PC.

| File | What it is |
|---|---|
| `deepfake_video.onnx` | the trained model (EfficientNet-B0, ONNX, runs on the PC's CPU) |
| `deepfake_video.json` | how CyberGuard must use it + alert levels + honest test results |

**How it works:** 16 frames spread over each video -> the largest face in each frame (OpenCV YuNet, the same face
finder CyberGuard uses) -> each face is scored -> the video score is the average of its faces.

**Data**
* **Train:** Celeb-DF v2 (590 real celebrity videos + 300 YouTube real videos + 5,639 face-swap videos), *without*
  its official test list. Downloaded from your private Drive link (Kaggle secret `CELEBDF_URL`).
* **Test 1:** Celeb-DF v2 official test list (518 videos, never trained on). Alert levels are chosen on one random
  half and reported on the other half.
* **Test 2 (independent):** the 400 labelled DFDC sample videos (Meta). A completely different dataset - the
  honest "does it work beyond what it learned" number.

**Before you press Run All**
1. Right panel -> **Session options** -> Accelerator **GPU T4 x2** (or P100), Internet **On**.
2. **Add-ons -> Secrets** -> add `CELEBDF_URL` = your Celeb-DF Drive link -> tick it for this notebook.
3. **Add Input** -> Competitions -> **Deepfake Detection Challenge**.
4. Optional (baseline): Add Input -> your private dataset with `deepfake_image.onnx` + `deepfake_image.json`.

Then **Save Version -> Save & Run All (Commit)**: it runs on Kaggle by itself (2-3 hours) even if you close the
browser. The 2 files appear in the version's **Output** tab.
""")

md("## 1. Settings and GPU check")
code(r'''
import os, sys, glob, json, time, random, shutil, subprocess
import numpy as np
SMOKE = os.environ.get('SMOKE') == '1'          # only for testing this notebook on a tiny fake dataset
def _roomiest(paths):                                         # big temporary files go where there is most space
    ok = []
    for p in paths:
        try:
            os.makedirs(p, exist_ok=True); ok.append((shutil.disk_usage(p).free, p))
        except OSError:
            pass
    return max(ok)[1]
WORK = os.environ.get('CG_WORK') or _roomiest(['/kaggle/temp/cg', '/tmp/cg'])   # temporary, not saved
OUT = os.environ.get('CG_OUT', '/kaggle/working')            # the 2 result files (saved in Output)
INPUT = os.environ.get('CG_INPUT', '/kaggle/input')
os.makedirs(WORK, exist_ok=True); os.makedirs(OUT, exist_ok=True)
IMG, BATCH, EPOCHS, LR, SEED = 224, 64, 4, 3e-4, 42
TRAIN_FRAMES_REAL, TRAIN_FRAMES_FAKE = 32, 8     # more frames from the (fewer) real videos -> balanced training
MEAN, STD = [0.485, 0.456, 0.406], [0.229, 0.224, 0.225]
WORKERS = min(4, os.cpu_count() or 2)
if SMOKE:
    IMG, BATCH, EPOCHS, TRAIN_FRAMES_REAL, TRAIN_FRAMES_FAKE = 64, 8, 1, 4, 2
random.seed(SEED); np.random.seed(SEED)
free = shutil.disk_usage(WORK).free / 1e9
print(f'free disk for temporary files: {free:.0f} GB')
import torch
torch.manual_seed(SEED)
DEV = 'cuda' if torch.cuda.is_available() else 'cpu'
if not SMOKE:
    assert DEV == 'cuda', 'No GPU: Session options -> Accelerator -> GPU T4 x2, then run again'
    assert free > 25, 'Less than 25 GB free disk - Celeb-DF needs about 20 GB while unpacking'
    print('GPU:', torch.cuda.get_device_name(0))
''')

md("## 2. Tools")
code(r'''
if not SMOKE:
    subprocess.run([sys.executable, '-m', 'pip', '-q', 'install', 'timm', 'onnx', 'onnxruntime', 'onnxscript', 'gdown'], check=True)
import cv2, timm, onnxruntime
print('OpenCV', cv2.__version__, '| timm', timm.__version__, '| onnxruntime', onnxruntime.__version__)
''')

md("## 3. The frame + face code (identical to CyberGuard's `video_frames.py`)")
code(FRAMES_SRC)

md("## 4. YuNet face detector (the same file CyberGuard uses)")
code(r'''
YUNET = os.path.join(WORK, 'face_detection_yunet_2023mar.onnx')
if not os.path.exists(YUNET):
    local = glob.glob(INPUT + '/**/face_detection_yunet_2023mar.onnx', recursive=True)
    if local:
        shutil.copy(local[0], YUNET)
    else:
        subprocess.run(['wget', '-q', '-O', YUNET, 'https://github.com/opencv/opencv_zoo/raw/main/models/'
                        'face_detection_yunet/face_detection_yunet_2023mar.onnx'], check=True)
assert os.path.getsize(YUNET) > 100_000, 'YuNet download failed - run this cell again'
make_detector(YUNET)
print('YuNet OK')
''')

md("""
## 5. Celeb-DF v2
Uses an attached Kaggle dataset if you added one; otherwise downloads the zip from your private Drive link
(secret `CELEBDF_URL`), unpacks it in temporary space and deletes the zip. The link is never printed.
""")
code(r'''
def find_celebdf(base):
    for root, dirs, files in os.walk(base):
        if 'Celeb-real' in dirs and 'Celeb-synthesis' in dirs:
            return root
    return None

CDF = find_celebdf(INPUT) or find_celebdf(WORK)
if CDF is None:
    zips = glob.glob(INPUT + '/**/Celeb-DF*.zip', recursive=True)
    if zips:
        zpath = zips[0]
    else:
        from kaggle_secrets import UserSecretsClient
        url = UserSecretsClient().get_secret('CELEBDF_URL')
        import gdown
        zpath = os.path.join(WORK, 'celebdf.zip')
        t0 = time.time()
        got = gdown.download(url, zpath, quiet=True, fuzzy=True)
        assert got and os.path.getsize(zpath) > 1e9, ('Download failed (Google Drive often limits big files). '
            'Plan B: download the zip on your PC, upload it to Kaggle as a PRIVATE dataset, Add Input, run again.')
        print(f'downloaded {os.path.getsize(zpath) / 1e9:.1f} GB in {(time.time() - t0) / 60:.0f} min')
    subprocess.run(['unzip', '-q', '-o', zpath, '-d', os.path.join(WORK, 'celebdf')], check=True)
    if zpath.startswith(WORK):
        os.remove(zpath)
    CDF = find_celebdf(WORK)
assert CDF, 'Celeb-DF folders (Celeb-real, Celeb-synthesis) not found'
print('Celeb-DF at', CDF)
for d in ('Celeb-real', 'YouTube-real', 'Celeb-synthesis'):
    print(f'  {d:16s} {len(glob.glob(os.path.join(CDF, d, "*.mp4"))):5d} videos')
''')

md("## 6. DFDC sample videos (independent test)")
code(r'''
meta_files = glob.glob(INPUT + '/**/train_sample_videos/metadata.json', recursive=True)
DFDC = []
if meta_files:
    folder = os.path.dirname(meta_files[0])
    meta = json.load(open(meta_files[0]))
    DFDC = [(os.path.join(folder, k), 1 if v['label'] == 'FAKE' else 0) for k, v in sorted(meta.items())
            if os.path.exists(os.path.join(folder, k))]
print(f'DFDC: {len(DFDC)} videos ({sum(y for _, y in DFDC)} fake, {sum(1 - y for _, y in DFDC)} real)'
      if DFDC else 'DFDC not attached - Add Input -> Competitions -> Deepfake Detection Challenge (the test will be skipped)')
''')

md("""
## 7. Split
* **test** = Celeb-DF's official `List_of_testing_videos.txt` (never trained on)
* the rest is split **by person** (Celeb-DF ids): about 12% of the people go to **validation**, so the model is
  checked on faces it has never seen.
""")
code(r'''
import re
def label_of(rel):
    return 1 if rel.startswith('Celeb-synthesis') else 0

def person_of(rel):
    name = os.path.basename(rel)
    m = re.match(r'(id\d+)', name)
    return m.group(1) if m else 'yt_' + name           # YouTube-real videos: each its own group

test_rel = set()
lst = os.path.join(CDF, 'List_of_testing_videos.txt')
for line in open(lst):
    parts = line.split()
    if len(parts) == 2:
        test_rel.add(parts[1].strip())
all_rel = sorted(os.path.relpath(p, CDF).replace(os.sep, '/') for d in ('Celeb-real', 'YouTube-real', 'Celeb-synthesis')
                 for p in glob.glob(os.path.join(CDF, d, '*.mp4')))
rest = [r for r in all_rel if r not in test_rel]
people = sorted({person_of(r) for r in rest})
rng = random.Random(SEED)
val_people = set(rng.sample(people, max(1, int(len(people) * 0.12))))
SPLIT = {'train': [r for r in rest if person_of(r) not in val_people],
         'val': [r for r in rest if person_of(r) in val_people],
         'test': sorted(r for r in test_rel if os.path.exists(os.path.join(CDF, r)))}
for k, v in SPLIT.items():
    print(f'{k:5s}: {sum(1 - label_of(r) for r in v):4d} real  {sum(label_of(r) for r in v):5d} fake')
''')

md("## 8. Cut the faces (16 frames per video for val/test; more from real training videos)")
code(r'''
from concurrent.futures import ProcessPoolExecutor
FACES = os.path.join(WORK, 'faces')

def _extract(job):
    split, src, key, label, k = job
    det = make_detector(YUNET)
    out = []
    try:
        for i, (sec, crop) in enumerate(video_faces(src, det, k=k)):
            path = os.path.join(FACES, split, f'{key}_{i:02d}.jpg')
            cv2.imwrite(path, cv2.resize(crop, (256, 256), interpolation=cv2.INTER_AREA), [cv2.IMWRITE_JPEG_QUALITY, 95])
            out.append(path)
    except Exception as e:
        print('skipped', key, e)
    return split, key, label, out

def jobs_for(split, items):
    os.makedirs(os.path.join(FACES, split), exist_ok=True)
    for src, label in items:
        key = re.sub(r'[^A-Za-z0-9]+', '_', os.path.relpath(src, '/'))[-80:]
        k = (TRAIN_FRAMES_REAL if label == 0 else TRAIN_FRAMES_FAKE) if split == 'train' else FRAMES
        yield split, src, key, label, k

VIDEOS = {s: [(os.path.join(CDF, r), label_of(r)) for r in SPLIT[s]] for s in SPLIT}
if DFDC:
    VIDEOS['dfdc'] = DFDC
FACE_LIST = {s: [] for s in VIDEOS}           # split -> [(video_key, label, [face paths])]
t0 = time.time()
with ProcessPoolExecutor(WORKERS) as pool:
    for s in VIDEOS:
        for n, (split, key, label, paths) in enumerate(pool.map(_extract, list(jobs_for(s, VIDEOS[s])), chunksize=4)):
            FACE_LIST[split].append((key, label, paths))
        no_face = sum(1 for _, _, p in FACE_LIST[s] if not p)
        print(f'{s:5s}: {len(FACE_LIST[s])} videos, {sum(len(p) for _, _, p in FACE_LIST[s])} faces, '
              f'{no_face} videos without a face  ({(time.time() - t0) / 60:.1f} min)', flush=True)
''')

md("""
## 9. Training data - the SAME preparation CyberGuard uses (resize -> RGB -> /255 -> mean/std)
Training adds real-world damage: crops, flips, brightness, colour, low resolution, blur, noise and **JPEG
re-compression** (videos shared on WhatsApp / social media are heavily compressed).
""")
code(r'''
from torch.utils.data import Dataset, DataLoader

def prepare(bgr):
    img = cv2.resize(bgr, (IMG, IMG), interpolation=cv2.INTER_LINEAR)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    img = (img - np.array(MEAN, np.float32)) / np.array(STD, np.float32)
    return torch.from_numpy(np.transpose(img, (2, 0, 1)).copy())

def augment(bgr, rng):
    h, w = bgr.shape[:2]
    s = rng.uniform(0.75, 1.0)
    ch, cw = int(h * s), int(w * s)
    y, x = rng.integers(0, h - ch + 1), rng.integers(0, w - cw + 1)
    bgr = bgr[y:y + ch, x:x + cw]
    if rng.random() < 0.5:
        bgr = bgr[:, ::-1]
    if rng.random() < 0.6:
        bgr = cv2.convertScaleAbs(bgr, alpha=rng.uniform(0.7, 1.3), beta=rng.uniform(-30, 30))
    if rng.random() < 0.3:
        hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV).astype(np.float32)
        hsv[..., 0] = (hsv[..., 0] + rng.uniform(-8, 8)) % 180
        hsv[..., 1] *= rng.uniform(0.6, 1.4)
        bgr = cv2.cvtColor(np.clip(hsv, 0, 255).astype(np.uint8), cv2.COLOR_HSV2BGR)
    if rng.random() < 0.15:
        bgr = cv2.cvtColor(cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY), cv2.COLOR_GRAY2BGR)
    if rng.random() < 0.35:
        f = rng.uniform(0.3, 0.7)
        small = cv2.resize(bgr, (max(16, int(bgr.shape[1] * f)), max(16, int(bgr.shape[0] * f))), interpolation=cv2.INTER_AREA)
        bgr = cv2.resize(small, (bgr.shape[1], bgr.shape[0]), interpolation=cv2.INTER_LINEAR)
    if rng.random() < 0.3:
        k = int(rng.choice([3, 5]))
        bgr = cv2.GaussianBlur(bgr, (k, k), 0)
    if rng.random() < 0.25:
        bgr = np.clip(bgr.astype(np.float32) + rng.normal(0, rng.uniform(3, 12), bgr.shape), 0, 255).astype(np.uint8)
    if rng.random() < 0.7:
        ok, enc = cv2.imencode('.jpg', np.ascontiguousarray(bgr), [cv2.IMWRITE_JPEG_QUALITY, int(rng.integers(20, 90))])
        bgr = cv2.imdecode(enc, cv2.IMREAD_COLOR)
    return np.ascontiguousarray(bgr)

class Faces(Dataset):
    def __init__(self, items, train=False, jpeg_quality=None):
        self.items, self.train, self.q = items, train, jpeg_quality
    def __len__(self):
        return len(self.items)
    def __getitem__(self, i):
        path, y = self.items[i][:2]
        bgr = cv2.imread(path, cv2.IMREAD_COLOR)
        if self.train:
            bgr = augment(bgr, np.random.default_rng())
        if self.q:
            bgr = cv2.imdecode(cv2.imencode('.jpg', bgr, [cv2.IMWRITE_JPEG_QUALITY, self.q])[1], cv2.IMREAD_COLOR)
        return prepare(bgr), torch.tensor([float(y)])

def frames_of(split):
    """-> [(face_path, label, video_index)]"""
    return [(p, y, vi) for vi, (_, y, paths) in enumerate(FACE_LIST[split]) for p in paths]

def loader(items, train=False, q=None):
    return DataLoader(Faces(items, train, q), batch_size=BATCH, shuffle=train, num_workers=WORKERS,
                      pin_memory=DEV == 'cuda', drop_last=train and len(items) > BATCH)

train_items = frames_of('train')
random.shuffle(train_items)
n_real, n_fake = sum(1 for t in train_items if t[1] == 0), sum(1 for t in train_items if t[1] == 1)
POS_WEIGHT = n_real / max(1, n_fake)              # balances real vs fake faces
train_dl = loader(train_items, train=True)
print(f'training faces: {n_real} real, {n_fake} fake  (fake weight {POS_WEIGHT:.2f})')
''')

md("## 10. Model: EfficientNet-B0 (ImageNet pre-trained), one output: logit -> sigmoid = probability manipulated")
code(r'''
model = timm.create_model('efficientnet_b0', pretrained=not SMOKE, num_classes=1).to(DEV)
opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=LR, total_steps=EPOCHS * len(train_dl), pct_start=0.1)
scaler = torch.amp.GradScaler(enabled=DEV == 'cuda')
lossf = torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor([POS_WEIGHT], device=DEV))
SMOOTH = 0.1
''')

md("## 11. Train (the epoch with the best VIDEO-level validation AUC is kept)")
code(r'''
from sklearn.metrics import roc_auc_score
sig = lambda z: 1.0 / (1.0 + np.exp(-np.asarray(z, dtype=np.float64)))

@torch.no_grad()
def face_logits(items, q=None):
    model.eval(); out = []
    for x, _ in loader(items, q=q):
        with torch.autocast(DEV, dtype=torch.float16, enabled=DEV == 'cuda'):
            out.append(model(x.to(DEV, non_blocking=True)).float().cpu())
    return torch.cat(out).numpy().ravel() if out else np.zeros(0)

def video_scores(split, q=None):
    """-> (scores, labels) per video that has at least one face; score = mean face probability."""
    items = frames_of(split)
    if not items:
        return np.zeros(0), np.zeros(0)
    p = sig(face_logits(items, q))
    vids = np.array([t[2] for t in items])
    labels = np.array([FACE_LIST[split][v][1] for v in sorted(set(vids))])
    scores = np.array([p[vids == v].mean() for v in sorted(set(vids))])
    return scores, labels

def safe_auc(y, s):
    return float(roc_auc_score(y, s)) if len(set(y)) == 2 else float('nan')

best_auc, best_state = -1, None
for ep in range(EPOCHS):
    model.train(); t0 = time.time(); total = 0
    for i, (x, y) in enumerate(train_dl):
        x, y = x.to(DEV, non_blocking=True), y.to(DEV, non_blocking=True)
        opt.zero_grad(set_to_none=True)
        with torch.autocast(DEV, dtype=torch.float16, enabled=DEV == 'cuda'):
            loss = lossf(model(x), y * (1 - SMOOTH) + SMOOTH / 2)
        scaler.scale(loss).backward(); scaler.step(opt); scaler.update(); sched.step()
        total += loss.item()
        if i % 300 == 0:
            print(f'  epoch {ep + 1} step {i}/{len(train_dl)} loss {total / (i + 1):.4f}', flush=True)
    sv, yv = video_scores('val')
    auc = safe_auc(yv, sv)
    print(f'epoch {ep + 1}: loss {total / max(1, len(train_dl)):.4f}  validation video AUC {auc:.4f}  ({(time.time() - t0) / 60:.1f} min)')
    if auc > best_auc or best_state is None:
        best_auc, best_state = auc, {k: v.detach().clone() for k, v in model.state_dict().items()}
        torch.save(best_state, os.path.join(WORK, 'best.pt'))
model.load_state_dict(best_state)
print('best validation video AUC', round(best_auc, 4))
''')

md("""
## 12. Alert levels and honest results
* Celeb-DF test list split at random into **half A** (chooses the levels) and **half B** (reported, never used to choose):
  **alert** = only 1% of REAL videos in half A reach it, **verify** = 5%.
* **DFDC** (a different dataset) and a **JPEG quality 35** copy of half B show how it holds up outside the lab.
""")
code(r'''
st, yt = video_scores('test')
sq, yq = video_scores('test', q=35)
rng = np.random.default_rng(0)
idx = rng.permutation(len(yt)); cal, ev = idx[: len(idx) // 2], idx[len(idx) // 2:]
real_cal = st[cal][yt[cal] == 0]
thr_alert = float(np.quantile(real_cal, 0.99)) if len(real_cal) else 0.99
thr_verify = float(min(np.quantile(real_cal, 0.95), thr_alert)) if len(real_cal) else 0.9

def report(s, y):
    if not len(y):
        return {'n': 0}
    return {'n': int(len(y)), 'real': int((y == 0).sum()), 'fake': int((y == 1).sum()), 'auc': round(safe_auc(y, s), 4),
            'caught_at_alert': round(float((s[y == 1] >= thr_alert).mean()), 4) if (y == 1).any() else None,
            'false_alarms_at_alert': round(float((s[y == 0] >= thr_alert).mean()), 4) if (y == 0).any() else None,
            'caught_at_verify': round(float((s[y == 1] >= thr_verify).mean()), 4) if (y == 1).any() else None,
            'false_alarms_at_verify': round(float((s[y == 0] >= thr_verify).mean()), 4) if (y == 0).any() else None}

sv, yv = video_scores('val')
RESULTS = {'validation_celebdf_unseen_people': report(sv, yv),
           'test_celebdf_half_A_levels_chosen_here': report(st[cal], yt[cal]),
           'test_celebdf_half_B_honest': report(st[ev], yt[ev]),
           'test_celebdf_half_B_jpeg_quality_35': report(sq[ev], yq[ev])}
if DFDC:
    sd, yd = video_scores('dfdc')
    RESULTS['test_dfdc_independent'] = report(sd, yd)
NO_FACE = {s: sum(1 for _, _, p in FACE_LIST[s] if not p) for s in FACE_LIST}
print(f'alert level {thr_alert:.4f}   verify level {thr_verify:.4f}')
for k, r in RESULTS.items():
    print('\n' + k); [print(f'   {a:24s} {b}') for a, b in r.items()]
print('\nvideos without any face (no verdict):', NO_FACE)
''')

md("""
## 13. Baseline (optional): CyberGuard's existing **image** face model on the same video faces
Only runs if you attached `deepfake_image.onnx` + `deepfake_image.json`. Shows how much the new video model adds.
""")
code(r'''
BASELINE = None
onx = glob.glob(INPUT + '/**/deepfake_image.onnx', recursive=True)
if onx and os.path.exists(onx[0].replace('.onnx', '.json')):
    import onnxruntime as ort
    bmeta = json.load(open(onx[0].replace('.onnx', '.json')))
    bs = ort.InferenceSession(onx[0], providers=['CPUExecutionProvider'])
    def bprep(bgr):
        size = int(bmeta.get('input_size', 224))
        img = cv2.cvtColor(cv2.resize(bgr, (size, size)), cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
        img = (img - np.array(bmeta['mean'], np.float32)) / np.array(bmeta['std'], np.float32)
        return np.transpose(img, (2, 0, 1))[None].astype(np.float32)
    def b_scores(split):
        items = frames_of(split); vids = np.array([t[2] for t in items])
        p = np.array([sig(bs.run(None, {bs.get_inputs()[0].name: bprep(cv2.imread(t[0]))})[0].ravel()[0]) for t in items])
        u = sorted(set(vids))
        return np.array([p[vids == v].mean() for v in u]), np.array([FACE_LIST[split][v][1] for v in u])
    BASELINE = {}
    for s in ['test'] + (['dfdc'] if DFDC else []):
        bsc, by = b_scores(s)
        BASELINE[s] = {'n': int(len(by)), 'auc': round(safe_auc(by, bsc), 4)}
    print('existing image model on video faces (AUC):', BASELINE)
else:
    print('baseline skipped (deepfake_image.onnx not attached)')
''')

md("## 14. Export to ONNX (CPU, no PyTorch needed on the PC) and check it gives the same answers")
code(r'''
import onnxruntime as ort
model.eval().cpu()
onnx_path = os.path.join(OUT, 'deepfake_video.onnx')
torch.onnx.export(model, torch.randn(1, 3, IMG, IMG), onnx_path, input_names=['input'], output_names=['logit'],
                  dynamic_axes={'input': {0: 'batch'}, 'logit': {0: 'batch'}}, opset_version=17, dynamo=False)
sess = ort.InferenceSession(onnx_path, providers=['CPUExecutionProvider'])
items = frames_of('test')[:16] or train_items[:16]
x = torch.stack([Faces(items)[i][0] for i in range(len(items))])
with torch.no_grad():
    ref = model(x).numpy()
got = sess.run(None, {'input': x.numpy()})[0]
diff = float(np.abs(ref - got).max())
print('largest difference PyTorch vs ONNX:', diff)
assert diff < 1e-3
print('ONNX OK,', round(os.path.getsize(onnx_path) / 1e6, 1), 'MB')
''')

md("## 15. The description file CyberGuard reads")
code(r'''
import datetime
meta = {
    'kind': 'cyberguard-deepfake-video', 'version': 1,
    'architecture': 'EfficientNet-B0 on face crops; video score = mean face probability',
    'output': 'logit per face; sigmoid(logit) = probability the face is manipulated',
    'detects': 'face swap / face re-enactment (Celeb-DF style). NOT fully AI-generated scenes, NOT lip-sync, NOT voice.',
    'dataset': 'Celeb-DF v2 (train, official test list held out); independent test: DFDC sample videos (Meta)',
    'input_size': IMG, 'mean': MEAN, 'std': STD,
    'face_margin': MARGIN, 'frames_per_video': FRAMES, 'min_face': MIN_FACE, 'max_side': MAX_SIDE,
    'aggregation': 'mean', 'min_faces_for_verdict': 3,
    'thr_alert': thr_alert, 'thr_verify': thr_verify,
    'training': {'faces': len(train_items), 'real_faces': n_real, 'fake_faces': n_fake, 'epochs': EPOCHS,
                 'batch': BATCH, 'lr': LR, 'label_smoothing': SMOOTH,
                 'augmentations': 'crop, flip, brightness/contrast, colour, grayscale, low resolution, blur, noise, JPEG 20-90',
                 'split': 'by person (Celeb-DF id); levels chosen on half A of the official test list'},
    'results': RESULTS, 'baseline_image_model_auc': BASELINE, 'videos_without_face': NO_FACE,
    'trained_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
}
json.dump(meta, open(os.path.join(OUT, 'deepfake_video.json'), 'w'), indent=2)
print(json.dumps(meta, indent=2))
print('\nDONE - download deepfake_video.onnx and deepfake_video.json from the Output tab.')
''')

nb = {"cells": cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                                   "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
out = os.path.join(HERE, "CyberGuard_Deepfake_Video_Kaggle.ipynb")
json.dump(nb, open(out, "w", encoding="utf-8"), indent=1)
print("wrote", out, len(cells), "cells")
