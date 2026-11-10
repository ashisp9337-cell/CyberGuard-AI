"""
(10 Nov) LIP-SYNC check for videos (Deepfake module): does the mouth move when the voice speaks?

The most common Indian deepfake scam video is a real politician / celebrity / bank official whose lips were re-made
to say something else (Wav2Lip-style), or a real clip with a cloned voice laid over it. In a genuine talking video the
mouth moves when there is speech and rests in the pauses; dubbed or badly re-synced videos break that pattern.

How (no trained model, no internet - OpenCV YuNet face landmarks + the sound):
  1. the first MAX_SECONDS of the video, 12.5 frames per second: the largest face, its two mouth corners and nose ->
     MOUTH OPENNESS (an open mouth shows its dark inside) and MOUTH MOVEMENT (how much the mouth changes);
  2. the sound at the same moments: SPEECH ENERGY (loudness in 80 ms windows, in decibels) and its changes;
  3. the correlation of openness with loudness and of movement with loudness changes, allowing the sound to be up
     to 0.32 s early or late (normal for phone videos); the stronger agreement counts.

Honest limits - this is a HINT, never proof, and it can only ask you to check (at most 55/100, "verify"):
  * it was NOT trained or measured on a labelled lip-sync dataset (FakeAVCeleb needs a signed request), so its error
    rate is unknown; a good modern lip-sync fake can pass, and a real video can fail;
  * real videos also fail it when the voice is not the visible person's (voice-over, interview, background music,
    several people talking, a face turned away), so the result always says so;
  * it only runs with a face in most frames and speech in a good part of the sound - otherwise "not checked".
"""
from __future__ import annotations

import numpy as np

MAX_SECONDS = 20.0
STEP = 0.08               # seconds between looked-at frames (12.5 per second)
MAX_LAG = 4               # steps: the sound may be up to 0.32 s early or late
MIN_PAIRS = 100           # >= 8 seconds of face + sound
MIN_FACE_SHARE = 0.8
MIN_SPEECH_SHARE = 0.4
IN_SYNC = 0.25             # correlation needed for "in sync" (and above the chance level)
MISMATCH_MARGIN = 0.02     # "mismatch" = no better than the sound from random other moments (+ this margin)
MAX_SIDE = 640


def _openness(gray: np.ndarray, f) -> float | None:
    """How OPEN the mouth looks: an open mouth shows the dark inside, so the centre of the mouth gets darker than the
    rest of the face (in face-brightness units, so light / skin colour does not matter)."""
    x, y, w, h = (int(v) for v in f[:4])
    face = gray[max(y, 0):y + h, max(x, 0):x + w]
    if face.size < 400:
        return None
    mx0, mx1 = sorted((f[10], f[12]))
    my, mw = (f[11] + f[13]) / 2, max(abs(f[12] - f[10]), 4.0)
    cx = (mx0 + mx1) / 2
    x0, x1 = int(cx - 0.25 * mw), int(cx + 0.25 * mw)
    y0, y1 = int(my - 0.18 * mw), int(my + 0.30 * mw)
    centre = gray[max(y0, 0):max(y1, 0), max(x0, 0):max(x1, 0)]
    if centre.size < 6:
        return None
    return float((face.mean() - centre.mean()) / (face.std() + 1e-3))


def _mouth_patch(gray: np.ndarray, f) -> np.ndarray | None:
    """f = one YuNet row: x y w h | right eye | left eye | nose | right mouth corner | left mouth corner | score."""
    import cv2
    nose_y = f[9]
    mx0, mx1 = sorted((f[10], f[12]))
    my = (f[11] + f[13]) / 2
    mw = max(mx1 - mx0, 4.0)
    drop = max(my - nose_y, 4.0)
    x0, x1 = int(mx0 - 0.25 * mw), int(mx1 + 0.25 * mw)
    y0, y1 = int(nose_y + 0.3 * drop), int(my + 0.9 * drop)
    h, w = gray.shape
    x0, y0, x1, y1 = max(x0, 0), max(y0, 0), min(x1, w), min(y1, h)
    if x1 - x0 < 8 or y1 - y0 < 6:
        return None
    p = cv2.resize(gray[y0:y1, x0:x1], (32, 20), interpolation=cv2.INTER_AREA).astype(np.float32)
    return (p - p.mean()) / (p.std() + 1e-3)


def mouth_series(path: str, detector_path: str) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """-> (times, mouth movement per step, mouth openness per step); NaN = no face in that frame."""
    import av
    import cv2
    from app.detectors.video_frames import create_yunet
    det = None
    times, moves, opens = [], [], []
    prev, next_t = None, 0.0
    with av.open(path) as c:
        vs = [s for s in c.streams if s.type == "video"]
        if not vs:
            return np.array([]), np.array([]), np.array([])
        for frame in c.decode(vs[0]):
            t = float(frame.time) if frame.time is not None else next_t
            if t > MAX_SECONDS:
                break
            if t + 1e-6 < next_t:
                continue
            next_t = t + STEP
            bgr = frame.to_ndarray(format="bgr24")
            s = MAX_SIDE / max(bgr.shape[:2])
            if s < 1:
                bgr = cv2.resize(bgr, (int(bgr.shape[1] * s), int(bgr.shape[0] * s)), interpolation=cv2.INTER_AREA)
            if det is None:
                det = create_yunet(cv2, detector_path, (bgr.shape[1], bgr.shape[0]))
            det.setInputSize((bgr.shape[1], bgr.shape[0]))
            _, faces = det.detect(bgr)
            patch, op = None, None
            if faces is not None and len(faces):
                f = max(faces, key=lambda r: r[2] * r[3])
                if f[2] >= 40:
                    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
                    patch, op = _mouth_patch(gray, f), _openness(gray, f)
            times.append(t)
            moves.append(float(np.mean(np.abs(patch - prev))) if patch is not None and prev is not None else np.nan)
            opens.append(op if op is not None else np.nan)
            prev = patch
    return np.array(times), np.array(moves), np.array(opens)


def speech_energy(path: str, times: np.ndarray) -> np.ndarray:
    """Loudness (dB) of the sound in an 80 ms window at each time; NaN when the video has no sound."""
    from app.detectors import voice_audio
    try:
        x, sr = voice_audio.decode(path, sr=16000, max_seconds=MAX_SECONDS + 1)
    except Exception:
        return np.full(len(times), np.nan)
    if x is None or len(x) < 1600:
        return np.full(len(times), np.nan)
    half = int(0.04 * sr)
    out = []
    for t in times:
        i = int(t * sr)
        seg = x[max(i - half, 0): i + half]
        out.append(10 * np.log10(np.mean(seg.astype(np.float64) ** 2) + 1e-10) if len(seg) else np.nan)
    return np.array(out)


def _best_lag(a_all: np.ndarray, b_all: np.ndarray) -> tuple[float, int]:
    best = (-2.0, 0)
    for lag in range(-MAX_LAG, MAX_LAG + 1):
        a = a_all[max(lag, 0): len(a_all) + min(lag, 0)]
        b = b_all[max(-lag, 0): len(b_all) + min(-lag, 0)]
        m = ~(np.isnan(a) | np.isnan(b))
        if m.sum() < MIN_PAIRS or np.std(a[m]) < 1e-6 or np.std(b[m]) < 1e-6:
            continue
        r = float(np.corrcoef(a[m], b[m])[0, 1])
        if r > best[0]:
            best = (r, lag)
    return best


def correlate(moves: np.ndarray, energy: np.ndarray, opens: np.ndarray | None = None) -> dict:
    """Best agreement between the mouth and the speech within +-MAX_LAG steps: mouth OPENNESS with loudness, and mouth
    MOVEMENT with changes in loudness (syllables starting / stopping); the stronger of the two counts."""
    if opens is None:
        opens = np.full(len(moves), np.nan)
    ok = ~((np.isnan(moves) & np.isnan(opens)) | np.isnan(energy))
    n_face = int(np.sum(~(np.isnan(moves) & np.isnan(opens))))
    speech = energy[~np.isnan(energy)]
    floor = (np.percentile(speech, 10) if len(speech) else 0) + 10          # 10 dB above the quietest moments
    speech_share = float(np.mean(speech > floor)) if len(speech) else 0.0
    out = {"pairs": int(ok.sum()), "faceShare": n_face / max(len(moves), 1), "speechShare": speech_share,
           "r": None, "lagSeconds": None}
    if ok.sum() < MIN_PAIRS:
        return out
    change = np.abs(np.diff(energy, prepend=np.nan))
    best = max(_best_lag(opens, energy), _best_lag(moves, change))
    if best[0] > -2:
        out["r"], out["lagSeconds"] = round(best[0], 3), round(best[1] * STEP, 2)
        # CHANCE level: the same mouth against the sound from 2+ seconds elsewhere in the video. A real talking video
        # agrees with its own moment clearly better than with random moments; a mismatched one does not.
        n = len(energy)
        chance = []
        for k in np.linspace(25, n - 25, 16).astype(int) if n > 80 else []:
            e2, c2 = np.roll(energy, k), np.roll(change, k)
            r2 = max(_best_lag(opens, e2), _best_lag(moves, c2))[0]
            if r2 > -2:
                chance.append(r2)
        if len(chance) >= 8:
            out["chance"] = round(float(np.median(chance)), 3)
            out["chanceHigh"] = round(float(np.percentile(chance, 90)), 3)
    return out


def check(path: str, detector_path: str) -> dict:
    """-> {"status": "in_sync" | "weak" | "mismatch" | "not_checked", "reason", "r", "lagSeconds", ...}"""
    try:
        times, moves, opens = mouth_series(path, detector_path)
    except Exception as e:
        return {"status": "not_checked", "reason": f"the video could not be read ({e.__class__.__name__})"}
    if len(times) == 0:
        return {"status": "not_checked", "reason": "no video picture"}
    energy = speech_energy(path, times)
    if np.all(np.isnan(energy)):
        return {"status": "not_checked", "reason": "the video has no sound"}
    c = correlate(moves, energy, opens)
    if c["faceShare"] < MIN_FACE_SHARE or c["pairs"] < MIN_PAIRS:
        return c | {"status": "not_checked",
                    "reason": f"a clear face was visible in only {c['faceShare'] * 100:.0f}% of the first "
                              f"{min(times[-1], MAX_SECONDS):.0f} s (needs {MIN_FACE_SHARE * 100:.0f}% and 8 s)"}
    if c["speechShare"] < MIN_SPEECH_SHARE:
        return c | {"status": "not_checked", "reason": "there is too little speech in the sound to compare"}
    if c["r"] is None:
        return c | {"status": "not_checked", "reason": "the mouth or the sound did not change enough to compare"}
    if "chance" not in c:
        return c | {"status": "not_checked", "reason": "the video is too short to compare with chance"}
    if c["r"] >= max(IN_SYNC, c["chanceHigh"]):
        status = "in_sync"                       # clearly better than random moments
    elif c["r"] <= c["chance"] + MISMATCH_MARGIN:
        status = "mismatch"                      # the mouth fits its own sound no better than random sound
    else:
        status = "weak"
    return c | {"status": status, "reason": ""}
