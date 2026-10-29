"""Audio in, clean 16 kHz speech out - ONE implementation shared by the Colab training notebook
(docs/colab/CyberGuard_Voice_Colab.ipynb copies this file word for word) and the scanner on the PC, so the voice
model sees exactly the same kind of audio in training and in real use.

  any voice note / recording (WhatsApp .opus/.ogg, .m4a, .mp3, .aac, .wav, .flac, .webm ...)
     --PyAV (bundled FFmpeg; the file is only decoded, never run)--> mono, 16 kHz, float32
     --trim silence at both ends (a known shortcut: in ASVspoof 2019 real clips have longer silences than fakes)
     --cut into 4-second clips (short audio is repeated up to 4 s) --> each clip normalised (zero mean, unit variance,
       exactly what the XLS-R speech model expects)

Also: codec round-trips (training augmentation: phone-quality compression applied to real AND fake clips alike, so
compression can never be a shortcut) and file facts for the forensics checks (format, codec, sample rate, tags).
Only NumPy + PyAV.
"""
from __future__ import annotations

import io
import math

import numpy as np

SR = 16_000
CLIP_S = 4.0
CLIP = int(SR * CLIP_S)
MIN_SPEECH_S = 1.0
MAX_SECONDS = 600            # at most 10 minutes of a recording are decoded
MAX_CLIPS = 15               # at most 15 clips (1 minute of speech, spread over the recording) are scored


def _av():
    import av                # imported here so the module loads (and its tests run) where PyAV is missing
    return av


def decode(src, sr: int | None = SR, max_seconds: float = MAX_SECONDS) -> tuple[np.ndarray, int]:
    """(mono float32 samples in [-1, 1], sample rate). src: a path or bytes. sr=None keeps the file's own rate.
    Raises ValueError for anything that is not decodable audio."""
    av = _av()
    try:
        container = av.open(io.BytesIO(src) if isinstance(src, (bytes, bytearray)) else src)
    except (av.error.FFmpegError, OSError, ValueError) as exc:          # type: ignore[attr-defined]
        raise ValueError(f"not a readable audio file ({type(exc).__name__})") from None
    try:
        streams = [s for s in container.streams if s.type == "audio"]
        if not streams:
            raise ValueError("the file has no audio track")
        stream = streams[0]
        rate = sr or stream.codec_context.sample_rate or SR
        resampler = av.AudioResampler(format="flt", layout="mono", rate=rate)
        chunks, n, limit = [], 0, int(rate * max_seconds)
        try:
            for frame in container.decode(stream):
                for out in resampler.resample(frame):
                    a = out.to_ndarray().reshape(-1)
                    chunks.append(a)
                    n += a.size
                if n >= limit:
                    break
            for out in resampler.resample(None):                          # flush
                chunks.append(out.to_ndarray().reshape(-1))
        except (av.error.FFmpegError, ValueError):                        # type: ignore[attr-defined]
            if not chunks:
                raise ValueError("the audio could not be decoded") from None   # cut-off file: keep what was read
    finally:
        container.close()
    x = np.concatenate(chunks)[:limit].astype(np.float32) if chunks else np.zeros(0, np.float32)
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    return np.clip(x, -1.0, 1.0), rate


def file_facts(src) -> dict:
    """Format / codec / sample rate / channels / duration / bit rate / metadata tags (no audio decoded)."""
    av = _av()
    try:
        c = av.open(io.BytesIO(src) if isinstance(src, (bytes, bytearray)) else src)
    except (av.error.FFmpegError, OSError, ValueError):                   # type: ignore[attr-defined]
        return {}
    try:
        s = next((s for s in c.streams if s.type == "audio"), None)
        tags = {str(k).lower(): str(v)[:200] for k, v in dict(c.metadata or {}).items()}
        if s is not None:
            tags.update({str(k).lower(): str(v)[:200] for k, v in dict(s.metadata or {}).items()})
        return {"container": c.format.name if c.format else "", "codec": s.codec_context.name if s else "",
                "sampleRate": int(s.codec_context.sample_rate or 0) if s else 0,
                "channels": int(s.codec_context.channels or 0) if s else 0,
                "seconds": round(float(c.duration) / 1_000_000, 2) if c.duration else None,
                "bitRate": int(c.bit_rate or 0), "tags": tags}
    finally:
        c.close()


def trim_silence(x: np.ndarray, sr: int = SR, floor_db: float = -45.0, rel_db: float = -35.0) -> np.ndarray:
    """Cut silence at the start and end (20 ms frames quieter than both an absolute floor and 35 dB under the
    loudest frame). Silence in the middle is kept - pauses are part of speech."""
    hop = max(1, int(sr * 0.02))
    n = x.size // hop
    if n == 0:
        return x
    frames = x[: n * hop].reshape(n, hop)
    db = 10 * np.log10(np.mean(frames.astype(np.float64) ** 2, axis=1) + 1e-12)
    voiced = np.where(db > max(floor_db, db.max() + rel_db))[0]
    if voiced.size == 0:
        return x[:0]
    return x[voiced[0] * hop: (voiced[-1] + 1) * hop]


def normalize(clip: np.ndarray) -> np.ndarray:
    """Zero mean, unit variance - the input normalisation the XLS-R / wav2vec2 models were trained with."""
    c = clip.astype(np.float32)
    return ((c - c.mean()) / np.sqrt(c.var() + 1e-7)).astype(np.float32)


def clips(x: np.ndarray, max_clips: int = MAX_CLIPS) -> list[np.ndarray]:
    """Speech -> normalised 4-second clips. Short speech (1-4 s) is repeated up to 4 s; under 1 s -> no clips.
    Long speech: clips spread evenly over the whole recording (not just the start)."""
    if x.size < int(SR * MIN_SPEECH_S):
        return []
    if x.size < CLIP:
        x = np.tile(x, math.ceil(CLIP / x.size))[:CLIP]
    n = x.size // CLIP
    starts = [i * CLIP for i in range(n)]
    if x.size - n * CLIP >= SR * MIN_SPEECH_S:            # the tail is worth a clip of its own (aligned to the end)
        starts.append(x.size - CLIP)
    if len(starts) > max_clips:
        idx = np.linspace(0, len(starts) - 1, max_clips).round().astype(int)
        starts = [starts[i] for i in idx]
    return [normalize(x[s: s + CLIP]) for s in starts]


def speech(src) -> np.ndarray:
    """File -> 16 kHz mono speech with the silent ends trimmed."""
    x, _ = decode(src)
    return trim_silence(x)


# ---- training augmentation (used by the notebook; harmless on the PC) ------------------------------------------
_CODECS = {"opus": ("ogg", "libopus", 48_000), "mp3": ("mp3", "libmp3lame", 16_000), "aac": ("adts", "aac", 16_000)}


def codec_roundtrip(x: np.ndarray, codec: str = "opus", bitrate: int = 16_000) -> np.ndarray:
    """Encode 16 kHz audio with a phone / messenger codec and decode it again (in memory)."""
    av = _av()
    fmt, enc, rate = _CODECS[codec]
    buf = io.BytesIO()
    out = av.open(buf, mode="w", format=fmt)
    st = out.add_stream(enc, rate=rate)
    st.bit_rate = bitrate
    st.layout = "mono"
    res = av.AudioResampler(format=st.format.name if st.format else "s16", layout="mono", rate=rate)
    frame = av.AudioFrame.from_ndarray(x.astype(np.float32).reshape(1, -1), format="flt", layout="mono")
    frame.sample_rate = SR
    for f in res.resample(frame) + res.resample(None):
        for p in st.encode(f):
            out.mux(p)
    for p in st.encode(None):
        out.mux(p)
    out.close()
    y, _ = decode(buf.getvalue())
    return y[: x.size] if y.size >= x.size else np.pad(y, (0, x.size - y.size))


def telephone(x: np.ndarray) -> np.ndarray:
    """Narrow-band phone line: down to 8 kHz and back (keeps only 300-3400 Hz-ish speech band)."""
    import numpy.fft as F
    spec = F.rfft(x)
    freqs = F.rfftfreq(x.size, 1 / SR)
    spec[(freqs < 300) | (freqs > 3400)] = 0
    return F.irfft(spec, n=x.size).astype(np.float32)
