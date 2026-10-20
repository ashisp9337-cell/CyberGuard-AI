"""
AI-GENERATED image detection (Deepfake module: every image upload, and "AI-Generated Multimedia").

Two independent checks:

1. PROVENANCE (proof, no model needed) - what the generator itself wrote into the file:
     * C2PA "Content Credentials" saying the picture was made by AI (OpenAI/DALL-E, Adobe Firefly, Google,
       Microsoft Designer, ... add them) - IPTC DigitalSourceType "trainedAlgorithmicMedia"
     * Stable Diffusion / ComfyUI / InvokeAI / NovelAI generation settings in PNG text chunks
     * a generator's name in the metadata (EXIF Software, XMP CreatorTool, ...)
   Found  -> proof the picture is (partly) AI-made.
   Absent -> proves nothing: screenshots, WhatsApp and re-saving remove it. That is why there is also:

2. TRAINED MODEL (pattern) - CLIP ViT-L/14 image encoder (frozen) + one linear layer, trained on Google Colab
   on real photos vs pictures from many generators (the "UnivFD" approach, Ojha et al., CVPR 2023: CLIP features
   generalise to generators that were not in the training data far better than a normally trained CNN).
   Files from docs/colab/CyberGuard_AI_Image_Colab.ipynb, put into backend/app/ml/models/:
       ai_image.onnx    the model (input: 1x3x224x224 CLIP-normalised RGB, output: logit)
       ai_image.json    input size, colour normalisation, alert levels, honest test results

Runs on the CPU with onnxruntime + Pillow. Missing files -> ModelUnavailable, never a made-up verdict.
"""
from __future__ import annotations

import json
import os
import re
import struct

import numpy as np

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "ai_image.onnx")
META_PATH = os.path.join(MODELS_DIR, "ai_image.json")
KIND = "cyberguard-ai-image"
MAX_VIEWS = 3                      # long pictures: left / centre / right crops, the most AI-looking one decides
MAX_META_BYTES = 4 * 1024 * 1024   # metadata is near the start of the file; never read huge files whole

_cache: dict = {}


class ModelUnavailable(Exception):
    """A model file or onnxruntime is missing, so the model gives no verdict."""


# ------------------------------------------------------------------------------------------------------------
# 1. Provenance
# ------------------------------------------------------------------------------------------------------------
GENERATORS = [  # (regex on metadata text, display name)
    (r"midjourney", "Midjourney"), (r"dall[\s\-·]?e", "DALL-E"), (r"openai", "OpenAI"),
    (r"stable[\s_\-]?diffusion|stability\.?ai|sdxl", "Stable Diffusion"), (r"adobe\s*firefly", "Adobe Firefly"),
    (r"novelai", "NovelAI"), (r"leonardo\.?ai", "Leonardo.Ai"), (r"ideogram", "Ideogram"),
    (r"google\s*(ai|imagen|gemini)|imagen\s*\d|gemini", "Google Imagen / Gemini"), (r"bing image creator|designer\.microsoft|microsoft designer", "Microsoft Designer / Bing"),
    (r"black forest labs|\bflux(\.1)?\b", "FLUX"), (r"comfyui", "ComfyUI"), (r"automatic1111|a1111", "AUTOMATIC1111"),
    (r"invokeai", "InvokeAI"), (r"runway(ml)?", "Runway"), (r"playground\s?ai", "Playground AI"),
    (r"nightcafe", "NightCafe"), (r"craiyon", "Craiyon"), (r"canva\s+(magic|ai|dream)", "Canva AI"),
    (r"meta\s*ai|imagine with meta", "Meta AI"), (r"grok|aurora\s+by\s+xai|\bxai\b", "xAI Grok"),
]
_GEN_RE = [(re.compile(p, re.I), n) for p, n in GENERATORS]
AI_SOURCE_TYPES = (b"trainedAlgorithmicMedia", b"compositeWithTrainedAlgorithmicMedia", b"algorithmicMedia")
SD_KEYS = ("parameters", "prompt", "workflow", "sd-metadata", "invokeai_metadata", "dream", "negative_prompt",
           "generation_data", "aigc")


def _metadata_blocks(data: bytes) -> list[tuple[str, bytes]]:
    """Return (where, bytes) for the metadata parts of a JPEG / PNG / WebP file (not the pixels)."""
    out = []
    if data[:2] == b"\xff\xd8":                                         # JPEG: APPn + COM segments before the scan
        i = 2
        while i + 4 <= len(data) and data[i] == 0xFF:
            marker = data[i + 1]
            if marker in (0xD9, 0xDA):                                  # end / start of scan: pixels follow
                break
            if marker == 0x01 or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
            if 0xE0 <= marker <= 0xEF or marker == 0xFE:
                out.append((f"JPEG APP{marker - 0xE0}" if marker != 0xFE else "JPEG comment", data[i + 4:i + 2 + length]))
            i += 2 + length
    elif data[:8] == b"\x89PNG\r\n\x1a\n":                              # PNG: text, exif, c2pa chunks
        i = 8
        while i + 8 <= len(data):
            length = struct.unpack(">I", data[i:i + 4])[0]
            ctype = data[i + 4:i + 8]
            if ctype in (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"caBX"):
                body = data[i + 8:i + 8 + length]
                if ctype == b"zTXt":
                    try:
                        import zlib
                        key, _, rest = body.partition(b"\x00")
                        body = key + b"\x00" + zlib.decompress(rest[1:])
                    except Exception:
                        pass
                elif ctype == b"iTXt":
                    key, _, rest = body.partition(b"\x00")
                    if len(rest) > 2 and rest[0] == 1:                    # compressed iTXt
                        try:
                            import zlib
                            parts = rest[2:].split(b"\x00", 2)
                            body = key + b"\x00" + zlib.decompress(parts[2])
                        except Exception:
                            pass
                out.append((f"PNG {ctype.decode()}", body))
            if ctype == b"IEND":
                break
            i += 12 + length
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":                  # WebP: EXIF / XMP chunks
        i = 12
        while i + 8 <= len(data):
            ctype, length = data[i:i + 4], struct.unpack("<I", data[i + 4:i + 8])[0]
            if ctype in (b"EXIF", b"XMP "):
                out.append((f"WebP {ctype.decode().strip()}", data[i + 8:i + 8 + length]))
            i += 8 + length + (length & 1)
    else:                                                               # other formats: the first 64 KB
        out.append(("file header", data[:65536]))
    return out


def provenance(file_path: str) -> dict:
    """-> {"proof": bool, "findings": [{"label", "detail", "proof"}], "hasContentCredentials": bool}"""
    try:
        with open(file_path, "rb") as f:
            data = f.read(MAX_META_BYTES)
    except OSError:
        return {"proof": False, "findings": [], "hasContentCredentials": False}
    blocks = _metadata_blocks(data)
    meta = b"\n".join(b for _, b in blocks)
    findings = []

    has_c2pa = b"c2pa" in meta or b"jumb" in meta
    ai_type = next((t for t in AI_SOURCE_TYPES if t in meta), None)
    if ai_type:
        partly = ai_type == b"compositeWithTrainedAlgorithmicMedia"
        findings.append({"label": "Content Credentials: made with AI" if not partly else "Content Credentials: partly made with AI",
                         "detail": (f"The file's provenance data (C2PA / IPTC) records the source as "
                                    f"'{ai_type.decode()}' - the tool that made it declared it as "
                                    + ("an AI edit of a real picture (e.g. generative fill)." if partly
                                       else "generated by an AI model.")),
                         "proof": True})
    elif has_c2pa:
        findings.append({"label": "Content Credentials present", "detail":
                         "The file carries C2PA Content Credentials but they do not declare AI generation "
                         "(e.g. a camera or editing app signed it). Check them at contentcredentials.org/verify.",
                         "proof": False})

    text = meta.decode("latin-1", errors="ignore")
    for where, body in blocks:
        if not where.startswith("PNG") or b"\x00" not in body:
            continue
        key = body.split(b"\x00", 1)[0].decode("latin-1", errors="ignore").strip().lower()
        val = body.split(b"\x00", 1)[1][:300].decode("utf-8", errors="ignore")
        if key in SD_KEYS and (key != "prompt" or "{" in val or "steps" in text.lower()):
            sample = re.sub(r"\s+", " ", val.strip(" \x00\x01"))[:120]
            findings.append({"label": "AI generation settings stored in the image",
                             "detail": f"PNG text field '{key}' holds image-generator settings (prompt / sampler / seed): "
                                       f"\"{sample}...\" - written by Stable Diffusion-style tools.",
                             "proof": True})
            break
    if re.search(r"Steps:\s*\d+.*Sampler:", text, re.S) and not any("settings" in f["label"] for f in findings):
        findings.append({"label": "AI generation settings stored in the image",
                         "detail": "The metadata contains Stable Diffusion parameters (Steps / Sampler / CFG / Seed).",
                         "proof": True})

    names = sorted({n for rx, n in _GEN_RE if rx.search(text)})
    if names:
        findings.append({"label": "AI generator named in the metadata",
                         "detail": "The image's metadata mentions: " + ", ".join(names) + ".", "proof": True})
    return {"proof": any(f["proof"] for f in findings), "findings": findings, "hasContentCredentials": has_c2pa}


# ------------------------------------------------------------------------------------------------------------
# 2. Trained model
# ------------------------------------------------------------------------------------------------------------
def _mtime(path):
    return os.path.getmtime(path) if os.path.exists(path) else None


def load():
    """-> (onnx session, metadata). Reloads when the files change."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(META_PATH):
        raise ModelUnavailable("ai_image.onnx / ai_image.json are not in app/ml/models yet")
    key = (_mtime(MODEL_PATH), _mtime(META_PATH))
    if _cache.get("key") != key:
        try:
            import onnxruntime as ort
        except ImportError as e:
            raise ModelUnavailable("onnxruntime is not installed (pip install onnxruntime)") from e
        with open(META_PATH, encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("kind") != KIND:
            raise ModelUnavailable("ai_image.json is not a CyberGuard AI-image model description")
        sess = ort.InferenceSession(MODEL_PATH, providers=["CPUExecutionProvider"])
        _cache.update(key=key, session=sess, meta=meta)
    return _cache["session"], _cache["meta"]


def views(img, size: int) -> list:
    """Shorter side -> size (bicubic, exactly like training), then up to MAX_VIEWS square crops along the long side."""
    from PIL import Image
    img = img.convert("RGB")
    w, h = img.size
    s = size / min(w, h)
    nw, nh = max(size, round(w * s)), max(size, round(h * s))
    img = img.resize((nw, nh), Image.BICUBIC)
    long_side = max(nw, nh)
    n = 1 if long_side < size * 1.25 else MAX_VIEWS
    starts = sorted({round((long_side - size) * k / max(n - 1, 1)) for k in range(n)}) if n > 1 else [(long_side - size) // 2]
    if n == 1:
        x0, y0 = (nw - size) // 2, (nh - size) // 2
        return [img.crop((x0, y0, x0 + size, y0 + size))]
    if nw >= nh:
        return [img.crop((x, (nh - size) // 2, x + size, (nh - size) // 2 + size)) for x in starts]
    return [img.crop(((nw - size) // 2, y, (nw - size) // 2 + size, y + size)) for y in starts]


def to_tensor(crop, meta) -> np.ndarray:
    x = np.asarray(crop, dtype=np.float32) / 255.0
    mean = np.array(meta.get("mean", [0.48145466, 0.4578275, 0.40821073]), dtype=np.float32)
    std = np.array(meta.get("std", [0.26862954, 0.26130258, 0.27577711]), dtype=np.float32)
    return np.transpose((x - mean) / std, (2, 0, 1))[None].astype(np.float32)


def _sigmoid(z: float) -> float:
    z = float(np.clip(z, -50, 50))
    return float(1.0 / (1.0 + np.exp(-z)))


def assess(file_path: str) -> dict:
    """-> {"probability", "level", "views", "thrAlert", "thrVerify", "meta"}. Raises ModelUnavailable / ValueError."""
    from PIL import Image, ImageOps
    session, meta = load()
    try:
        size = int(meta.get("input_size", 224))
        with Image.open(file_path) as im:
            im.draft("RGB", (size * 2, size * 2))           # fast JPEG decoding - exactly as in training
            im = ImageOps.exif_transpose(im)
            if getattr(im, "is_animated", False):
                im.seek(0)
            crops = views(im.convert("RGB"), size)
    except Exception as e:
        raise ValueError(f"the file is not an image Pillow can read ({e.__class__.__name__})") from e
    name = session.get_inputs()[0].name
    probs = []
    for c in crops:
        logit = float(np.asarray(session.run(None, {name: to_tensor(c, meta)})[0]).reshape(-1)[0])
        probs.append(_sigmoid(logit))
    p = max(probs)
    ta, tv = float(meta["thr_alert"]), float(meta["thr_verify"])
    level = "high" if p >= ta else "medium" if p >= tv else "low"
    return {"probability": p, "level": level, "views": [round(v, 4) for v in probs], "thrAlert": ta, "thrVerify": tv,
            "meta": meta}


def score_from(a: dict) -> int:
    """Alert -> 71-100, verify -> 51-70, below -> 0-25."""
    p, ta, tv = a["probability"], a["thrAlert"], a["thrVerify"]
    if a["level"] == "high":
        return min(100, 71 + round(29 * (p - ta) / max(1 - ta, 1e-6)))
    if a["level"] == "medium":
        return min(70, 51 + round(19 * (p - tv) / max(ta - tv, 1e-6)))
    return _low_score(p, tv)


def _low_score(p: float, tv: float) -> int:
    """Below the verify level -> 0-25 ("safe"). Measured on the raw model output (logit), because these models are
    very sure of themselves: a real photo can get a raw 79% while the warning only starts at 99.9998%."""
    if tv <= 0.5:
        return round(25 * min(p, tv) / max(tv, 1e-6))
    lp = float(np.log(max(p, 1e-12) / max(1 - p, 1e-12)))
    lt = float(np.log(tv / max(1 - tv, 1e-12)))
    return round(25 * min(max(lp, 0.0) / lt, 1.0))
