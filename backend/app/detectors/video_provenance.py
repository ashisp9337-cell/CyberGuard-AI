"""
VIDEO provenance (Deepfake module -> Video Analysis / AI-Generated Multimedia): does the video file itself say that
it was made or changed with AI? No model, no internet - only what the generating tool wrote into the file:

  * C2PA "Content Credentials" whose digital-source type is "trainedAlgorithmicMedia" (made by AI) or
    "compositeWithTrainedAlgorithmicMedia" (real footage partly changed by AI). OpenAI Sora, Adobe Firefly and other
    tools sign their videos this way.
  * the name of an AI video generator or face-swap tool in the file's metadata (encoder / software / comment tags).

Found  -> proof that the video is (partly) AI-made.
Absent -> proves NOTHING: re-uploading (WhatsApp, Instagram, YouTube), screen recording or re-encoding removes it,
          and invisible watermarks such as Google's SynthID cannot be read by anyone outside Google.

Safety / accuracy: only METADATA boxes are read (MP4/MOV 'moov/udta', 'meta', 'uuid'), never the picture data
('mdat') or the sample tables, so random bytes in the video can never look like a generator's name. At most a few
MB are read, whatever the size of the video.
"""
from __future__ import annotations

import os
import re
import struct

from app.detectors.ai_image import AI_SOURCE_TYPES

MAX_BOX = 16 * 1024 * 1024        # a metadata box larger than this is not read
MAX_TOTAL = 32 * 1024 * 1024      # never read more than this in total
EDGE = 2 * 1024 * 1024            # WebM / MKV / AVI: start and end of the file only

KEEP = {b"udta", b"meta", b"uuid", b"ilst", b"keys", b"XMP_", b"\xa9too", b"\xa9cmt", b"\xa9swr", b"\xa9nam"}
CONTAINERS = {b"moov", b"trak", b"udta", b"meta", b"mdia", b"minf"}   # walked into, but only KEEP boxes are read
SKIP = {b"mdat", b"stbl", b"free", b"skip", b"wide", b"moof", b"mfra", b"sidx"}

# (regex, display name, kind). Only matched inside printable metadata strings.
GENERATORS = [
    # Short names that are also ordinary words or names (sora = "sky", Runway = fashion, Kling / Roop = surnames,
    # "dream machine", "minimax") only count WITH context, so a video titled "sora beach" is not called AI.
    (r"openai\s*sora|sora\s*(by|from)\s*openai|made\s*(with|by|in)\s*sora\b|sora\.(com|chatgpt)|\bsora[\s_-]?2\b",
     "OpenAI Sora", "ai"),
    (r"openai", "OpenAI", "ai"),
    (r"google\s*veo|\bveo[\s_-]?[0-9]", "Google Veo", "ai"),
    (r"kling\s*(ai|[0-9])|klingai|kuaishou", "Kling (Kuaishou)", "ai"),
    (r"runwayml|runway\s*(ml|ai|gen[\s-]?[0-9])|app\.runwayml", "Runway", "ai"),
    (r"pika\s?(labs|art)|pika\.art", "Pika", "ai"),
    (r"luma\s?(ai|labs)|luma\s*dream\s?machine|lumalabs", "Luma Dream Machine", "ai"),
    (r"hailuo|minimax\s*(ai|hailuo|video)|minimaxi", "MiniMax Hailuo", "ai"),
    (r"synthesia", "Synthesia (AI avatar)", "ai"), (r"heygen", "HeyGen (AI avatar)", "ai"),
    (r"\bd-id\.com|\bd-id\s*(studio|creative|ai)", "D-ID (AI avatar)", "ai"), (r"invideo\s?ai", "InVideo AI", "ai"),
    (r"haiper", "Haiper", "ai"), (r"vidu\s*(ai|[0-9])|vidu\.(com|studio)|shengshu", "Vidu", "ai"),
    (r"hunyuan\s?video", "Tencent HunyuanVideo", "ai"),
    (r"\bwan\s?2\.\d|wanx|tongyi\s?wanxiang", "Alibaba Wan", "ai"),
    (r"seedance|jimeng|dreamina", "ByteDance Seedance / Dreamina", "ai"), (r"pixverse", "PixVerse", "ai"),
    (r"ltx[\s-]?video|lightricks", "LTX-Video", "ai"), (r"cogvideo", "CogVideoX", "ai"),
    (r"animatediff", "AnimateDiff", "ai"), (r"deforum", "Deforum", "ai"), (r"meta\s*movie\s?gen|moviegen", "Meta Movie Gen", "ai"),
    (r"grok\s?imagine", "xAI Grok Imagine", "ai"), (r"midjourney", "Midjourney", "ai"),
    (r"adobe\s*firefly", "Adobe Firefly", "ai"), (r"stable\s?video\s?diffusion", "Stable Video Diffusion", "ai"),
    (r"deepfacelab", "DeepFaceLab", "faceswap"), (r"\bfaceswap\b", "Faceswap", "faceswap"),
    (r"roop[\s_-]?unleashed|roop[\s_-]?cam", "roop", "faceswap"), (r"facefusion", "FaceFusion", "faceswap"),
    (r"deep-?live-?cam", "Deep-Live-Cam", "faceswap"), (r"reface\s*app|\breface\.ai", "Reface", "faceswap"),
]
_GEN_RE = [(re.compile(p, re.I), n, k) for p, n, k in GENERATORS]
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def _read_boxes(f, start: int, end: int, out: list, budget: list, depth: int = 0) -> None:
    """Walk ISO-BMFF boxes between start and end, appending the bytes of metadata boxes to out."""
    pos = start
    while pos + 8 <= end and budget[0] > 0:
        f.seek(pos)
        head = f.read(16)
        if len(head) < 8:
            return
        size, btype = struct.unpack(">I", head[:4])[0], head[4:8]
        hdr = 8
        if size == 1:
            if len(head) < 16:
                return
            size, hdr = struct.unpack(">Q", head[8:16])[0], 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end + 8:          # damaged file: stop instead of guessing
            return
        body_start, body_end = pos + hdr, min(pos + size, end)
        if btype in SKIP:
            pass
        elif btype in CONTAINERS and depth < 6:
            inner = body_start + (4 if btype == b"meta" else 0)    # 'meta' is a full box (4-byte version/flags)
            if btype == b"meta":
                n = min(body_end - body_start, MAX_BOX, budget[0])
                f.seek(body_start)
                out.append(f.read(n))
                budget[0] -= n
            _read_boxes(f, inner, body_end, out, budget, depth + 1)
        elif btype in KEEP or depth > 0 and btype[:1] == b"\xa9":
            n = min(body_end - body_start, MAX_BOX, budget[0])
            f.seek(body_start)
            out.append(f.read(n))
            budget[0] -= n
        pos += size


def _metadata(file_path: str) -> bytes:
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        head = f.read(12)
        if head[4:8] in (b"ftyp", b"moov", b"free", b"wide", b"mdat", b"skip", b"uuid"):   # MP4 / MOV / 3GP / M4V
            out: list = []
            _read_boxes(f, 0, size, out, [MAX_TOTAL])
            return b"\n".join(out)
        f.seek(0)                                                  # WebM / MKV / AVI: tags sit at the start or end
        data = f.read(min(size, EDGE))
        if size > EDGE:
            f.seek(max(EDGE, size - EDGE))
            data += b"\n" + f.read(EDGE)
        return data


def provenance(file_path: str) -> dict:
    """-> {"proof": bool, "kind": "ai"|"faceswap"|None, "findings": [{"label","detail","proof"}],
           "hasContentCredentials": bool}"""
    empty = {"proof": False, "kind": None, "findings": [], "hasContentCredentials": False}
    try:
        meta = _metadata(file_path)
    except OSError:
        return empty
    findings, kind = [], None
    has_c2pa = b"c2pa" in meta or b"jumb" in meta
    ai_type = next((t for t in AI_SOURCE_TYPES if t in meta), None)
    if ai_type:
        partly = ai_type == b"compositeWithTrainedAlgorithmicMedia"
        kind = "ai"
        findings.append({"label": "Content Credentials: video partly made with AI" if partly
                         else "Content Credentials: video made with AI",
                         "detail": f"The video's Content Credentials (C2PA) record the source as '{ai_type.decode()}': "
                                   + ("real footage changed with AI." if partly
                                      else "the tool that made it declared it as generated by an AI model."),
                         "proof": True})
    elif has_c2pa:
        findings.append({"label": "Content Credentials present", "proof": False,
                         "detail": "The video carries C2PA Content Credentials that do not declare AI generation (for "
                                   "example a camera or editing app signed it). Check them at contentcredentials.org/verify."})
    text = "\n".join(s.decode("ascii") for s in _PRINTABLE.findall(meta))
    hits = []
    for rx, name, k in _GEN_RE:
        if rx.search(text) and name not in [h[0] for h in hits]:
            hits.append((name, k))
    if hits:
        swap = [n for n, k in hits if k == "faceswap"]
        gen = [n for n, k in hits if k == "ai"]
        if swap:
            kind = "faceswap"
            findings.append({"label": "Face-swap tool named in the video's metadata", "proof": True,
                             "detail": "The video's metadata mentions the face-swap tool " + ", ".join(swap) + "."})
        if gen:
            kind = kind or "ai"
            findings.append({"label": "AI video generator named in the video's metadata", "proof": True,
                             "detail": "The video's metadata mentions: " + ", ".join(gen) + "."})
    return {"proof": any(f["proof"] for f in findings), "kind": kind, "findings": findings,
            "hasContentCredentials": has_c2pa}
