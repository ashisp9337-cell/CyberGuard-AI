"""
QR image -> text. Real decoding, no guessing.

Engines (tried in this order, first success wins):
  1. zxing-cpp   (optional: `pip install zxing-cpp`; most robust, reads several codes)
  2. OpenCV      (`opencv-python-headless`; pure pip, no system libraries)

Each engine is tried on several preprocessed versions of the image (original,
upscaled, downscaled, padded quiet-zone, inverted, contrast-enhanced,
thresholded) because real-world QR photos are rarely clean.

This module never raises for a bad image: it returns a DecodeResult with an
`error` message, so callers can say "could not decode" instead of "safe".

Manual test from the backend folder:
    python -m app.detectors.qr_decoder path\\to\\image.png
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np

try:  # optional, better accuracy
    import zxingcpp  # type: ignore
except Exception:  # pragma: no cover - depends on the machine
    zxingcpp = None

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None

log = logging.getLogger("cyberguard.qr")

MAX_PIXELS = 40_000_000   # refuse absurdly large images (decompression-bomb guard)
MAX_SIDE = 4000           # larger images are shrunk before decoding
MAX_CODES = 5             # analyse at most this many codes per image


@dataclass
class DecodedCode:
    text: str
    engine: str


@dataclass
class DecodeResult:
    codes: list[DecodedCode] = field(default_factory=list)
    engines_available: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def engine(self) -> str:
        return self.codes[0].engine if self.codes else ""


def available_engines() -> list[str]:
    engines = []
    if zxingcpp is not None:
        engines.append("zxing-cpp")
    if cv2 is not None:
        engines.append("opencv")
    return engines


def _load_gray(path: str) -> np.ndarray:
    from PIL import Image, ImageOps

    with Image.open(path) as im:
        w, h = im.size
        if w * h > MAX_PIXELS:
            raise ValueError("The image is too large to analyse.")
        im.load()
        im = ImageOps.exif_transpose(im)
        if im.mode in ("RGBA", "LA", "P"):
            rgba = im.convert("RGBA")
            background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            background.alpha_composite(rgba)  # transparent QR backgrounds become white
            im = background.convert("L")
        else:
            im = im.convert("L")
        if max(im.size) > MAX_SIDE:
            im.thumbnail((MAX_SIDE, MAX_SIDE))
        return np.array(im, dtype=np.uint8)


def _variants(gray: np.ndarray):
    yield "original", gray
    if cv2 is None:
        return
    h, w = gray.shape
    longest = max(h, w)
    if longest < 700:
        yield "upscaled", cv2.resize(gray, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC)
    if longest > 1400:
        scale = 1200 / longest
        yield "downscaled", cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    pad = max(20, int(0.08 * longest))
    padded = cv2.copyMakeBorder(gray, pad, pad, pad, pad, cv2.BORDER_CONSTANT, value=255)
    yield "padded", padded
    yield "inverted", 255 - padded
    yield "contrast", cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(padded)
    yield "threshold", cv2.adaptiveThreshold(
        padded, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10
    )
    if longest > 800:
        yield "half-size", cv2.resize(padded, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA)


def _decode_zxing(gray: np.ndarray) -> list[str]:
    texts = []
    for result in zxingcpp.read_barcodes(gray):
        fmt = str(getattr(result, "format", "")).upper()
        if "QR" not in fmt:  # ignore 1D barcodes etc.
            continue
        text = getattr(result, "text", "")
        if text:
            texts.append(text)
    return texts


def _decode_opencv(gray: np.ndarray) -> list[str]:
    detector = cv2.QRCodeDetector()
    texts: list[str] = []
    try:
        ok, values, _points, _straight = detector.detectAndDecodeMulti(gray)
        if ok:
            texts.extend(v for v in values if v)
    except cv2.error:
        pass
    if not texts:
        try:
            value, _points, _straight = detector.detectAndDecode(gray)
            if value:
                texts.append(value)
        except cv2.error:
            pass
    return texts


def _clean(texts: list[str]) -> list[str]:
    seen, out = set(), []
    for t in texts:
        t = t.replace("\x00", "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:MAX_CODES]


def decode_qr_image(path: str) -> DecodeResult:
    engines: list[tuple[str, object]] = []
    if zxingcpp is not None:
        engines.append(("zxing-cpp", _decode_zxing))
    if cv2 is not None:
        engines.append(("opencv", _decode_opencv))
    names = [name for name, _ in engines]

    if not engines:
        return DecodeResult(
            engines_available=[],
            error="No QR decoder is installed on the server. Run: pip install opencv-python-headless",
        )

    try:
        gray = _load_gray(path)
    except Exception as exc:  # corrupt file, wrong format, too large...
        log.info("QR image could not be opened: %s", exc)  # details stay in the server log, not in the API response
        return DecodeResult(engines_available=names, error="The file could not be read as an image. Upload a PNG or JPG that contains the QR code.")

    for variant_name, image in _variants(gray):
        for engine_name, decode in engines:
            try:
                texts = _clean(decode(image))  # type: ignore[operator]
            except Exception as exc:
                log.warning("QR engine %s failed on '%s': %s", engine_name, variant_name, exc)
                continue
            if texts:
                log.info("QR decoded with %s (%s)", engine_name, variant_name)
                return DecodeResult(codes=[DecodedCode(t, engine_name) for t in texts], engines_available=names)

    return DecodeResult(
        engines_available=names,
        error=(
            "No QR code could be detected in this image. Try a sharper, well-lit, "
            "front-on picture of the code with all four corners visible."
        ),
    )


if __name__ == "__main__":  # manual check
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m app.detectors.qr_decoder <image>")
        raise SystemExit(2)
    result = decode_qr_image(sys.argv[1])
    print("engines available:", result.engines_available or "none")
    if result.codes:
        for i, code in enumerate(result.codes, 1):
            print(f"[{i}] ({code.engine}) {code.text}")
    else:
        print("NOT DECODED:", result.error)