"""Download the offline speech-to-text model used by the voice scam check (once, about 480 MB).

Whisper "small" (OpenAI, MIT licence) converted for faster-whisper by Systran, from Hugging Face. It is saved in
backend/app/ml/models/whisper-small/ (git-ignored). After this, no internet is needed to transcribe - voice
recordings never leave the PC. Run from the backend folder:
    python -m app.ml.training.fetch_whisper
"""
import os
import sys
import time

REPO = "Systran/faster-whisper-small"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "models", "whisper-small")
FILES = ["config.json", "model.bin", "tokenizer.json", "vocabulary.txt"]


def main():
    from huggingface_hub import snapshot_download
    t0 = time.time()
    print(f"Downloading {REPO} (about 480 MB) into {os.path.abspath(OUT)} ...", flush=True)
    snapshot_download(REPO, local_dir=OUT, allow_patterns=FILES + ["vocabulary.json", "preprocessor_config.json"])
    missing = [f for f in FILES if not os.path.isfile(os.path.join(OUT, f))]
    size = os.path.getsize(os.path.join(OUT, "model.bin")) if "model.bin" not in missing else 0
    if missing or size < 2e8:
        sys.exit(f"Download incomplete (missing: {missing}, model.bin {size / 1e6:.0f} MB) - run this command again.")
    print(f"ok - downloaded in {time.time() - t0:.0f}s, model.bin {size / 1e6:.0f} MB. Checking it loads ...", flush=True)
    import numpy as np
    from faster_whisper import WhisperModel
    m = WhisperModel(OUT, device="cpu", compute_type="int8")
    list(m.transcribe(np.zeros(16_000, np.float32), beam_size=1)[0])
    print("ok - speech-to-text works offline. Restart the backend to use it.")


if __name__ == "__main__":
    main()
