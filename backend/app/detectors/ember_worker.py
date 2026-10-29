"""Separate-process worker for the malware scan: file bytes in, EMBER v3 feature vectors out. Nothing is run.

Started by app/detectors/malware.py as `python -I ember_worker.py` with a time limit, so a booby-trapped file can at
worst be stopped - it can never hang or crash the server. Input (stdin): one or more blobs, each prefixed with its
length (8 bytes, little endian). Output (stdout): JSON list, one entry per blob - the 2,568 numbers, or {"error": ...}.
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))


def main():
    raw = sys.stdin.buffer.read()
    out = sys.stdout
    sys.stdout = sys.stderr                    # the feature code prints pefile warnings: keep them off the reply
    from app.detectors import ember_features
    ex = ember_features.PEFeatureExtractor()
    vectors, i = [], 0
    while i + 8 <= len(raw):
        n = struct.unpack("<Q", raw[i:i + 8])[0]
        blob, i = raw[i + 8:i + 8 + n], i + 8 + n
        try:
            vectors.append(ex.feature_vector(blob).tolist())
        except Exception as exc:               # noqa: BLE001 - one unreadable file never stops the others
            vectors.append({"error": type(exc).__name__})
    out.write(json.dumps(vectors))
    out.flush()


if __name__ == "__main__":
    main()
