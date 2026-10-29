r"""Insider-risk training, step 1: download the CERT Insider Threat Test Dataset r4.2 and its answer key.

Source: Carnegie Mellon University, Software Engineering Institute (CERT Division) with ExactData, "Insider Threat Test
Dataset" (doi:10.1184/R1/12841247), hosted on CMU KiltHub (licence shown there: CC BY 4.0 - credit the authors).
SYNTHETIC data (a simulator), the standard benchmark for insider-threat research. The files stay on this PC because
they are large (git-ignored folder backend\app\ml\training\data\insider\).

What this does - and nothing more:
  * asks KiltHub's public API which files the dataset has (prints them with their sizes)
  * downloads r4.2.tar.bz2 (about 4.8 GB) and answers.tar.bz2 (the answer key), continuing after an interruption
  * checks each file's size and MD5 checksum against the values KiltHub publishes
It does NOT unpack anything and runs nothing from the files. Run from the backend folder:
    python -I app\ml\training\download_insider_data.py            (list + download)
    python -I app\ml\training\download_insider_data.py --list     (only list the files)
"""
import hashlib
import json
import os
import sys
import time
import urllib.request

ARTICLE = 12841247                      # doi:10.1184/R1/12841247 (CMU KiltHub, a figshare site)
API = f"https://api.figshare.com/v2/articles/{ARTICLE}"
WANT = ("r4.2.tar.bz2", "answers.tar.bz2")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "insider")
UA = {"User-Agent": "CyberGuard-training/1.0 (student hackathon project)"}


def api_files():
    with urllib.request.urlopen(urllib.request.Request(API, headers=UA), timeout=60) as r:
        meta = json.load(r)
    files = meta.get("files") or []
    if not files:
        sys.exit("KiltHub's API listed no files for this dataset - try again later.")
    return meta, files


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(f):
    name, size = f["name"], int(f.get("size") or 0)
    md5 = f.get("computed_md5") or f.get("supplied_md5") or ""
    path = os.path.join(OUT, name)
    if os.path.exists(path):
        print(f"{name} is already downloaded - checking it ...", flush=True)
    else:
        part = path + ".part"
        have = os.path.getsize(part) if os.path.exists(part) else 0
        req = urllib.request.Request(f["download_url"], headers={**UA, **({"Range": f"bytes={have}-"} if have else {})})
        print(f"Downloading {name} ({size / 1e9:.2f} GB)" + (f", continuing at {have / 1e9:.2f} GB" if have else "")
              + " - Ctrl+C stops it; run the same command again to continue.", flush=True)
        with urllib.request.urlopen(req, timeout=120) as r:
            if have and r.status != 206:
                have = 0
            t0, done = time.time(), have
            with open(part, "ab" if have else "wb") as out:
                while True:
                    chunk = r.read(4 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    rate = (done - have) / max(time.time() - t0, 1e-6) / 1e6
                    print(f"\r  {done / 1e9:.2f} / {size / 1e9:.2f} GB  ({rate:.1f} MB/s)   ", end="", flush=True)
        print()
        os.replace(part, path)
    if size and os.path.getsize(path) != size:
        sys.exit(f"{name}: size {os.path.getsize(path):,} bytes, KiltHub says {size:,}. Delete it and run again.")
    if md5:
        print(f"Checking {name}'s MD5 checksum (a minute or two) ...", flush=True)
        if md5_of(path) != md5:
            sys.exit(f"{name}: the checksum does not match KiltHub's (damaged download). Delete it and run again.")
        print(f"ok - {name}: size and MD5 match KiltHub.")
    else:
        print(f"ok - {name}: size matches (KiltHub gave no checksum).")


def main():
    meta, files = api_files()
    print(f"Dataset: {meta.get('title')}  (licence: {(meta.get('license') or {}).get('name', '?')})")
    for f in files:
        print(f"  {int(f.get('size') or 0) / 1e9:8.2f} GB  {f['name']}")
    if "--list" in sys.argv:
        return
    os.makedirs(OUT, exist_ok=True)
    for name in WANT:
        f = next((x for x in files if x["name"] == name), None)
        if f is None:
            sys.exit(f"{name} is not in the list above - tell Claude what the list shows.")
        download(f)
    print(f"\nDone. Files are in {OUT}. Next: python -I app\\ml\\training\\prepare_insider_data.py")


if __name__ == "__main__":
    main()
