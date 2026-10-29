r"""Step 2 of the network-traffic training: download the corrected CIC-IDS2017 flow data and check it.

Source: Engelen, Rimmer & Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study"
(KU Leuven / DistriNet, WTMC 2021) - the CIC-IDS2017 traffic re-processed with a fixed CICFlowMeter and re-labelled
(incl. "Attempted" attacks). Original traffic: Canadian Institute for Cybersecurity, UNB (cite Sharafaldin et al. 2018).

What this does - and nothing more:
  * downloads dataset.zip (about 334 MB) into backend\app\ml\training\data\network\  (that folder is gitignored)
  * can be stopped with Ctrl+C and run again: it continues where it stopped
  * checks the zip is complete and not damaged, prints its SHA-256 fingerprint and the list of files inside
It does NOT unpack the zip and runs nothing from it. Run from the backend folder:
    python -I app\ml\training\download_network_data.py
"""
import hashlib
import os
import sys
import time
import urllib.request
import zipfile

URL = "https://intrusion-detection.distrinet-research.be/WTMC2021/Dataset/dataset.zip"
ZIP_NAME = "cicids2017_distrinet_dataset.zip"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "data", "network")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(path):
    part = path + ".part"
    have = os.path.getsize(part) if os.path.exists(part) else 0
    req = urllib.request.Request(URL, headers={"User-Agent": "CyberGuard-training/1.0",
                                               **({"Range": f"bytes={have}-"} if have else {})})
    print("Downloading dataset.zip (about 334 MB) from KU Leuven" + (f", continuing at {have / 1e6:.0f} MB" if have else "")
          + " - you can stop with Ctrl+C and run the same command again to continue.", flush=True)
    with urllib.request.urlopen(req, timeout=120) as r:
        if have and r.status != 206:              # server ignored the resume request -> start again
            have = 0
        total = have + int(r.headers.get("Content-Length") or 0)
        t0, done = time.time(), have
        with open(part, "ab" if have else "wb") as f:
            while True:
                chunk = r.read(4 << 20)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                rate = (done - have) / max(time.time() - t0, 1e-6) / 1e6
                print(f"\r  {done / 1e6:,.0f} / {total / 1e6:,.0f} MB  ({rate:.1f} MB/s)   ", end="", flush=True)
    print()
    if total and os.path.getsize(part) != total:
        sys.exit(f"The download stopped early ({os.path.getsize(part):,} of {total:,} bytes). Run the same command again.")
    os.replace(part, path)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, ZIP_NAME)
    if os.path.exists(path):
        print(f"{ZIP_NAME} is already downloaded - checking it.")
    else:
        download(path)
    print("Checking the zip is complete and undamaged (reads it once, about a minute) ...", flush=True)
    try:
        with zipfile.ZipFile(path) as z:
            bad = z.testzip()                     # reads every file's data and checks its CRC; nothing is unpacked
            infos = z.infolist()
    except zipfile.BadZipFile:
        sys.exit(f"{path} is not a complete zip file. Delete it and run this command again.")
    if bad:
        sys.exit(f"The zip is damaged ({bad}). Delete {path} and run this command again.")
    print(f"ok - zip is complete. {len(infos)} entries:")
    for i in infos:
        print(f"  {i.file_size / 1e6:10,.1f} MB  {i.filename}")
    print(f"\nSHA-256 fingerprint: {sha256_of(path)}")
    print(f"Saved at: {path}")


if __name__ == "__main__":
    main()
