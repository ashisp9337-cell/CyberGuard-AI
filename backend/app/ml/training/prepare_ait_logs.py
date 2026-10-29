"""
Step 1 of training the LOG ANALYSIS model: download the AIT Log Data Set V1.1 and turn it into one small labelled file.

The data (real logs, real attacks, labelled per line):
  AIT Log Data Set V1.1 - Austrian Institute of Technology, https://zenodo.org/records/4264796
  Licence CC BY-NC-SA 4.0 (non-commercial use with attribution). Cite: Landauer et al., "Have it Your Way: Generating
  Customized Log Datasets With a Model-Driven Simulation Testbed", IEEE Transactions on Reliability 70(1), 2021.
  Four web servers (Apache, PHP, Exim mail, Horde, OkayCMS) with simulated users for six days; on day five each was
  attacked: nmap + nikto scans, SMTP account enumeration, hydra password brute force, webshell upload (CVE-2019-9858),
  privilege escalation (CVE-2019-10149) and a webshell injected through a cookie (CVE-2019-16885).

What this script does (safe for your PC):
  --download   downloads AIT-LDS-v1_1.zip (3.4 GB) into app/ml/training/data/log_analysis/ (git ignores it), can be
               stopped and restarted (it continues), and checks it with Zenodo's MD5. Needs ~3.5 GB free disk.
  (no option)  READS the logs straight out of the zip - nothing is unpacked, nothing is run - and writes
               ait_v1_lines.jsonl.gz (every attack line + a sample of normal lines, ~100-250 MB) and
               ait_v1_summary.txt (what is inside). Uses < 1 GB RAM. Takes ~10-30 minutes.
Afterwards you may delete the 3.4 GB zip (keep it if you have the space).

Run from backend/ (venv active):
    python -m app.ml.training.prepare_ait_logs --download
    python -m app.ml.training.prepare_ait_logs
"""
import argparse
import gzip
import hashlib
import json
import os
import random
import sys
import time
import urllib.request
import zipfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "data", "log_analysis")
ZIP_NAME = "AIT-LDS-v1_1.zip"
URL = "https://zenodo.org/records/4264796/files/AIT-LDS-v1_1.zip?download=1"
MD5 = "4573b78ca4909c259632a49a3a34211e"
SIZE_HINT = "3.4 GB"
MAX_NORMAL_PER_FILE = 150_000      # normal lines kept per log file (random sample); every attack line is kept
MAX_LINE = 2000                    # characters kept per line
SEED = 42


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, ZIP_NAME)
    if os.path.exists(path):
        print(f"{ZIP_NAME} is already here - checking it (1-2 minutes) ...", flush=True)
        if md5_of(path) == MD5:
            print("ok - checksum matches Zenodo.")
            return path
        sys.exit(f"{path} exists but its checksum does not match Zenodo. Delete it and run --download again.")
    part = path + ".part"
    have = os.path.getsize(part) if os.path.exists(part) else 0
    req = urllib.request.Request(URL, headers={"User-Agent": "CyberGuard-training/1.0",
                                               **({"Range": f"bytes={have}-"} if have else {})})
    print(f"Downloading {ZIP_NAME} ({SIZE_HINT}) from Zenodo" + (f", continuing at {have / 1e9:.2f} GB" if have else "")
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
                if total:
                    rate = (done - have) / max(time.time() - t0, 1e-6) / 1e6
                    print(f"\r  {done / 1e9:.2f} / {total / 1e9:.2f} GB  ({rate:.1f} MB/s)   ", end="", flush=True)
    print("\nChecking the download against Zenodo's checksum ...", flush=True)
    if md5_of(part) != MD5:
        sys.exit("The downloaded file does not match Zenodo's checksum (the download was damaged). "
                 f"Delete {part} and run --download again.")
    os.replace(part, path)
    print("ok - download complete and checked.")
    return path


def _is_text_log(name):
    low = name.lower()
    return not (low.endswith("/") or low.endswith((".zip", ".gz", ".tar", ".pcap", ".bz2", ".xz", ".7z"))
                or "/audit/" in low)


def prepare(zip_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rnd = random.Random(SEED)
    summary, counts = [], Counter()
    out_path = os.path.join(out_dir, "ait_v1_lines.jsonl.gz")
    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
        infos = {i.filename: i for i in z.infolist()}
        # the archive may have one extra top folder; find the data/ and labels/ roots wherever they are
        data_files = [n for n in names if "/data/" in "/" + n and _is_text_log(n)]
        summary.append(f"zip members: {len(names)}; text log files under data/: {len(data_files)}")
        tmp = out_path + ".part"
        with gzip.open(tmp, "wt", encoding="utf-8") as out:
            for n in sorted(data_files):
                parts = ("/" + n).split("/data/", 1)
                label_name = (parts[0] + "/labels/" + parts[1]).lstrip("/")
                rel = parts[1]                                     # e.g. mail.cup.com/apache2/mail.cup.com-access.log
                host = rel.split("/", 1)[0]
                size = infos[n].file_size
                if label_name not in infos:
                    summary.append(f"  {rel}  ({size / 1e6:.1f} MB)  NO LABEL FILE - skipped")
                    continue
                kept, total, lab_counts, reservoir = 0, 0, Counter(), []
                with z.open(n) as fd, z.open(label_name) as fl:
                    for raw, lab in zip(fd, fl):
                        total += 1
                        line = raw.decode("utf-8", "replace").rstrip("\r\n")[:MAX_LINE]
                        lab = lab.decode("utf-8", "replace").strip()
                        lab_counts[lab] += 1
                        row = {"host": host, "log": rel, "n": total, "label": lab, "line": line}
                        if lab.replace(" ", "") not in ("0,0", "0", ""):
                            out.write(json.dumps(row, ensure_ascii=False) + "\n")
                            kept += 1
                        elif len(reservoir) < MAX_NORMAL_PER_FILE:
                            reservoir.append(row)
                        else:                                       # uniform random sample of the normal lines
                            j = rnd.randrange(total)
                            if j < MAX_NORMAL_PER_FILE:
                                reservoir[j] = row
                for row in sorted(reservoir, key=lambda r: r["n"]):
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
                kept += len(reservoir)
                counts.update({host: kept})
                top = ", ".join(f"{k!r}: {v}" for k, v in lab_counts.most_common(6))
                summary.append(f"  {rel}  ({size / 1e6:.1f} MB)  lines {total:,}  kept {kept:,}  labels {{{top}}}")
                print(summary[-1], flush=True)
        os.replace(tmp, out_path)
        other = sorted({("/" + n).split("/data/", 1)[-1].split("/", 1)[0] for n in names if "/data/" in "/" + n})
        summary.append("hosts / folders under data/: " + ", ".join(other))
        summary.append("examples of label files: " + ", ".join([n for n in names if "/labels/" in "/" + n][:5]))
    summary.append(f"written: {out_path}  ({os.path.getsize(out_path) / 1e6:.1f} MB), lines per host: {dict(counts)}")
    with open(os.path.join(out_dir, "ait_v1_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(summary) + "\n")
    print("\n".join(summary[-3:]))
    print(f"\nDone. Summary: {os.path.join(out_dir, 'ait_v1_summary.txt')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true", help="download + check the 3.4 GB zip, then stop")
    ap.add_argument("--out-dir", default=OUT_DIR)
    ap.add_argument("--zip", default="", help="use a zip you downloaded yourself (e.g. with the browser)")
    a = ap.parse_args()
    if a.download:
        download(a.out_dir)
        print("Next:  python -m app.ml.training.prepare_ait_logs")
        return
    zip_path = a.zip or os.path.join(a.out_dir, ZIP_NAME)
    if not os.path.exists(zip_path):
        sys.exit(f"Not found: {zip_path}\nRun first:  python -m app.ml.training.prepare_ait_logs --download")
    os.makedirs(a.out_dir, exist_ok=True)
    prepare(zip_path, a.out_dir)


if __name__ == "__main__":
    main()
