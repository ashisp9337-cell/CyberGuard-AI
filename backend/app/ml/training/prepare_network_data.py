r"""Step 3 of the network-traffic training: turn the downloaded zip into two compact files.

Reads data\network\cicids2017_distrinet_dataset.zip directly (it is NOT unpacked; nothing in it is run) and writes,
next to it, in the gitignored data\network\ folder:
  * network_flows.csv.gz   - EVERY connection, but only the ~15 columns the detector uses (time, addresses, port,
                             protocol, duration, packets / bytes each way, TCP flag counts, label)
  * network_sample.csv.gz  - a small random sample with ALL columns (at most 4,000 rows per day and label)
  * network_summary.txt    - each day's column names and how many connections carry each label
Memory stays small: rows are streamed one at a time; only the small sample is held in memory.
Run from the backend folder (about 3-6 minutes):
    python -I app\ml\training\prepare_network_data.py
"""
import csv
import gzip
import hashlib
import io
import os
import random
import sys
import time
import zipfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(HERE, "data", "network")
ZIP = os.path.join(DIR, "cicids2017_distrinet_dataset.zip")
SHA256 = "4d535da19795d85376ae1397d161329e3b06fc47d9a5a68cd9be2cd7ecee0f2a"   # printed by download_network_data.py
SAMPLE_PER_LABEL = 4000
SEED = 42

# the columns kept for every connection: our name -> accepted spellings in the CSV header (compared without spaces,
# "_" or "/" and in lower case, because CICFlowMeter versions spell them differently)
WANT = {
    "timestamp": ["timestamp"],
    "src_ip": ["srcip", "sourceip"],
    "src_port": ["srcport", "sourceport"],
    "dst_ip": ["dstip", "destinationip"],
    "dst_port": ["dstport", "destinationport"],
    "protocol": ["protocol"],
    "duration": ["flowduration"],
    "fwd_packets": ["totalfwdpacket", "totalfwdpackets"],
    "bwd_packets": ["totalbwdpackets", "totalbwdpacket", "totalbackwardpackets"],
    "fwd_bytes": ["totallengthoffwdpacket", "totallengthoffwdpackets", "fwdpacketslengthtotal"],
    "bwd_bytes": ["totallengthofbwdpacket", "totallengthofbwdpackets", "bwdpacketslengthtotal"],
    "syn_flags": ["synflagcount"],
    "rst_flags": ["rstflagcount"],
    "fin_flags": ["finflagcount"],
    "label": ["label"],
    "attempted": ["attemptedcategory"],
}


def norm(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch not in " _/-﻿")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if not os.path.exists(ZIP):
        sys.exit(f"{ZIP} is missing - run download_network_data.py first.")
    print("Checking the zip's fingerprint ...", flush=True)
    if sha256_of(ZIP) != SHA256:
        sys.exit("The zip's fingerprint does not match the one recorded at download. Delete it and download again.")
    rng = random.Random(SEED)
    out_flows = os.path.join(DIR, "network_flows.csv.gz")
    out_sample = os.path.join(DIR, "network_sample.csv.gz")
    summary, sample_rows, all_headers = [], {}, None
    t0 = time.time()
    with zipfile.ZipFile(ZIP) as z, gzip.open(out_flows + ".part", "wt", newline="", encoding="utf-8") as fo:
        w = csv.writer(fo)
        w.writerow(["day"] + list(WANT))
        for name in sorted(n for n in z.namelist() if n.lower().endswith(".csv")):
            day = os.path.basename(name).split("-")[0]
            with z.open(name) as raw:
                r = csv.reader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline=""))
                header = next(r)
                if all_headers is None:
                    all_headers = header
                idx = {norm(h): i for i, h in enumerate(header)}
                cols = {k: next((idx[s] for s in spell if s in idx), None) for k, spell in WANT.items()}
                missing = [k for k, v in cols.items() if v is None]
                if cols["label"] is None:
                    sys.exit(f"{name}: no Label column found. Header: {header}")
                labels, seen = Counter(), Counter()
                for row in r:
                    if len(row) != len(header):
                        continue                            # broken line - skipped (counted below)
                    lab = row[cols["label"]].strip()
                    labels[lab] += 1
                    w.writerow([day] + [row[c].strip() if c is not None else "" for c in cols.values()])
                    if header != all_headers:
                        continue                            # sample only rows laid out like the sample's header
                    key = (day, lab)                        # reservoir sample: every row has an equal chance
                    seen[key] += 1
                    bucket = sample_rows.setdefault(key, [])
                    if len(bucket) < SAMPLE_PER_LABEL:
                        bucket.append([day] + row)
                    else:
                        j = rng.randrange(seen[key])
                        if j < SAMPLE_PER_LABEL:
                            bucket[j] = [day] + row
            total = sum(labels.values())
            print(f"{day}: {total:,} connections, {len(labels)} labels  ({time.time() - t0:.0f}s)", flush=True)
            summary.append(f"== {name}: {total:,} connections\n   columns ({len(header)}): {header}\n"
                           f"   not found: {missing or 'none'}\n"
                           + "".join(f"   {n:>10,}  {lab}\n" for lab, n in labels.most_common()))
    os.replace(out_flows + ".part", out_flows)
    with gzip.open(out_sample, "wt", newline="", encoding="utf-8") as fs:
        w = csv.writer(fs)
        w.writerow(["day"] + all_headers)
        for key in sorted(sample_rows):
            w.writerows(sample_rows[key])
    with open(os.path.join(DIR, "network_summary.txt"), "w", encoding="utf-8") as f:
        f.write("".join(summary))
    print("".join(summary))
    for p in (out_flows, out_sample):
        print(f"wrote {p}  ({os.path.getsize(p) / 1e6:.1f} MB)")
    print(f"done in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
