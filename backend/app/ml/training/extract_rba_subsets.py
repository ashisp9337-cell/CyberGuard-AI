"""
Cut the 9 GB RBA login dataset down to two small, complete subsets for training the six
Credential Theft & Account Takeover subtopic models (train_credential_subtopics.py).

Why subsets instead of random rows: the models need COMPLETE histories.
  * accounts subset  -- every login of ~1 in 10 accounts (+ every account with a confirmed takeover),
                        so each account's full history is there (location, device, timing, failures)
  * IP subset        -- every login attempt from ~1 in 10 IP addresses, so each IP's full activity
                        is there (how many accounts it tried, how many failed -- password spraying)
Accounts and IPs are picked by a fixed hash, so running it twice gives the same result.

Dataset: "Login Data Set for Risk-Based Authentication" (Wiefling et al., CC BY 4.0)
  https://www.kaggle.com/datasets/dasgroup/rba-dataset

Run from backend/  (takes about 15-30 minutes, reads the file twice, uses little memory):
    python -m app.ml.training.extract_rba_subsets
    python -m app.ml.training.extract_rba_subsets --ip-only     # only the IP subset (one pass)

Output (in app/ml/training/data/):
    rba_accounts_subset.csv.gz
    rba_ip_subset.csv.gz
"""
import argparse
import gzip
import os
import sys
import time
import zipfile

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
UNKNOWN_ACCOUNT_ID = "-4324475583306591935"   # all logins to non-existent accounts are filed under this ID
CHUNK = 500_000

COLS = {"Login Timestamp": "ts", "User ID": "user", "IP Address": "ip", "Country": "country", "Region": "region",
        "City": "city", "ASN": "asn", "User Agent String": "ua", "Browser Name and Version": "browser",
        "OS Name and Version": "os", "Device Type": "device", "Login Successful": "success",
        "Is Attack IP": "attack", "Is Account Takeover": "ato"}
ACC_COLS = ["ts", "user", "ip", "country", "region", "city", "asn", "ua", "browser", "os", "device",
            "success", "attack", "ato"]
IP_COLS = ["ts", "user", "ip", "country", "asn", "success", "attack", "ua", "device"]


def _open(path):
    if path.endswith(".zip"):
        z = zipfile.ZipFile(path)
        return z.open([n for n in z.namelist() if n.endswith(".csv")][0])
    return open(path, "rb")


def _find_input(given):
    for p in [given] if given else [os.path.join(DATA_DIR, "rba-dataset.csv"), os.path.join(DATA_DIR, "rba-dataset.zip")]:
        if p and os.path.exists(p):
            return p
    sys.exit("rba-dataset.csv (or .zip) not found in app/ml/training/data/")


def _bucket(values: pd.Series, mod: int) -> pd.Series:
    """Stable bucket 0..mod-1 for each value (same value -> same bucket on every run and every PC)."""
    return pd.Series(pd.util.hash_array(values.astype(str).to_numpy(), categorize=False) % mod, index=values.index)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=None)
    ap.add_argument("--account-mod", type=int, default=10, help="keep 1 in N accounts (default 10 = 10%%)")
    ap.add_argument("--ip-mod", type=int, default=10, help="keep 1 in N IP addresses (default 10 = 10%%)")
    ap.add_argument("--max-rows", type=int, default=0, help="stop early (testing)")
    ap.add_argument("--ip-only", action="store_true", help="only (re)make the IP subset (one pass, faster)")
    a = ap.parse_args()
    src = _find_input(a.input)
    out_acc = os.path.join(DATA_DIR, "rba_accounts_subset.csv.gz")
    out_ip = os.path.join(DATA_DIR, "rba_ip_subset.csv.gz")
    t0 = time.time()

    # Pass 1: which accounts were really taken over (keep all of their history)
    ato_users, n = set(), 0
    for ch in ([] if a.ip_only else pd.read_csv(_open(src), usecols=["User ID", "Is Account Takeover"], dtype={"User ID": str},
                          chunksize=CHUNK)):
        ato_users.update(ch.loc[ch["Is Account Takeover"].astype(str).str.lower() == "true", "User ID"])
        n += len(ch)
        print(f"\rpass 1/2: {n:,} rows, {len(ato_users)} taken-over accounts ({time.time() - t0:.0f}s)", end="", flush=True)
        if a.max_rows and n >= a.max_rows:
            break
    print()

    # Pass 2: write the two subsets
    n = acc_rows = ip_rows = 0
    fa = None if a.ip_only else gzip.open(out_acc, "wt", encoding="utf-8", newline="")   # ip-only: accounts file untouched
    with gzip.open(out_ip, "wt", encoding="utf-8", newline="") as fi:
        for i, ch in enumerate(pd.read_csv(_open(src), usecols=list(COLS), dtype=str, chunksize=CHUNK,
                                           keep_default_na=False)):
            ch = ch.rename(columns=COLS)
            keep_acc = ((_bucket(ch["user"], a.account_mod) == 0) | ch["user"].isin(ato_users)) & (ch["user"] != UNKNOWN_ACCOUNT_ID)
            keep_ip = _bucket(ch["ip"], a.ip_mod) == 0
            if fa is not None:
                ch.loc[keep_acc, ACC_COLS].to_csv(fa, header=(i == 0), index=False)
            ch.loc[keep_ip, IP_COLS].to_csv(fi, header=(i == 0), index=False)
            n += len(ch)
            acc_rows += int(keep_acc.sum()) if fa is not None else 0
            ip_rows += int(keep_ip.sum())
            print(f"\rpass 2/2: {n:,} rows -> accounts {acc_rows:,} | IPs {ip_rows:,} ({time.time() - t0:.0f}s)", end="", flush=True)
            if a.max_rows and n >= a.max_rows:
                break
    if fa is not None:
        fa.close()
    print(f"\nDone in {time.time() - t0:.0f}s")
    for p in ((out_ip,) if a.ip_only else (out_acc, out_ip)):
        print(f"  {os.path.relpath(p, os.path.join(HERE, '..', '..', '..'))}  {os.path.getsize(p) / 1e6:.0f} MB")


if __name__ == "__main__":
    main()
