"""
Step 2 of the LOG ANALYSIS model: choose the burst sizes ("thresholds") of the whole-log incident detector
(app/detectors/log_incidents.py) from real attack data, and test it honestly. Real data only, nothing is downloaded
except the LogHub test logs (16 small files from GitHub, SHA-256 checked).

Data:
  * AIT Log Data Set V1.1 (CC BY-NC-SA 4.0), prepared by app/ml/training/prepare_ait_logs.py into
    data/log_analysis/ait_v1_lines.jsonl.gz: 4 attacked web / mail servers, every line labelled.
  * LogHub (github.com/logpai/loghub, 2,000-line samples of 16 real systems) - TEST ONLY: 14 normal systems (Hadoop,
    Spark, Windows, Android, Apache error log ...) for false alarms, and Linux + OpenSSH, which contain REAL
    internet password attacks, for detection.

Method (no learning from the test data):
  * For each burst detector (password brute force, web scan, service probing, account enumeration) the threshold is
    the largest burst seen in NORMAL traffic + 1 - normal lines of the training servers AND real website logs (the lab's
    simulated users are cleaner than the internet) - and never below 5 (fail2ban's long-standing default).
  * Leave-one-server-out: thresholds from 3 servers, then on the 4th server: which real attack steps became incidents
    (nikto scan, hydra brute force, mail VRFY enumeration, nmap probing, webshell upload), and how many incidents were
    made only of normal lines (false incidents).
  * Final thresholds from all 4 servers -> app/ml/models/log_analysis.json (+ every result).

Run from backend/ (venv active), after prepare_ait_logs:
    python -m app.ml.training.train_log_analysis
"""
import argparse
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

from app.detectors import log_incidents as LI

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "log_analysis")
MODELS = os.path.join(HERE, "..", "models")
GH = "https://raw.githubusercontent.com/logpai/loghub/"
LOGHUB = {   # system: (URL pinned to one commit, SHA-256)
    "Android": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Android/Android_2k.log", "47641549915e662ff590291df266a45f635eedca7c5f1b41a4fa853fe5d2f409"),
    "Apache": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Apache/Apache_2k.log", "c7efa3eb686e3a96bd2f8f4457b2a7887e9cf2f3649327f1b4e87af841363ce8"),
    "BGL": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/BGL/BGL_2k.log", "2a819ea540909db682005c9cf948387a40729b5c2e9f19d430e29ce704825496"),
    "HDFS": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/HDFS/HDFS_2k.log", "7c967000980c086ed55fa6544ba4f05fe66d44622795e890c68caf8bbb635035"),
    "HPC": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/HPC/HPC_2k.log", "826e5957b461e65780a8bda5c186c2fcf90fd6c1863721ef9c1ccfa9ada86f88"),
    "Hadoop": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Hadoop/Hadoop_2k.log", "9ecaeb807d50d5fb5a20982ea66f1c8d32545259a51ce7456c1ab78db0509732"),
    "HealthApp": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/HealthApp/HealthApp_2k.log", "95ec36322f5db1e6faaab764c568b67023d7d6733793106289dbf30516fc13ee"),
    "Linux": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Linux/Linux_2k.log", "b3e20bc1afe732ab1bf3ed1de4bf9c809e4194e02f7dea911d918e5342e8e173"),
    "Mac": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Mac/Mac_2k.log", "d9ea495488728d8c989dc942fca3324a3cc7b19b0a6f409a5fd568ad547fd931"),
    "OpenSSH": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/OpenSSH/OpenSSH_2k.log", "1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f"),
    "OpenStack": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/OpenStack/OpenStack_2k.log", "025a1bc64ff5b2ef4a4bda6c4ad5c5c5f18478b71cd1ad2b0676e01625629f2f"),
    "Proxifier": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Proxifier/Proxifier_2k.log", "94b6a9d98d76e7ad7841ed10caa463cd4e638a229b92a220a2bf1707552adbb9"),
    "Spark": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Spark/Spark_2k.log", "2e8b9a37fc5c238253e0b8e18a8bd5e489671def91767ae1192d28c8e1f95901"),
    "Thunderbird": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Thunderbird/Thunderbird_2k.log", "903bbfa61c34d4803e4adcb0d726ff2eeb9a2e11971243269a2035fa6c3bbeb0"),
    "Windows": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Windows/Windows_2k.log", "372fb809464a6d6016e599e9272d7cf1e8b644f25c90c7f76f19c936362456d0"),
    "Zookeeper": (GH + "dd61d0952749ee7963bde24220d1be5ede023033/Zookeeper/Zookeeper_2k.log", "e40e0af5ef9eb6e4097200f260b9d1f626b3676f861a432e87977242e75543d8"),
}
# Real NORMAL website traffic used to choose the web-scan level (the AIT lab's simulated users are cleaner than the
# internet: real visitors and crawlers produce up to 14 rejected requests per 10 minutes). Elastic's sample of real
# Apache access logs (semicomplete.com, 10,000 lines; Apache 2.0 licence).
REFERENCE_NORMAL = {"elastic_apache_access.log": (
    "https://raw.githubusercontent.com/elastic/examples/6d86454ebb7a850bcd7e80abe86fe683370018a6/"
    "Common%20Data%20Formats/apache_logs/apache_logs",
    "f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef")}
MIN_THRESHOLD = 5      # never fewer than 5 events: the long-standing default of fail2ban (5 failures in 10 minutes)
SKIP_LOGS = ("suricata/eve.json", "mail.info")                   # eve.json = network flows; mail.info = copy of mail.log
ATTACK_CATEGORIES = {"nikto": {"web_scan", "scanner_tool", "web_attack"}, "hydra": {"brute_force"},
                     "vrfy": {"enumeration"}, "nmap": {"probe"}, "upload": {"webshell"}}
BURST = ("brute_force", "web_scan", "probe", "enumeration")


def attack_name(label: str):
    a, _, b = label.partition(",")
    for name in (b, a):
        if name and name != "0":
            return name.split("-")[0]
    return None


def load_ait(path):
    files = defaultdict(list)        # (host, log) -> [(n, label, line)]
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if any(s in r["log"] for s in SKIP_LOGS):
                continue
            files[(r["host"], r["log"])].append((r["n"], r["label"], r["line"]))
    for k in files:
        files[k].sort()
    return files


def precompute(files):
    """Events of every file, once: on its normal lines only, and on all its lines."""
    cache = {}
    for k, rows in files.items():
        normal = [line for _, lab, line in rows if lab.replace(" ", "") == "0,0"]
        lines = [line for _, _, line in rows]
        cache[k] = {"normal_events": LI.events(normal), "lines": lines, "labels": [lab for _, lab, _ in rows],
                    "events": LI.events(lines)}
    return cache


def normal_max_bursts(cache, hosts):
    """Largest burst per category on the NORMAL lines ('0,0') of the given servers."""
    worst = {c: 0 for c in BURST}
    for (host, log), c in cache.items():
        if host not in hosts:
            continue
        by = defaultdict(list)
        for ev in c["normal_events"]:
            by[(ev[0], ev[3])].append(ev)
        for (cat, key), items in by.items():
            if cat in worst:
                worst[cat] = max(worst[cat], LI._max_window(items))
    return worst


def evaluate_host(cache, host, cfg):
    """Which attack steps on this server became incidents, and how many incidents had only normal lines."""
    present, caught, false_inc, all_inc = defaultdict(int), defaultdict(bool), [], 0
    for (h, log), c in cache.items():
        if h != host:
            continue
        labels, evs = c["labels"], c["events"]
        for lab in labels:
            name = attack_name(lab)
            if name in ATTACK_CATEGORIES:
                present[name] += 1
        for inc in LI.incidents(c["lines"], cfg, evs):
            all_inc += 1
            names = {attack_name(labels[ev[1] - 1]) for ev in evs
                     if ev[0] == inc["category"] and ev[3] == inc["source"]}
            if names == {None}:
                false_inc.append({"log": log, "category": inc["category"], "source": inc["source"], "count": inc["count"],
                                  "example": inc["examples"][0][:160]})
            for name in names:
                if name in ATTACK_CATEGORIES and inc["category"] in ATTACK_CATEGORIES[name]:
                    caught[name] = True
    return ({n: bool(caught[n]) for n in present if present[n]}, false_inc, all_inc)


def fetch(name, url, digest, folder):
    path = os.path.join(folder, name)
    if not os.path.exists(path) or sha256(path) != digest:
        os.makedirs(folder, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "CyberGuard-training/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r, open(path + ".part", "wb") as f:
            f.write(r.read())
        if sha256(path + ".part") != digest:
            os.remove(path + ".part")
            sys.exit(f"{name}: downloaded file does not match its pinned SHA-256 - not used.")
        os.replace(path + ".part", path)
    return path


def reference_max_bursts(folder):
    """Largest burst per category in real normal reference logs (real website traffic)."""
    worst = {c: 0 for c in BURST}
    for name, (url, digest) in REFERENCE_NORMAL.items():
        with open(fetch(name, url, digest, folder), encoding="utf-8", errors="replace") as f:
            lines = [ln.rstrip("\n") for ln in f]
        by = defaultdict(list)
        for ev in LI.events(lines):
            by[(ev[0], ev[3])].append(ev)
        for (cat, key), items in by.items():
            if cat in worst:
                worst[cat] = max(worst[cat], LI._max_window(items))
    return worst


def choose(worst_ait, worst_ref):
    return {c: max(worst_ait[c], worst_ref[c]) + 1 if max(worst_ait[c], worst_ref[c]) + 1 > MIN_THRESHOLD
            else MIN_THRESHOLD for c in BURST}


def loghub_test(cfg, lh_dir):
    out = {}
    for system, (url, digest) in LOGHUB.items():
        with open(fetch(f"{system}_2k.log", url, digest, lh_dir), encoding="utf-8", errors="replace") as f:
            res = LI.analyze(f.read(), cfg)          # exactly the thresholds chosen in this run
        out[system] = [{"incident": i["label"], "lines": i["lines"], "sources": i["sources"][:5]} for i in res["incidents"]]
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(DATA, "ait_v1_lines.jsonl.gz"))
    ap.add_argument("--out", default=MODELS)
    ap.add_argument("--no-loghub", action="store_true", help="skip the LogHub test (automated tests only)")
    a = ap.parse_args()
    if not os.path.exists(a.data):
        sys.exit(f"Not found: {a.data}\nRun first: python -m app.ml.training.prepare_ait_logs --download, "
                 "then python -m app.ml.training.prepare_ait_logs")
    t0 = time.time()
    files = load_ait(a.data)
    hosts = sorted({h for h, _ in files})
    print("Reading every line once (a few minutes) ...", flush=True)
    cache = precompute(files)
    print(f"Loaded {sum(len(v) for v in files.values()):,} lines from {len(files)} log files of {len(hosts)} servers "
          f"({time.time() - t0:.0f}s)", flush=True)

    ref = reference_max_bursts(os.path.join(DATA, "reference"))
    print(f"largest bursts in real normal website traffic: {ref}", flush=True)
    folds = {}
    for test in hosts:
        train = [h for h in hosts if h != test]
        worst = normal_max_bursts(cache, train)
        cfg = choose(worst, ref)
        caught, false_inc, n_inc = evaluate_host(cache, test, cfg)
        folds[test] = {"thresholds": cfg, "attack_steps_caught": caught, "incidents": n_inc,
                       "false_incidents": len(false_inc), "false_incident_examples": false_inc[:5]}
        print(f"held-out {test}: thresholds {cfg}  caught {caught}  incidents {n_inc}  false {len(false_inc)}"
              f"  ({time.time() - t0:.0f}s)", flush=True)

    worst = normal_max_bursts(cache, hosts)
    final = choose(worst, ref)
    steps = defaultdict(lambda: [0, 0])
    for f in folds.values():
        for name, ok in f["attack_steps_caught"].items():
            steps[name][0] += int(ok)
            steps[name][1] += 1
    results = {"leave_one_server_out": folds,
               "attack_steps_caught_on_held_out_servers": {k: f"{v[0]} of {v[1]} servers" for k, v in steps.items()},
               "false_incidents_on_held_out_servers": sum(f["false_incidents"] for f in folds.values())}
    if not a.no_loghub:
        results["loghub_other_systems"] = loghub_test(final, os.path.join(DATA, "loghub"))
    info = {"what": "burst thresholds of the whole-log incident detector (app/detectors/log_incidents.py)",
            "thresholds": final, "window_seconds": LI.WINDOW_S,
            "method": "largest burst seen in normal traffic (AIT normal lines + real website logs) + 1, at least "
                      f"{MIN_THRESHOLD}; leave-one-server-out test on AIT, LogHub (16 systems) as an outside test",
            "normal_reference_bursts": ref, "ait_normal_bursts": worst,
            "data": "AIT Log Data Set V1.1 (Landauer et al., IEEE TR 2021; CC BY-NC-SA 4.0); test: LogHub 2k samples",
            "results": results, "calibrated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "log_analysis.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    print(json.dumps({"thresholds": final, **{k: v for k, v in results.items() if k != "leave_one_server_out"}}, indent=2))
    print(f"\nSaved {os.path.join(a.out, 'log_analysis.json')}  ({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
