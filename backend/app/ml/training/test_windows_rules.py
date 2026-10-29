r"""Test the Windows event rules (app/detectors/windows_events.py) on REAL attack recordings: OTRF Security-Datasets.

OTRF Security-Datasets (Open Threat Research Forge, MIT licence; github.com/OTRF/Security-Datasets) are Windows
Security / Sysmon / PowerShell logs recorded while one known attack technique ran on lab machines - together with all
the ordinary background activity of those machines. The rules were written from MITRE ATT&CK descriptions BEFORE this
test and are not tuned on it.
A cleared event log is not counted (OTRF clears the logs at the start of every recording).
Reads every datasets\atomic\windows\<tactic>\host\*.zip / *.tar.gz in the folder given (nothing is unpacked to disk)
and prints, per tactic, how many recordings raised at least one medium-or-higher incident; every incident goes to
windows_rules_report.txt for review. Get the data once (about 100 MB, from the backend folder):
    git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets app\ml\training\data\otrf
    cd app\ml\training\data\otrf && git sparse-checkout set --no-cone "datasets/atomic/windows/*/host/*" && cd ..\..\..\..\..
    python -I app\ml\training\test_windows_rules.py app\ml\training\data\otrf
Optional second, INDEPENDENT test (the rules added on 26 Oct were written while looking at OTRF misses, so OTRF alone
would flatter them): EVTX-ATTACK-SAMPLES (github.com/sbousseaden/EVTX-ATTACK-SAMPLES, GPL-3.0), .evtx files of real
attack tools sorted by tactic, never looked at while writing the rules (about 40 MB):
    git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES app\ml\training\data\evtx_samples
    python -I app\ml\training\test_windows_rules.py app\ml\training\data\otrf app\ml\training\data\evtx_samples
"""
import io
import json
import os
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))   # the backend folder (python -I ignores cwd)

from app.detectors import windows_events as W  # noqa: E402

# which incident lenses count as "the technique was seen", per tactic folder
EXPECTED = {"credential_access": {"Credential theft", "Attacker activity"},
            "defense_evasion": {"Security controls bypassed", "Attacker activity", "Account / permission change"},
            "discovery": {"Abnormal activity", "Attacker activity"},
            "execution": {"Attacker activity"},
            "lateral_movement": {"Attacker activity", "Persistence"},
            "persistence": {"Persistence"},
            "privilege_escalation": {"Attacker activity", "Persistence", "Account / permission change"},
            "collection": set()}


def _texts(path):
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.endswith(".json"):
                    yield z.read(n).decode("utf-8", "replace")
    elif path.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as t:
            for m in t:
                if m.isfile() and m.name.endswith(".json"):
                    yield t.extractfile(m).read().decode("utf-8", "replace")


def independent_test(folder):
    """EVTX-ATTACK-SAMPLES: per tactic folder, how many .evtx files raise at least one medium-or-higher incident."""
    per, report = defaultdict(lambda: [0, 0]), []
    for tactic in sorted(os.listdir(folder)):
        d = os.path.join(folder, tactic)
        if not os.path.isdir(d) or tactic.startswith("."):
            continue
        for f in sorted(os.listdir(d)):
            if not f.lower().endswith(".evtx"):
                continue
            xml, _ = W.evtx_to_xml(os.path.join(d, f))
            evs = W.parse(xml)[0] if xml else []
            if not evs:
                continue
            real = [i for i in W.analyze(evs)["incidents"] if i["severity"] in ("critical", "high", "medium")
                    and i["rule"] != "log_cleared"]
            per[tactic][0] += 1
            per[tactic][1] += bool(real)
            report.append(f"   {tactic}/{f}: {sorted({i['rule'] for i in real})}")
    tot = [sum(v[0] for v in per.values()), sum(v[1] for v in per.values())]
    print(f"\nINDEPENDENT test (EVTX-ATTACK-SAMPLES): {tot[1]} of {tot[0]} attack files raise an incident")
    for t, (n, a) in sorted(per.items()):
        print(f"   {t:24s} {a:3d} of {n:3d}")
    return {"data": "EVTX-ATTACK-SAMPLES, github.com/sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0); not used to write the rules",
            "per_tactic": {t: {"files": n, "any_incident": a} for t, (n, a) in per.items()},
            "total": {"files": tot[0], "any_incident": tot[1]},
            "before_26_oct_rules": "41 of 263 files (same test, rules before the 26 Oct additions)"}, report


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "data", "otrf")
    base = os.path.join(root, "datasets", "atomic", "windows")
    if not os.path.isdir(base):
        sys.exit(f"{base} not found - see the instructions at the top of this script.")
    per_tactic = defaultdict(lambda: [0, 0, 0])      # recordings, any medium+ incident, expected lens seen
    rule_counts = Counter()
    report = []
    for tactic in sorted(os.listdir(base)):
        hostdir = os.path.join(base, tactic, "host")
        if not os.path.isdir(hostdir):
            continue
        for f in sorted(os.listdir(hostdir)):
            if not (f.endswith(".zip") or f.endswith(".tar.gz")):
                continue
            evs = []
            for text in _texts(os.path.join(hostdir, f)):
                evs += W.parse(text)[0]
            if not evs:
                continue
            s = W.analyze(evs)
            # OTRF clears the event logs at the start of every recording (lab procedure, not the attack): a cleared
            # log is still reported by the app, but it is NOT counted here as having caught the technique
            real = [i for i in s["incidents"] if i["severity"] in ("critical", "high", "medium")
                    and i["rule"] != "log_cleared"]
            seen = {i["lens"] for i in real}
            pt = per_tactic[tactic]
            pt[0] += 1
            pt[1] += bool(real)
            pt[2] += bool(seen & EXPECTED.get(tactic, set()))
            rule_counts.update(i["rule"] for i in real)
            report.append(f"\n== {tactic}/{f}: {len(evs):,} events, {len(real)} medium+ incident(s)")
            for i in s["incidents"]:
                report.append(f"   [{i['severity']:8s}] {i['label']} | {i['user']}@{i['host']} x{i['count']} | "
                              f"{i['mitre']} | {'; '.join(str(e) for e in i['examples'])[:220]}")
    print(f"{'tactic':22s} {'recordings':>10s} {'any incident':>13s} {'technique seen':>15s}")
    tot = [0, 0, 0]
    for t, (n, a, e) in sorted(per_tactic.items()):
        print(f"{t:22s} {n:10d} {a:13d} {e:15d}")
        tot = [tot[0] + n, tot[1] + a, tot[2] + e]
    print(f"{'ALL':22s} {tot[0]:10d} {tot[1]:13d} {tot[2]:15d}")
    print("medium+ incidents by rule:", dict(rule_counts.most_common()))
    independent = None
    if len(sys.argv) > 2:
        independent, more = independent_test(sys.argv[2])
        report += ["", "== INDEPENDENT TEST (EVTX-ATTACK-SAMPLES)"] + more
    out = os.path.join(HERE, "windows_rules_report.txt")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    print(f"every incident: {out}")
    saved = {"data": "OTRF Security-Datasets, datasets/atomic/windows/*/host (MIT licence)",
             "per_tactic": {t: {"recordings": n, "any_incident": a, "technique_seen": e}
                            for t, (n, a, e) in per_tactic.items()},
             "total": {"recordings": tot[0], "any_incident": tot[1], "technique_seen": tot[2]},
             "incidents_by_rule": dict(rule_counts)}
    if independent:
        saved["independent_test"] = independent
    with open(os.path.join(HERE, "..", "models", "windows_rules.json"), "w", encoding="utf-8") as fh:
        json.dump(saved, fh, indent=1)


if __name__ == "__main__":
    main()
