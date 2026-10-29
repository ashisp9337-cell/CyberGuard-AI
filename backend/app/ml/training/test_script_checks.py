r"""Test the script checks (app/detectors/script_checks.py) on REAL scripts: how many malicious scripts reach the alert
level (71+, quarantined by the Downloads watcher) and how many ordinary scripts do (false alarms).

!! Do NOT run this on your Windows PC. The malicious set is real malware text (never run, only read), and Microsoft
!! Defender would flag and delete those files as soon as git writes them. Run it on a Linux / cloud machine; the
!! results it saves (app/ml/models/script_checks.json) are what show_auc.py reads.

Data (git clone each into one folder, e.g. data/scripts/):
  * das-lab/mpsd (Fang, Zhou, Huang, Neurocomputing 448, 2021) - malicious_pure: real malicious PowerShell from
    malware reports and attack tools; powershell_benign_dataset: ordinary PowerShell from GitHub. No licence is stated,
    so it is only used for testing here, never copied into CyberGuard.
    Many samples are near-copies (the same dropper with another address), so scripts are grouped by their "skeleton"
    (strings, numbers, Base64 and variable names blanked) and each group counts once. The groups are split in two by a
    hash: "dev" was looked at while the checks were written, "test" was not.
  * ordinary scripts from big public projects (all MIT / Apache): chocolatey-community/chocolatey-packages (software
    installers - they download and install programs, the hardest case), PowerShell/PowerShell, PowerShell/PSScriptAnalyzer,
    dotnet/install-scripts.
  * redcanaryco/atomic-red-team (MIT): the attack commands of selected MITRE ATT&CK techniques for Windows, run through
    the same checks as a script would be. Not every technique is something the checks look for (e.g. downloading alone).

    python -I app/ml/training/test_script_checks.py <folder with the clones>
"""
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, BACKEND)   # the backend folder (python -I ignores cwd)

from app.detectors import script_checks as S  # noqa: E402

OUT_JSON = os.path.join(BACKEND, "app", "ml", "models", "script_checks.json")
ALERT, CHECK = 71, 55
ORDINARY = {"Software installers (chocolatey-packages)": ["chocolatey-packages/**/*.ps1"],
            "PowerShell's own scripts (PowerShell/PowerShell)": ["PowerShell/**/*.ps1", "PowerShell/**/*.psm1"],
            "PSScriptAnalyzer": ["PSScriptAnalyzer/**/*.ps1", "PSScriptAnalyzer/**/*.psm1"],
            "dotnet install scripts": ["install-scripts/**/*.ps1", "install-scripts/**/*.sh"]}
TECHNIQUES = ["T1059.001", "T1027", "T1105", "T1490", "T1218.005", "T1218.010", "T1218.011", "T1197", "T1140",
              "T1548.002", "T1055", "T1620", "T1059.005", "T1059.007", "T1547.001", "T1053.005"]


def skeleton(text: str) -> str:
    t = text.lower()
    t = re.sub(r"[a-z0-9+/=]{30,}", "B", t)
    t = re.sub(r"(['\"]).*?\1", "S", t)
    t = re.sub(r"\$[\w:]+", "$v", t)
    t = re.sub(r"\d+", "0", t)
    return hashlib.sha1(re.sub(r"\s+", " ", t).encode()).hexdigest()


def load(folder, patterns):
    """{skeleton: (path, bytes)} - one script per skeleton group."""
    out = {}
    for pat in patterns:
        for f in sorted(glob.glob(os.path.join(folder, pat), recursive=True)):
            if os.path.isfile(f) and os.path.getsize(f) < 3_000_000:
                with open(f, "rb") as fh:
                    b = fh.read()
                out.setdefault(skeleton(b.decode("utf-8", "ignore")), (f, b))
    return out


def measure(scripts: dict, report: list, tag: str) -> dict:
    """alert / check: the script checks' own level (Malware upload card, where being a script is not counted);
    quarantine: the Downloads watcher, where a script file also gets the 45 points of "program or script"."""
    alert = check = anyf = quarantine = 0
    by = Counter()
    for _, (f, b) in sorted(scripts.items()):
        inds, floor = S.check(os.path.basename(f), b)
        alert += floor >= ALERT
        check += CHECK <= floor < ALERT
        anyf += bool(inds)
        quarantine += max(45 + sum(i["weight"] for i in inds), floor) >= ALERT
        by.update(i["label"] for i in inds)
        if inds:
            report.append(f"[{tag}] floor {floor}: {', '.join(i['label'] for i in inds)}\n    {f}")
    n = max(len(scripts), 1)
    return {"scripts": len(scripts), "alert": alert, "alert_rate": round(alert / n, 4), "check": check,
            "any_finding": anyf, "downloads_quarantined": quarantine, "by_check": dict(by)}


def atomics(folder):
    import yaml
    out = {}
    for t in TECHNIQUES:
        p = os.path.join(folder, "atomic-red-team", "atomics", t, f"{t}.yaml")
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        for test in doc.get("atomic_tests", []):
            ex = test.get("executor") or {}
            if "windows" not in (test.get("supported_platforms") or []) or ex.get("name") not in ("powershell",
                                                                                               "command_prompt"):
                continue
            cmd = ex.get("command") or ""
            for arg, spec in (test.get("input_arguments") or {}).items():
                cmd = cmd.replace("#{" + arg + "}", str((spec or {}).get("default", "")))
            ext = ".ps1" if ex["name"] == "powershell" else ".bat"
            out.setdefault(t, []).append((f"{t} {test.get('name', '')}", cmd.encode("utf-8"), ext))
    return out


def main(folder):
    results, report = {}, []
    mpsd_bad = load(folder, ["mpsd/malicious_pure/*"])
    mpsd_ok = load(folder, ["mpsd/powershell_benign_dataset/*"])
    if not mpsd_bad:
        sys.exit(f"mpsd not found in {folder} - see the top of this file.")
    for split, want in (("dev", 0), ("test", 1)):
        bad = {k: v for k, v in mpsd_bad.items() if int(k, 16) % 2 == want}
        ok = {k: v for k, v in mpsd_ok.items() if int(k, 16) % 2 == want}
        results[f"mpsd_malicious_{split}"] = measure(bad, report, f"malicious {split}")
        results[f"mpsd_ordinary_{split}"] = measure(ok, report, f"ordinary {split}")
    for name, pats in ORDINARY.items():
        s = load(folder, pats)
        if s:
            results[name] = measure(s, report, name)
    at = atomics(folder)
    if at:
        per = {}
        for t, tests in at.items():
            fl = [S.check("x" + ext, b)[1] for _, b, ext in tests]
            per[t] = {"commands": len(tests), "alert": sum(f >= ALERT for f in fl), "check": sum(CHECK <= f < ALERT for f in fl)}
            for (name, b, ext), f in zip(tests, fl):
                report.append(f"[ATT&CK {'ALERT' if f >= ALERT else 'check' if f >= CHECK else 'missed'}] {name}")
        results["attack_commands"] = per

    for k, v in results.items():
        if k == "attack_commands":
            continue
        print(f"{k:52s} {v['alert']:5d} of {v['scripts']:5d} at alert ({v['alert_rate']:.1%}), {v['check']} at check; "
              f"Downloads watcher would quarantine {v['downloads_quarantined']}")
    if at:
        tot = sum(v["commands"] for v in results["attack_commands"].values())
        al = sum(v["alert"] for v in results["attack_commands"].values())
        ch = sum(v["check"] for v in results["attack_commands"].values())
        print(f"{'ATT&CK attack commands (atomic-red-team)':52s} {al:5d} of {tot:5d} at alert, {ch} at check")
        for t, v in results["attack_commands"].items():
            print(f"    {t:12s} {v['alert']:3d} alert, {v['check']:3d} check, of {v['commands']}")
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)
    with open(os.path.join(HERE, "script_checks_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report) + "\n")
    print(f"\nwrote {OUT_JSON} and script_checks_report.txt")
    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
