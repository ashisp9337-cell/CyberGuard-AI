"""
CyberGuard - the AUC of every subtopic of every module, in one table. READ-ONLY: nothing is trained, no model or
data file is changed.

    cd backend   (venv active)
    python show_auc.py            # the AUCs each training script saved (measured on data the model never saw)
    python show_auc.py --recalc   # ALSO recalculates live, now, on this PC (about 1-2 minutes):
                                  #   Email, SMS and the fallback text model on the exact 20% of their data they never
                                  #   trained on (same split as training: test_size 0.2, random_state 42)
                                  #   URL-structure model on 2026 urlscan.io links (data/urlscan/scans.jsonl)
                                  #   domain-name model on 2026 sites (needs data/crux/current.csv.gz, see below)

AUC: 1.0 = always ranks a scam above a real item, 0.5 = coin toss. Report saved to backend/auc_check.txt (git ignores it).
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MODELS = os.path.join(HERE, "app", "ml", "models")
DATA = os.path.join(HERE, "app", "ml", "training", "data")
OUT = []


def say(s=""):
    print(s, flush=True)
    OUT.append(s)


def saved(file, *path):
    """A number from a saved metrics file, or None."""
    try:
        with open(os.path.join(MODELS, file), encoding="utf-8") as f:
            d = json.load(f)
        for p in path:
            d = d[p]
        return d if isinstance(d, (int, float)) else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def fmt(v):
    return f"{v:.3f}" if isinstance(v, (int, float)) else "  -  "


# (module, subtopic, [(what, file, key path...)], note when there is no AUC)
ROWS = [
    ("Phishing", "Email analysis", [("held-out 20% (never trained on)", "phishing_email.metrics.json", "results", "heldout", "auc"),
                                    ("held-out, unlike any training e-mail", "phishing_email.metrics.json", "results", "heldout_unseen_texts", "auc")],
     "saved by: python -I app\\ml\\training\\measure_text_models.py"),
    ("Phishing", "SMS / message", [("held-out real messages", "phishing_sms.metrics.json", "results", "heldout_real_only", "auc"),
                                   ("held-out real, unlike any training SMS", "phishing_sms.metrics.json", "results", "heldout_real_unseen_texts", "auc")],
     "saved by: python -I app\\ml\\training\\measure_text_models.py"),
    ("Phishing", "Social media", [("unseen YouTube video", "phishing_social.metrics.json", "tests", "youtube_unseen_video", "roc_auc"),
                                  ("held-out SMS", "phishing_social.metrics.json", "tests", "sms_holdout", "roc_auc")], ""),
    ("Phishing", "QR code", [("public QR set, whole engine", "link_benchmark_2026.metrics.json", "qr_dataset", "auc")],
     "QR reading: 9,987 / 9,987 codes decoded"),
    ("Phishing", "Fraudulent website / URL", [("2026 links, whole engine offline", "link_benchmark_2026.metrics.json", "url_engine_2026", "auc"),
                                              ("later 2026 links + real sites, with 2026 link model", "link_2026.metrics.json", "results", "whole_url_engine_offline", "after", "auc"),
                                              ("  same links, without it", "link_2026.metrics.json", "results", "whole_url_engine_offline", "before", "auc")],
     "same URL engine as URL security; live checks not included"),
    ("URL security", "Domain spoofing", [("held-out domains", "domain_spoofing.metrics.json", "results", "heldout_domains_all", "auc"),
                                         ("independent set", "domain_spoofing.metrics.json", "results", "extra_independent_test", "auc")], ""),
    ("URL security", "Look-alike domain", [("held-out sites", "lookalike_domain.metrics.json", "results", "heldout_sites_all", "auc")], ""),
    ("URL security", "URL manipulation", [("held-out sites", "url_manipulation.metrics.json", "results", "heldout_sites", "auc"),
                                          ("2026 links", "link_benchmark_2026.metrics.json", "url_manipulation_model_2026", "auc")], ""),
    ("URL security", "Redirect analysis", [], "no model of its own (shared URL engine + rules)"),
    ("URL security", "SSL & domain (registry)", [("held-out domains", "domain_age.metrics.json", "results", "test", "auc"),
                                                 ("domains < 1 year old", "domain_age.metrics.json", "results", "test_domains_under_1_year", "auc")], ""),
    ("URL security", "Fake login page", [("unseen kits + sites", "fake_login.metrics.json", "results", "all_clues_unseen_kits_and_sites", "auc"),
                                         ("October-only phishing", "fake_login.metrics.json", "results", "time_test_october_phishing_unseen", "auc")], ""),
    ("URL security", "General (domain-name model)", [("held-out domains", "url_domain_model.metrics.json", "metrics", "roc_auc"),
                                                     ("2026 phishing domains", "link_benchmark_2026.metrics.json", "domain_name_model_2026", "auc_new_2026_phishing_domains")], ""),
    ("Credential", "Failed logins", [("held-out", "cred_failed-logins.metrics.json", "metrics", "test", "roc_auc")], ""),
    ("Credential", "Password spraying", [("held-out", "cred_password-spraying.metrics.json", "metrics", "test", "roc_auc")], ""),
    ("Credential", "Unusual location", [("held-out", "cred_unusual-location.metrics.json", "metrics", "test", "roc_auc"),
                                        ("real attacker logins", "cred_unusual-location.metrics.json", "metrics", "real_attacker_logins_vs_normal", "roc_auc")], ""),
    ("Credential", "Unknown device", [("held-out", "cred_unknown-device.metrics.json", "metrics", "test", "roc_auc"),
                                      ("real attacker logins", "cred_unknown-device.metrics.json", "metrics", "real_attacker_logins_vs_normal", "roc_auc")], ""),
    ("Credential", "Session activity", [("held-out", "cred_session-activity.metrics.json", "metrics", "test", "roc_auc"),
                                        ("real attacker logins", "cred_session-activity.metrics.json", "metrics", "real_attacker_logins_vs_normal", "roc_auc")], ""),
    ("Credential", "Behaviour changes", [("held-out", "cred_behavior-changes.metrics.json", "metrics", "test", "roc_auc"),
                                         ("real attacker logins", "cred_behavior-changes.metrics.json", "metrics", "real_attacker_logins_vs_normal", "roc_auc")], ""),
    ("Credential", "Account takeover (main)", [("foreign attacker", "ato_rba_model.metrics.json", "metrics", "account_side", "simulated_attacker_naive", "roc_auc"),
                                               ("same-country attacker", "ato_rba_model.metrics.json", "metrics", "account_side", "simulated_attacker_same_country", "roc_auc")], ""),
    ("Cyber threat", "API abuse", [("independent (Fwaf) attacks", "api_abuse.metrics.json", "results", "auc", "fwaf_independent_attack_payloads"),
                                   ("unseen websites vs attacks", "api_abuse.metrics.json", "results", "auc", "unseen_websites_vs_csic_attacks"),
                                   ("CSIC official test", "api_abuse.metrics.json", "results", "auc", "csic_official_test")],
     "train it: python -m app.ml.training.train_api_abuse --download, then without --download"),
    ("Deepfake", "Image: AI-generated", [("held-out", "ai_image.json", "results", "test", "auc"),
                                         ("modern generators", "ai_image.json", "results", "test:modern-generators", "auc")], ""),
    ("Deepfake", "Image: face-swap", [("held-out", "deepfake_image.json", "results", "test", "auc")], ""),
    ("Deepfake", "Video / video call", [("Celeb-DF unseen", "deepfake_video.json", "results", "test_celebdf_half_B_honest", "auc"),
                                        ("DFDC (other dataset)", "deepfake_video.json", "results", "test_dfdc_independent", "auc")], ""),
    ("Deepfake", "AI multimedia", [], "uses the image models above; no model for fully AI-generated video"),
    ("Deepfake", "Voice: AI / cloned voice", [("In-the-Wild (real-world)", "voice_ai.json", "results", "In-the-Wild (real-world, outside test)", "AUC"),
                                              ("ASVspoof 2019 eval", "voice_ai.json", "results", "ASVspoof 2019 eval (11 of 13 attacks unseen)", "AUC"),
                                              ("held-out MLAAD systems", "voice_ai.json", "results", "MLAAD held-out English systems + LibriSpeech test-clean real", "AUC"),
                                              ("In-the-Wild after Opus", "voice_ai.json", "results", "In-the-Wild after WhatsApp-style Opus 16 kbps", "AUC")],
     "train it: docs/colab/CyberGuard_Voice_Colab.ipynb (Google Colab)"),
    ("Deepfake", "Voice match (voiceprint)", [("unseen speakers", "voiceprint.json", "results", "AUC")], ""),
]
IMPERSONATION = [("Government", "government_official_impersonation.metrics.json", "government"),
                 ("Senior management", "senior_management_impersonation.metrics.json", "management"),
                 ("Teacher / university", "teacher_university_impersonation.metrics.json", "teacher"),
                 ("Financial", "financial_impersonation.metrics.json", "financial"),
                 ("Brand", "brand_impersonation.metrics.json", "brand")]


def show_saved():
    say("=" * 100)
    say("SAVED AUCs (written by each training script; measured on data the model never saw)")
    say("=" * 100)
    say(f"{'Module':13s} {'Subtopic':30s} {'AUC':>6s}  measured on")
    last = None
    for module, sub, items, note in ROWS:
        if module != last:
            say("-" * 100)
            last = module
        if not items:
            say(f"{module:13s} {sub:30s} {'  -  ':>6s}  {note}")
            continue
        for i, (what, file, *path) in enumerate(items):
            say(f"{module if i == 0 else '':13s} {sub if i == 0 else '':30s} {fmt(saved(file, *path)):>6s}  {what}")
        if note:
            say(f"{'':13s} {'':30s} {'':6s}  ({note})")
    say("-" * 100)
    say("Impersonation models saved catch / false-alarm rates on real messages (no AUC):")
    for name, file, word in IMPERSONATION:
        try:
            r = json.load(open(os.path.join(MODELS, file), encoding="utf-8"))["results"]["new_detector"]
            caught = next(v["caught_rate"] for k, v in r.items() if "scam" in k)
            fa = next(v["false_alarm_rate"] for k, v in r.items() if "genuine" in k and word in k)
            say(f"{'Impersonation':13s} {name:30s} caught {caught:.1%}, false alarms on real {word} messages {fa:.1%}")
        except Exception:
            say(f"{'Impersonation':13s} {name:30s} (metrics file missing)")
    acc = saved("impersonation_router.metrics.json", "model_alone_accuracy", "contact-impersonation")
    say(f"{'Impersonation':13s} {'Friend / known contact':30s} router accuracy {acc:.1%}" if acc else
        f"{'Impersonation':13s} {'Friend / known contact':30s} (metrics file missing)")
    try:
        la = json.load(open(os.path.join(MODELS, "log_analysis.json"), encoding="utf-8"))
        r = la["results"]
        steps = ", ".join(f"{k} {v}" for k, v in r["attack_steps_caught_on_held_out_servers"].items())
        lh = r.get("loghub_other_systems", {})
        quiet = sum(1 for k, v in lh.items() if not v and k not in ("Linux", "OpenSSH"))
        say(f"{'Cyber threat':13s} {'Log analysis (whole files)':30s} incidents, not AUC: attack steps caught on held-out "
            f"AIT servers: {steps}")
        say(f"{'':13s} {'':30s} other real systems: {quiet} of 14 normal ones quiet; real SSH attacks found in "
            f"{sum(1 for k in ('Linux', 'OpenSSH') if lh.get(k))} of 2")
    except (OSError, ValueError, KeyError):
        say(f"{'Cyber threat':13s} {'Log analysis (whole files)':30s} not calibrated yet: python -m app.ml.training.train_log_analysis")
    try:
        nt = json.load(open(os.path.join(MODELS, "network_traffic.json"), encoding="utf-8"))
        held = nt["held_out_days"]
        caught = sum(1 for d in held.values() for v in d["attacks"].values() if v["caught_by"])
        total = sum(len(d["attacks"]) for d in held.values())
        false = sum(len(d["false_incidents"]) for d in held.values())
        say(f"{'Cyber threat':13s} {'Network traffic (behaviour)':30s} incidents, not AUC: attack types caught on held-out "
            f"CIC-IDS2017 days {caught} of {total}; false incidents on held-out normal traffic {false}")
        missed = sorted(k for d in held.values() for k, v in d["attacks"].items() if not v["caught_by"])
        say(f"{'':13s} {'':30s} missed: {', '.join(missed)}")
        aucs = ", ".join(f"{d[:3]} {v['auc']:.3f}" for d, v in nt["model_held_out_days"].items())
        say(f"{'Cyber threat':13s} {'Network: connection model':30s} supporting only - AUC on held-out days: {aucs}")
    except (OSError, ValueError, KeyError):
        say(f"{'Cyber threat':13s} {'Network traffic':30s} not trained yet: python -m app.ml.training.train_network_traffic")
    try:
        ir = json.load(open(os.path.join(MODELS, "insider_risk.json"), encoding="utf-8"))["results"]
        ts, nw, un = ir["time_split"], ir["time_split_no_web"], ir["unseen_total"]
        say(f"{'Cyber threat':13s} {'Insider risk (UEBA, 3 lenses)':30s} AUC {ts['auc']:.3f} (user-days after 1 Oct 2010); "
            f"new insiders caught with 10 reviews/day: {ts['caught']} of {ts['of']} (random {ts['random']})")
        say(f"{'':13s} {'':30s} without web signals: AUC {nw['auc']:.3f}, caught {nw['caught']} of {nw['of']}; "
            f"never-seen insider patterns: {un['caught']} of {un['of']} (random {un['random']})")
        say(f"{'':13s} {'':30s} false alert-level person-days: {ts['false_alert_per_day']} per day (of ~600)")
    except (OSError, ValueError, KeyError):
        say(f"{'Cyber threat':13s} {'Insider risk':30s} not trained yet: python -I app\\ml\\training\\train_insider_risk.py")
    try:
        ix = json.load(open(os.path.join(MODELS, "indic_scams.json"), encoding="utf-8"))
        fa = ix["false_alarms"]
        one = [v for k, v in fa.items() if not k.startswith("SMS corpus") and "chunks" not in k]
        chunks = [v for k, v in fa.items() if "chunks" in k]
        q = ix["quotes"]
        say(f"{'Phishing':13s} {'Hindi / Hinglish / Odia rules':30s} rules, not AUC: fired on {sum(v['fired'] for v in one)} of "
            f"{sum(v['texts'] for v in one):,} real ordinary Hindi / Odia / Hinglish texts and "
            f"{sum(v['fired'] for v in chunks)} of {sum(v['texts'] for v in chunks):,} 3-sentence chunks")
        say(f"{'':13s} {'':30s} real scam quotes caught: held-out {q['held-out']['caught']} of {q['held-out']['of']}, "
            f"dev {q['dev']['caught']} of {q['dev']['of']} (cut quotes: held-out "
            f"{q.get('held-out (cut quotes)', {}).get('caught', 0)} of {q.get('held-out (cut quotes)', {}).get('of', 0)})")
        sl = fa.get("SMS corpus - rows labelled legitimate")
        if sl:
            say(f"{'':13s} {'':30s} SMS corpus rows labelled legitimate: {sl['fired']} of {sl['texts']:,} fired "
                "(read by hand 30 Oct: all are scam texts with a wrong label)")
    except (OSError, ValueError, KeyError):
        say(f"{'Phishing':13s} {'Hindi / Hinglish / Odia rules':30s} not tested yet: app\\ml\\training\\test_indic_scams.py")
    try:
        wr = json.load(open(os.path.join(MODELS, "windows_rules.json"), encoding="utf-8"))
        tot = wr["total"]
        say(f"{'Cyber threat':13s} {'Windows event rules':30s} rules, not AUC: technique seen in {tot['technique_seen']} of "
            f"{tot['recordings']} real attack recordings (OTRF)")
        pt = wr["per_tactic"]
        say(f"{'':13s} {'':30s} " + ", ".join(f"{t.replace('_', ' ')} {v['technique_seen']}/{v['recordings']}"
                                              for t, v in sorted(pt.items()) if v["recordings"] >= 3))
        ind = wr.get("independent_test")
        if ind:
            say(f"{'':13s} {'':30s} independent test (EVTX-ATTACK-SAMPLES, not used to write the rules): "
                f"{ind['total']['any_incident']} of {ind['total']['files']} attack files "
                f"({ind.get('before_26_oct_rules', '').split(' (')[0]} before 26 Oct)")
    except (OSError, ValueError, KeyError):
        say(f"{'Cyber threat':13s} {'Windows event rules':30s} not tested yet: app\\ml\\training\\test_windows_rules.py")
    try:
        mm = json.load(open(os.path.join(MODELS, "malware_model.json"), encoding="utf-8"))["results"]
        a = mm["all"]
        say(f"{'Cyber threat':13s} {'Malware (EMBER2024 model)':30s} AUC {a['auc']:.3f} on files first seen Nov-Dec 2024 "
            f"({a['malware']:,} malware, {a['clean']:,} clean); caught at alert {a['malware_caught_alert']:.1%}, "
            f"clean files flagged {a['clean_flagged_alert']:.2%}")
        say(f"{'':13s} {'':30s} challenge set (first missed by ~70 antivirus engines): "
            f"{a['challenge_caught_alert']:.1%} caught at alert, {a['challenge_caught_check']:.1%} at check")
        for t in ("Win32", "Win64", "Dot_Net", "APK", "PDF", "ELF"):
            r = mm.get(t)
            if r and r.get("auc") is not None:
                say(f"{'':13s} {'  ' + t:30s} AUC {r['auc']:.3f}; caught at alert {r['malware_caught_alert']:.1%}, "
                    f"clean flagged {r['clean_flagged_alert']:.2%}; challenge {r['challenge_caught_alert'] or 0:.1%}")
    except (OSError, ValueError, KeyError, TypeError):
        say(f"{'Cyber threat':13s} {'Malware (EMBER2024 model)':30s} not set up yet: python -I app\\ml\\training\\download_malware_data.py, "
            "then calibrate_malware_model.py")


def recalc_text(name, model_file, data_file, pos_label):
    import joblib
    import pandas as pd
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split
    mp, dp = os.path.join(MODELS, model_file), os.path.join(DATA, data_file)
    if not (os.path.exists(mp) and os.path.exists(dp)):
        say(f"  {name:28s} skipped - missing {model_file if not os.path.exists(mp) else data_file}")
        return
    t0 = time.time()
    df = pd.read_csv(dp, sep="\t", header=None, names=["label", "text"]).dropna(subset=["text"])
    df["y"] = (df["label"] == pos_label).astype(int)
    x_tr, x_te, y_tr, y_te = train_test_split(df["text"], df["y"], test_size=0.2, random_state=42, stratify=df["y"])
    model = joblib.load(mp)
    p = model.predict_proba(x_te)[:, 1]
    auc = roc_auc_score(y_te, p)
    seen = set(x_tr)                          # test messages whose exact text is also in the training part
    keep = [t not in seen for t in x_te]
    auc_new = roc_auc_score(y_te[keep], p[keep]) if 0 < y_te[keep].sum() < sum(keep) else None
    say(f"  {name:28s} AUC {auc:.3f}   only texts not in training: {fmt(auc_new)}   "
        f"({len(y_te):,} held-out, {int(y_te.sum()):,} scams; {time.time() - t0:.0f}s)")


def recalc_links():
    import numpy as np
    from sklearn.metrics import roc_auc_score
    scans = os.path.join(DATA, "urlscan", "scans.jsonl")
    if not os.path.exists(scans):
        say("  URL-structure model, 2026     skipped - data/urlscan/scans.jsonl not found")
        return
    from app.detectors import url_manipulation as UM
    rows = [json.loads(line) for line in open(scans, encoding="utf-8") if line.strip()]

    def probs(urls):
        out = []
        for u in urls:
            a = UM.assess(u)
            if a is not None and not (a.get("noPath") and not a["findings"]):
                out.append(a["probability"])
        return np.array(out)
    real = probs(r["page_url"] for r in rows if r["group"] in ("genuine-login", "genuine-web") and r.get("page_url"))
    ph = probs(r["page_url"] for r in rows if r["group"] == "phish" and r.get("page_url"))
    if len(real) and len(ph):
        auc = roc_auc_score(np.r_[np.ones(len(ph)), np.zeros(len(real))], np.r_[ph, real])
        say(f"  {'URL-structure model, 2026':28s} AUC {auc:.3f}   ({len(ph):,} phishing vs {len(real):,} real urlscan.io pages with a path)")

    crux = os.path.join(DATA, "crux", "current.csv.gz")
    if not os.path.exists(crux):
        say(f"  {'Domain-name model, 2026':28s} skipped - needs the Chrome UX Report list: run once")
        say(f"  {'':28s}   python -m app.ml.training.calibrate_url_domain   (downloads it, ~9 MB)")
        return
    from app.detectors import domain_model as DM
    from app.detectors.url_features_v2 import split_url
    from app.ml.training import calibrate_url_domain as C
    try:
        seen = C.training_sites()
    except SystemExit as e:
        say(f"  {'Domain-name model, 2026':28s} skipped - {e}")
        return
    crux_sites = C.crux_sites()
    real = sorted(v for k, v in crux_sites.items() if k not in seen)
    ph = sorted({s for s in (C.site_of(split_url(r["page_url"])["host"]) for r in rows
                             if r["group"] == "phish" and r.get("page_url")) if s and s[0] not in seen and s[0] not in crux_sites})
    b = DM.load()
    pr, pp = C.probs(b, real), C.probs(b, ph)
    auc = roc_auc_score(np.r_[np.ones(len(pp)), np.zeros(len(pr))], np.r_[pp, pr])
    say(f"  {'Domain-name model, 2026':28s} AUC {auc:.3f}   ({len(pp):,} urlscan.io 2026 phishing sites vs "
        f"{len(pr):,} real 2026 sites it never saw)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recalc", action="store_true", help="also recalculate live on this PC (1-2 minutes)")
    a = ap.parse_args()
    show_saved()
    if a.recalc:
        import warnings
        warnings.filterwarnings("ignore")
        say("")
        say("=" * 100)
        say("RECALCULATED NOW on this PC (read-only)")
        say("=" * 100)
        recalc_text("Email (phishing_email)", "phishing_email.joblib", "phishing_email_real.tsv", "phishing")
        recalc_text("SMS (phishing_sms)", "phishing_sms.joblib", "phishing_sms_clean_v2.tsv", "phishing")
        recalc_text("Fallback text model", "phishing_pipeline.joblib", "phishing_text_sample.tsv", "spam")
        recalc_links()
    with open(os.path.join(HERE, "auc_check.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(OUT) + "\n")
    print(f"\nSaved to backend{os.sep}auc_check.txt")


if __name__ == "__main__":
    main()
