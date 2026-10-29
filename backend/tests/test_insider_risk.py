"""Insider Risk (UEBA): data exfiltration + abnormal activity + insider threat as ONE engine (added 26 Oct).

The events here are a small synthetic company (tests only); accuracy figures come from the real CERT r4.2 data
(app/ml/training/train_insider_risk.py)."""
import bz2
import csv
import io
import json
import os
import random
import tarfile
from datetime import datetime, timedelta

import numpy as np
import pytest

from app.detectors import cyber_threat as C
from app.detectors import insider_risk as R
from app.detectors import insider_signals as S

START = datetime(2010, 3, 1)
UNIFIED = ["date", "user", "pc", "activity", "details", "to", "cc", "bcc", "from", "size", "attachments"]


def company(n_users=25, days=40, insider="U007", insider_from=30, seed=1):
    """Ordinary office days for everyone; from day `insider_from` the insider copies files to a new USB drive at night,
    visits WikiLeaks and e-mails files to a gmail address."""
    rnd = random.Random(seed)
    ev = []
    for d in range(days):
        day = START + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for u in range(n_users):
            user, pc = f"U{u:03d}", f"PC-{u:03d}"
            t_in = day + timedelta(hours=8, minutes=rnd.randint(0, 40))
            t_out = day + timedelta(hours=17, minutes=rnd.randint(0, 40))
            ev.append((t_in, user, pc, "logon", {}))
            for k in range(rnd.randint(3, 6)):
                ev.append((t_in + timedelta(minutes=30 + 20 * k), user, pc, "web",
                           {"url": rnd.choice(["http://news.example.com/a", "http://intranet.dtaa.com/x",
                                               "http://weather.example.org/"])}))
            ev.append((t_in + timedelta(hours=2), user, pc, "email",
                       {"to": f"u{(u + 1) % n_users:03d}@dtaa.com", "from": f"{user.lower()}@dtaa.com", "size": 20000,
                        "attachments": 0}))
            ev.append((t_out, user, pc, "logoff", {}))
            if user == insider and d >= insider_from:
                night = day + timedelta(hours=23, minutes=5)
                ev += [(night - timedelta(minutes=10), user, "PC-999", "logon", {}),
                       (night, user, "PC-999", "usb_connect", {}),
                       (night + timedelta(minutes=2), user, "PC-999", "file", {"filename": "R:\\payroll_2010.xlsx"}),
                       (night + timedelta(minutes=3), user, "PC-999", "file", {"filename": "R:\\customers.docx"}),
                       (night + timedelta(minutes=5), user, "PC-999", "web", {"url": "http://wikileaks.org/submit"}),
                       (night + timedelta(minutes=8), user, "PC-999", "email",
                        {"to": "me.private@gmail.com", "from": f"{user.lower()}@dtaa.com", "size": 900000,
                         "attachments": 2})]
    return sorted(ev, key=lambda e: e[0])


def unified_csv(ev):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(UNIFIED)
    for t, user, pc, kind, a in ev:
        act = {"file": "file_copy"}.get(kind, kind)
        w.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), user, pc, act, a.get("url") or a.get("filename") or "",
                    a.get("to", ""), "", "", a.get("from", ""), a.get("size", ""), a.get("attachments", "")])
    return out.getvalue()


# ---------------------------------------------------------------------------------------------- shared signal rules
def test_site_categories_match_whole_domains_only():
    cat = S.site_category
    assert cat("wikileaks.org") == "leak" and cat("www.dropbox.com") == "cloud" and cat("box.com") == "cloud"
    assert cat("inbox.com") == "" and cat("redbox.com") == ""                  # NOT box.com
    assert cat("lifehacker.com") == "" and cat("cracked.com") == ""            # NOT hacking sites
    assert cat("www.refog.com") == "spyware" and cat("best-spy-soft.com") == "spyware"
    assert cat("monster.com") == "job" and cat("jobs.acme.com") == "job" and cat("linkedin.com") == ""
    assert S.domain_of("HTTPS://www.WikiLeaks.org:443/x?y") == "wikileaks.org"


def test_personal_mail_times_and_file_kinds():
    assert S.is_personal_address("A.B@Gmail.com") and not S.is_personal_address("boss@dtaa.com")
    assert S.parse_time("01/02/2010 07:01:00") == datetime(2010, 1, 2, 7, 1)
    assert S.parse_time("2026-10-10T03:00:00Z") == datetime(2026, 10, 10, 3, 0)
    assert S.parse_time("2026-10-10 03:00:00+05:30") == datetime(2026, 10, 10, 3, 0)
    assert S.parse_time("yesterday") is None
    assert S.after_hours(datetime(2026, 10, 10, 3)) and not S.after_hours(datetime(2026, 10, 12, 10))
    assert S.file_kind("a.XLSX") == "doc" and S.file_kind("tool.exe") == "exe" and S.file_kind("x.7z") == "zip"


# ------------------------------------------------------------------------------------------------- reading the log
def test_unified_activity_log_is_read_into_user_days():
    p = R.parse_activity(unified_csv(company()))
    ud = p["ud"].set_index(["user", "date"])
    assert p["format"].startswith("user activity log") and p["events"] > 0
    assert p["company"] == "dtaa.com" and p["skipped"] == 0
    night = ud.loc[("U007", "2010-04-01")]                # day 31: the insider's night session
    assert night["usb_n"] == 1 and night["usb_after"] == 1 and night["file_after"] == 2 and night["file_doc"] == 2
    assert night["web_leak"] == 1 and night["email_personal_attach"] == 1 and night["email_ext"] == 1
    assert set(night["pcs"].split(";")) == {"PC-007", "PC-999"}
    normal = ud.loc[("U003", "2010-04-01")]
    assert normal["usb_n"] == 0 and normal["email_ext"] == 0 and normal["pcs"] == "PC-003"


def test_pcs_come_only_from_logons_and_usb_like_training():
    txt = ("date,user,pc,activity,details\n2026-10-12 10:00:00,ravi,PC-1,logon,\n"
           "2026-10-12 10:05:00,ravi,PC-2,web,http://x.com/\n2026-10-12 10:06:00,ravi,PC-3,email,a@b.com\n")
    ud = R.parse_activity(txt)["ud"]
    assert ud.loc[0, "pcs"] == "PC-1" and ud.loc[0, "first_min"] == 600


def test_cert_http_layout_and_things_that_are_not_activity_logs():
    http = ("id,date,user,pc,url,content\n{A1},01/04/2010 07:12:00,ACM2278,PC-6377,http://monster.com/jobs,a b c\n"
            "{A2},01/04/2010 07:15:00,ACM2278,PC-6377,http://wikileaks.org/,some, commas, here\n")
    p = R.parse_activity(http)
    assert p["format"].startswith("web proxy log") and p["ud"].loc[0, "web_job"] == 1 and p["ud"].loc[0, "web_leak"] == 1
    assert R.parse_activity("Oct 10 03:11:00 srv sshd[22]: Failed password for root from 1.2.3.4") is None
    assert R.parse_activity("Src IP,Dst IP,Dst Port,Timestamp\n10.0.0.1,10.0.0.2,22,2026-10-10 10:00:00") is None
    assert R.parse_activity("date,pc,activity\n2026-10-10 10:00:00,PC-1,logon") is None        # no user column
    assert R.activity_log_kind("timestamp,username,host,action\n") == "unified"


# --------------------------------------------------------------------------------------- training == live features
def _cert_archive(tmp_path, ev):
    """The same events written the way CERT r4.2 ships them (multi-stream bzip2 like the real archive)."""
    files = {"logon.csv": [["id", "date", "user", "pc", "activity"]],
             "device.csv": [["id", "date", "user", "pc", "activity"]],
             "file.csv": [["id", "date", "user", "pc", "filename", "content"]],
             "email.csv": [["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"]],
             "http.csv": [["id", "date", "user", "pc", "url", "content"]]}
    for i, (t, user, pc, kind, a) in enumerate(ev):
        ts, rid = t.strftime("%m/%d/%Y %H:%M:%S"), f"{{X{i}}}"
        if kind in ("logon", "logoff"):
            files["logon.csv"].append([rid, ts, user, pc, kind.capitalize()])
        elif kind == "usb_connect":
            files["device.csv"].append([rid, ts, user, pc, "Connect"])
        elif kind == "file":
            files["file.csv"].append([rid, ts, user, pc, a["filename"], "some text"])
        elif kind == "email":
            files["email.csv"].append([rid, ts, user, pc, a["to"], "", "", a["from"], a["size"], a["attachments"], "hi"])
        elif kind == "web":
            files["http.csv"].append([rid, ts, user, pc, a["url"], "words"])
    users = sorted({e[1] for e in ev})
    files["LDAP/2010-03.csv"] = [["employee_name", "user_id", "email", "role", "business_unit", "functional_unit",
                                  "department", "team", "supervisor"]] + \
        [[f"N {u}", u, f"{u.lower()}@dtaa.com", "Salesman", "1", "2 - Sales", "3 - Field", "4 - East", "Boss"]
         for u in users]

    def tar_bz2(path, members):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tar:
            for name, rows in members.items():
                buf = io.StringIO()
                csv.writer(buf, lineterminator="\n").writerows(rows)
                data = buf.getvalue().encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        b = raw.getvalue()
        path.write_bytes(b"".join(bz2.compress(b[i:i + 4096]) for i in range(0, len(b), 4096)))   # multi-stream

    tar_bz2(tmp_path / "r4.2.tar.bz2", {f"r4.2/{k}": v for k, v in files.items()})
    night = [e for e in ev if e[1] == "U007" and e[2] == "PC-999"]
    detail = [[e[3], "{x}", e[0].strftime("%m/%d/%Y %H:%M:%S"), "U007", e[2]] for e in night]
    tar_bz2(tmp_path / "answers.tar.bz2", {
        "answers/insiders.csv": [["dataset", "scenario", "details", "user", "start", "end"],
                                 ["4.2", "1", "r4.2-1-U007.csv", "U007", "x", "y"]],
        "answers/r4.2-1/r4.2-1-U007.csv": detail})


def test_training_and_live_scan_compute_identical_features(tmp_path, monkeypatch):
    pd = pytest.importorskip("pandas")
    from app.ml.training import prepare_insider_data as P
    ev = company()
    _cert_archive(tmp_path, ev)
    monkeypatch.setattr(P, "DIR", str(tmp_path))
    monkeypatch.setattr(P, "ARCHIVE", str(tmp_path / "r4.2.tar.bz2"))
    monkeypatch.setattr(P, "ANSWERS", str(tmp_path / "answers.tar.bz2"))
    P.main()
    trained = pd.read_csv(tmp_path / "insider_userdays.csv.gz").fillna({"pcs": ""})
    live = R.parse_activity(unified_csv(ev))["ud"]
    m = trained.merge(live, on=["user", "date"], suffixes=("_t", "_l"), how="outer", indicator=True)
    assert (m["_merge"] == "both").all() and len(m) == len(trained)
    for c in S.FEATURES:
        assert np.allclose(m[c + "_t"], m[c + "_l"], atol=0.011), c
    assert (m["pcs_t"] == m["pcs_l"]).all()
    labels = pd.read_csv(tmp_path / "insider_labels.csv")
    assert labels.loc[0, "user"] == "U007" and labels.loc[0, "malicious_days"].split(";")[0] == "2010-03-31"


# -------------------------------------------------------------------------------------------------------- scoring
def test_own_baseline_uses_only_the_past():
    ud = R.parse_activity(unified_csv(company()))["ud"]
    X = R.add_features(ud)
    before = X[(X.user == "U007") & (X.date < "2010-03-31")]
    first = X[(X.user == "U007") & (X.date == "2010-03-31")].iloc[0]
    assert (before["usb_first"] == 0).all() and first["usb_first"] == 1 and first["new_pc"] == 1
    assert first["own_usb_after"] > 0 and first["peer_usb_after"] > 0
    assert X[X.user == "U007"].iloc[0]["history_days"] == 0                  # nothing to compare with on day 1


class _ConstModel:
    def predict_proba(self, X):
        return np.column_stack([np.full(len(X), 0.99), np.full(len(X), 0.01)])


def _fake_training(monkeypatch, ev):
    """A stand-in for the trained files: the model is silent, the cut points come from ordinary days."""
    X = R.add_features(R.parse_activity(unified_csv(ev))["ud"])
    normal = X[X.user != "U007"]
    cfg = {"model_quantiles": np.linspace(0, 1, 1001).tolist(),
           "baseline_quantiles": np.quantile(R.baseline_score(normal), np.linspace(0, 1, 1001)).tolist(),
           "review_level": 99.0, "alert_level": 99.9,
           "results": {"time_split": {"false_alert_per_day": 0.8, "caught": 35, "of": 35}}}
    monkeypatch.setattr(R, "load_trained", lambda: ({"model": _ConstModel(), "columns": R.feature_columns(True)}, cfg))


def test_the_insider_tops_the_queue_with_all_three_lenses(monkeypatch):
    ev = company()
    _fake_training(monkeypatch, ev)
    s = R.analyze_text(unified_csv(ev))
    top = s["queue"][0]
    assert s["trained"] and s["people"] == 25 and top["user"] == "U007" and top["level"] == "alert"
    assert top["date"] >= "2010-03-31" and top["score"] >= 71
    assert any("outside office hours" in r for r in top["exfiltration"])
    assert any("leak site" in r for r in top["exfiltration"])
    assert any("never used before" in r for r in top["abnormal"])
    assert top["pattern"]["name"] == "Data leak to outsiders"
    assert {"T1052.001", "T1567", "T1048", "T1078"} <= set(top["mitre"])
    assert s["lenses"]["exfiltration"] >= 1 and s["lenses"]["insider"] >= 1


def test_a_quiet_company_stays_quiet(monkeypatch):
    ev = company(insider="nobody")
    _fake_training(monkeypatch, company())
    s = R.analyze_text(unified_csv(ev))
    # by definition ~0.1% of ordinary days sit above the alert level: at most a couple, never a strong insider pattern
    assert s["alerts"] <= 2
    assert all(q["pattern"] is None or q["pattern"]["strength"] != "high" for q in s["queue"])


def test_without_a_trained_model_rules_still_report_but_stay_at_review(monkeypatch):
    monkeypatch.setattr(R, "load_trained", lambda: (None, None))
    s = R.analyze_text(unified_csv(company()))
    assert not s["trained"] and s["alerts"] == 0 and s["queue"][0]["user"] == "U007"
    assert s["queue"][0]["level"] == "review" and any("not trained" in n for n in s["notes"])


def test_small_logs_say_what_they_cannot_judge(monkeypatch):
    monkeypatch.setattr(R, "load_trained", lambda: (None, None))
    txt = "date,user,pc,activity,details\n2026-10-10 03:00:00,ravi,PC-1,logon,\n2026-10-10 03:05:00,ravi,PC-1,usb_connect,\n"
    s = R.analyze_text(txt)
    assert s["people"] == 1 and any("at least 20 people" in n for n in s["notes"])
    assert any("own normal behaviour could be learned" in n for n in s["notes"])


def test_score_levels():
    assert R.to_score(100, 99, 99.9) == 100 and R.to_score(99.9, 99, 99.9) == 71
    assert R.to_score(99.0, 99, 99.9) == 51 and R.to_score(50, 99, 99.9) == 25


# ------------------------------------------------------------------------------------------- inside the cyber engine
def test_cyber_engine_verdict_mitre_and_playbook(monkeypatch):
    from app.services import mitre, response_playbook, scan_store
    ev = company()
    _fake_training(monkeypatch, ev)
    r = C.analyze_event_text(unified_csv(ev), {}, "Insider Risk")
    assert r["riskScore"] >= 71 and r["insiderRisk"]["queue"][0]["user"] == "U007"
    assert "logAnalysis" not in r and "not recognised" not in r["explanation"]
    assert "U007" in r["explanation"] and "review queue, not proof" in r["explanation"]
    ind = [i for i in r["indicators"] if i["triggered"] and i["label"].startswith("Insider risk: U007")]
    assert ind and ind[0]["severity"] == "critical"
    ids = mitre.annotate("cyber-threat", "insider-risk", r)
    assert "T1052.001" in ids and "T1204.002" not in ids                     # no "malicious attachment" mix-up
    for t in ("T1567.002", "T1056.001"):
        assert t in mitre.CATALOGUE
    actions = response_playbook.build_actions(r, "cyber-threat", "insider-risk", unified_csv(ev)[:2000])
    titles = [a["title"] for a in actions]
    assert "Stop the data leaving" in titles and "Review U007's access" in titles
    assert "Involve HR / legal before acting" in titles and not any(t.startswith("Block IP") for t in titles)
    d = scan_store.detail_fields(r)["insiderRisk"]
    assert d["queue"][0]["user"] == "U007" and d["lenses"]["exfiltration"] >= 1 and len(d["queue"][0]["timeline"]) <= 30


def test_router_sends_activity_logs_to_the_one_insider_subtopic():
    from app.services import subtopic_router as SR
    c = SR.classify(module_id="cyber-threat", text_input=unified_csv(company(n_users=3, days=3)), url_input=None,
                    file_path=None, file_name=None, extra_field_values=None)
    assert c.subtopic_id == "insider-risk" and "header row" in c.reasons[0]
    for old in ("data-exfiltration", "abnormal-activity", "insider-threat"):
        assert old in SR.TITLES["cyber-threat"]                          # older scans keep their titles
    assert SR.DETECTORS[("cyber-threat", "insider-risk")][1] == "ok"


def test_uploading_an_activity_log(auth_client, monkeypatch):
    ev = company()
    _fake_training(monkeypatch, ev)
    files = {"file": ("activity.csv", io.BytesIO(unified_csv(ev).encode()), "text/csv")}
    r = auth_client.post("/api/analysis/scan", data={"moduleId": "cyber-threat", "subtopicId": "auto",
                                                      "subtopicTitle": "Auto-detect"}, files=files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["subtopicId"] == "insider-risk" and body["riskScore"] >= 71
    assert body["insiderRisk"]["queue"][0]["user"] == "U007"
    from app.core.config import get_settings
    folder = get_settings().UPLOAD_DIR
    assert not any(n.endswith(".csv") for n in (os.listdir(folder) if os.path.isdir(folder) else []))   # deleted


# ---------------------------------------------------------------------------------------------------- training run
def test_training_script_runs_and_saves_honest_results(tmp_path, monkeypatch):
    pd = pytest.importorskip("pandas")
    from app.ml.training import train_insider_risk as T
    rows, labels, rare = [], [], []
    rnd = np.random.RandomState(0)
    dates = pd.date_range("2010-06-01", "2010-12-31", freq="B").strftime("%Y-%m-%d")
    for u in range(60):
        user = f"U{u:03d}"
        for d in dates:
            r = {"user": user, "date": d, "pcs": f"PC-{u}", **{k: 0.0 for k in S.FEATURES}}
            r.update(logon_n=1, first_min=480 + rnd.randint(0, 30), last_min=1020, email_n=rnd.poisson(6),
                     email_ext=rnd.poisson(1), web_job=rnd.poisson(0.5), file_n=rnd.poisson(0.2))
            rows.append(r)
    scen = {"U001": ("1", "2010-07-12"), "U002": ("2", "2010-08-02"), "U003": ("3", "2010-09-06"),
            "U004": ("1", "2010-10-11"), "U005": ("2", "2010-11-01"), "U006": ("3", "2010-11-15")}
    for user, (sc, start) in scen.items():
        days = [d for d in dates if start <= d][:4]
        labels.append({"user": user, "scenario": sc, "start": start, "end": days[-1], "malicious_days": ";".join(days)})
        for r in rows:
            if r["user"] == user and r["date"] in days:
                r.update(usb_n=3, usb_after=2, logon_after=1, file_n=8, file_after=4, web_leak=1 if sc == "1" else 0,
                         web_spyware=1 if sc == "3" else 0, web_job=6 if sc == "2" else r["web_job"])
    data = tmp_path / "data"
    data.mkdir()
    pd.DataFrame(rows).to_csv(data / "insider_userdays.csv.gz", index=False)
    pd.DataFrame({"user": [f"U{u:03d}" for u in range(60)], "role": "Salesman"}).to_csv(data / "insider_users.csv",
                                                                                         index=False)
    pd.DataFrame(labels).to_csv(data / "insider_labels.csv", index=False)
    pd.DataFrame(rare or [], columns=["user", "date", "domain", "visits"]).to_csv(data / "insider_rareweb.csv.gz",
                                                                                  index=False)
    monkeypatch.setattr(T, "DATA", str(data))
    monkeypatch.setattr(T, "MODELS", str(tmp_path / "models"))
    T.main()
    meta = json.loads((tmp_path / "models" / "insider_risk.json").read_text())
    assert (tmp_path / "models" / "insider_risk.joblib").exists()
    assert len(meta["model_quantiles"]) == 1001 and len(meta["baseline_quantiles"]) == 1001
    res = meta["results"]
    assert {"time_split", "time_split_no_web", "unseen_total"} <= set(res)
    assert res["time_split"]["of"] == 3 and res["unseen_total"]["of"] == 6
