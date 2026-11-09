"""
Watcher 5 (6 Nov) -- this PC's network connections, every 30 seconds (Module 6: suspicious network traffic).

ASKS FIRST: it starts OFF and runs only after the owner switches it on in Settings (that switch is the permission).
Each round it takes the same read-only look as the "PC Network" page (app/services/pc_network.py): the open ports and
live connections the operating system lists. Nothing is captured from inside the connections, nothing is closed,
blocked or changed, and command lines are never read.

Only HIGH findings become an automatic finding (the page shows the medium / low ones):
  * a database / remote-desktop / old clear-text service open to the network (a risky setting: score 78, high),
  * any traffic on a backdoor port (4444, 31337, 1337 ...)                                  (score 88, critical),
  * a program from Temp / Downloads waiting for connections                                 (score 88, critical),
  * a connection to an address one of your scans already marked as dangerous                (score 88, critical).
Each finding carries the concrete fix for its kind (pc_network.advice). Alerts follow the usual automatic limits
(by default only critical ones are sent).
The same finding is reported once, then again only after REPEAT_HOURS (open ports) or a day (connections), so a
setting you already know about does not alert every 30 seconds.
"""
from datetime import datetime, timedelta, timezone

from app.automation.engine import Watcher, get_state, save_and_alert, update_state
from app.detectors.base import build_result
from app.services import pc_network

REPEAT_HOURS_PORT = 24 * 7        # an open port is a setting: remind once a week
REPEAT_HOURS_CONNECTION = 24      # a connection is an event: again after a day


def _flagged_ips() -> set[str]:
    from app.automation.engine import owner_user_id
    from app.db.database import SessionLocal
    from app.db.models import IOC
    db = SessionLocal()
    try:
        uid = owner_user_id(db)
        if not uid:
            return set()
        return {v for (v,) in db.query(IOC.value).filter(IOC.user_id == uid, IOC.ioc_type == "ip").limit(5000)}
    finally:
        db.close()


def finding_result(f: dict) -> dict:
    # (7 Nov) an open service is a risky SETTING (high, 78: on the dashboard; it alerts only if Settings says "same
    # level as my scans"); a backdoor port, a program from Temp / Downloads or a flagged address can be an attack in
    # progress (critical, 88: alerts). The advice is the concrete fix for this kind of finding (pc_network.advice),
    # not the generic incident steps ("block the source", "escalate") that do not fit an open port.
    setting = pc_network.finding_kind(f) == "exposed"
    score = 78 if setting else 88
    ind = {"label": f["title"], "description": f["why"], "severity": "high" if setting else "critical",
           "weight": score, "triggered": True}
    result = build_result(indicators=[{**ind, "id": "IND_net_live"}], base_score=score, confidence=85,
                          engine_name="CyberGuard live network monitor (operating-system connection list + "
                                      "CyberGuard network rules)",
                          threat_type="Risky network setting on this PC" if setting
                          else "Suspicious network activity on this PC",
                          explanation=f["why"])
    result["recommendations"] = pc_network.advice(f)
    result["liveNetwork"] = {k: f.get(k) for k in ("title", "port", "remote", "program", "pid")}
    return result


class NetworkWatcher(Watcher):
    name = "network"
    title = "Network connections of this PC"
    what = ("Every 30 seconds: this computer's open ports and live connections, judged by CyberGuard's network "
            "rules (backdoor ports, databases or remote desktop open to the Wi-Fi, programs from Temp / Downloads, "
            "addresses your scans flagged).")
    modules = ["cyber-threat"]
    technology = "Operating-system connection list (psutil, read-only) + CyberGuard network rules"
    interval_seconds = 30
    default_enabled = False
    permission = ("Read this computer's list of open ports and network connections (addresses, ports and program "
                  "names) every 30 seconds. Nothing inside the connections is read, nothing is blocked or saved "
                  "except real findings.")

    def configured(self) -> tuple[bool, str]:
        if pc_network._psutil() is None:
            return False, pc_network.install_hint()
        return True, ""

    def check(self) -> dict:
        snap = pc_network.snapshot(_flagged_ips())
        if not snap.get("available"):
            raise RuntimeError(snap.get("reason", "The connection list is not available."))
        now = datetime.now(timezone.utc)
        reported = get_state(self.name).get("reported", {})
        threats, finding = 0, None
        for f in snap["findings"]:
            if f["severity"] != "high":
                continue
            # a connection: both of its ends are listed (one sometimes without a program name) -> one finding
            sig = "|".join(str(f.get(k, "")) for k in (("title", "port", "remote") if f.get("remote")
                                                        else ("title", "program", "port")))
            last = reported.get(sig)
            hours = REPEAT_HOURS_CONNECTION if f.get("remote") else REPEAT_HOURS_PORT
            if last and now - datetime.fromisoformat(last) < timedelta(hours=hours):
                continue
            result = finding_result(f)
            self.record(f["title"], result["riskScore"], result["classification"])
            scan_id = save_and_alert(module_id="cyber-threat", subtopic_id="network-traffic",
                                     subtopic_title="Automatic network monitoring (this PC)", result=result,
                                     target=f["title"], target_type="network", source="network",
                                     metadata={"program": f.get("program"), "port": f.get("port"),
                                               "remote": f.get("remote")})
            reported[sig] = now.isoformat()
            if scan_id:
                threats += 1
                finding = f["title"]
        if len(reported) > 1000:
            reported = dict(sorted(reported.items(), key=lambda kv: kv[1])[-1000:])
        update_state(self.name, reported=reported)
        s = snap["summary"]
        return {"checked": s["connections"] + s["openPorts"], "threats": threats, "finding": finding,
                "note": f"{s['openPorts']} open port(s) ({s['openToNetwork']} reachable from the network), "
                        f"{s['connections']} connection(s); {s['high']} high, {s['medium']} medium finding(s)"}
