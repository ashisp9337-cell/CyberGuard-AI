"""Account-takeover fixes from the Phase 2 audit (19 Oct):
  * IOC poisoning: a risky login log must never turn the account's own normal IPs into "known bad" IPs
  * rapid bursts of failed logins on one account are a brute-force attack
  * a first login from a new country / network (for an account with history) is at least "verify"
"""
from app.detectors import account_takeover as A

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0"
HOME = "\n".join(f"2026-10-{d:02d} 09:{d:02d}:00 sign-in success user=asha ip=49.37.12.{d} country=IN ASN=AS55836 ua=\"{UA}\""
                 for d in range(1, 11))


def scan(client, sub, text):
    r = client.post("/api/analysis/scan", data={"moduleId": "credential", "subtopicId": sub, "subtopicTitle": sub,
                                                "textInput": text})
    assert r.status_code == 200, r.text
    return r.json()


def test_attack_log_does_not_poison_the_users_own_home_ips(auth_client):
    attack = HOME + "\n2026-10-18 03:11:00 sign-in success user=asha ip=91.240.118.2 country=RU ASN=AS48693"
    first = scan(auth_client, "unusual-location", attack)
    assert first["riskScore"] >= 71
    normal = HOME + "\n2026-10-18 09:15:00 sign-in success user=asha ip=49.37.12.3 country=IN ASN=AS55836"
    later = scan(auth_client, "unusual-location", normal)
    assert later["riskScore"] < 51, later["indicators"]
    assert not any(i["label"] == "Seen before in an earlier threat" for i in later["indicators"])
    iocs = auth_client.get("/api/iocs").json()
    rows = iocs.get("items", iocs) if isinstance(iocs, dict) else iocs
    ips = {r["value"] for r in rows if r["type"] == "ip"}
    assert "91.240.118.2" in ips and not any(ip.startswith("49.37.12.") for ip in ips)


def test_the_real_attacker_ip_is_still_remembered(auth_client):
    attack = "\n".join(f"2026-10-18 02:{10 + i}:00 login failed user=asha ip=45.155.205.233 country=NL" for i in range(12))
    scan(auth_client, "failed-logins", attack)
    again = scan(auth_client, "failed-logins", "2026-10-19 02:00:00 login failed user=ravi ip=45.155.205.233 country=NL")
    assert any(i["label"] == "Seen before in an earlier threat" for i in again["indicators"])


def test_rapid_burst_of_failures_is_brute_force():
    log = "\n".join(f"2026-10-18 02:{10 + i}:0{i % 10} EventID=4625 Account Name: asha Source Network Address: "
                    f"45.155.205.233 Failure Reason: Unknown user name or bad password" for i in range(12))
    r = A.analyze_event({}, "Failed logins", text=log, subtopic_id="failed-logins")
    assert r["riskScore"] >= 71 and any(i["label"] == "Rapid burst of failed logins" and i["triggered"] for i in r["indicators"])
    assert r["attackerIps"] == ["45.155.205.233"]


def test_a_few_typos_are_not_an_attack():
    log = ("2026-10-18 09:00:01 login failed user=asha ip=49.37.12.4 country=IN\n"
           "2026-10-18 09:00:20 login failed user=asha ip=49.37.12.4 country=IN\n"
           "2026-10-18 09:00:40 login success user=asha ip=49.37.12.4 country=IN")
    r = A.analyze_event({}, "Failed logins", text=log, subtopic_id="failed-logins")
    assert r["riskScore"] < 51 and r["attackerIps"] == []


def test_slow_failures_over_hours_are_not_a_burst():
    log = "\n".join(f"2026-10-18 {10 + i}:00:00 login failed user=asha ip=49.37.12.4 country=IN" for i in range(6))
    r = A.analyze_event({}, "Failed logins", text=log, subtopic_id="failed-logins")
    assert not any(i["label"] == "Rapid burst of failed logins" and i["triggered"] for i in r["indicators"])


def test_first_login_from_a_new_country_needs_verification():
    for country, ip, asn in [("NG", "196.251.80.9", "328543"), ("VN", "103.251.167.20", "131429"),
                             ("NL", "45.155.205.233", "49870")]:
        log = HOME + f"\n2026-10-18 09:12:00 sign-in success user=asha ip={ip} country={country} ASN=AS{asn}"
        r = A.analyze_event({}, "Unusual location", text=log, subtopic_id="unusual-location")
        assert r["riskScore"] >= 51, (country, r["riskScore"])
        assert any(i["label"] == "First login from a new country" for i in r["indicators"])
        assert ip in r["attackerIps"] and not any(x.startswith("49.37.12.") for x in r["attackerIps"])


def test_a_trip_abroad_is_verify_not_alert():
    log = HOME + "\n2026-10-18 13:00:00 sign-in success user=asha ip=203.0.113.50 country=SG ASN=AS9506"
    r = A.analyze_event({}, "Unusual location", text=log, subtopic_id=None)
    assert 51 <= r["riskScore"] <= 70, r["riskScore"]          # "verify the user" (e.g. OTP), not a critical alert


def test_usual_country_and_network_is_normal():
    log = HOME + "\n2026-10-18 09:15:00 sign-in success user=asha ip=49.37.12.3 country=IN ASN=AS55836"
    r = A.analyze_event({}, "Unusual location", text=log, subtopic_id="unusual-location")
    assert r["riskScore"] < 51 and r["attackerIps"] == []


def test_new_network_in_the_same_country_is_only_low_risk():
    log = HOME + "\n2026-10-18 19:15:00 sign-in success user=asha ip=106.51.22.8 country=IN ASN=AS24560"
    r = A.analyze_event({}, "Unusual location", text=log, subtopic_id="unusual-location")
    assert r["riskScore"] < 51 and any(i["label"] == "Login from a never-seen network" and i["triggered"] for i in r["indicators"])


def test_no_history_means_no_new_country_judgement():
    log = ("2026-10-01 09:00:00 sign-in success user=new ip=49.37.12.1 country=IN\n"
           "2026-10-02 09:00:00 sign-in success user=new ip=196.251.80.9 country=NG")
    assert A.new_place_logins(log) == []


def test_impossible_travel_alone_is_verify_level():
    """Bhubaneswar then Moscow 40 minutes later: at least 'verify' (51), never harmless (21 Oct check)."""
    from app.detectors.account_takeover import analyze_event
    log = ("2026-10-20 09:00:00 login success user=ashis ip=49.37.12.10 location=Bhubaneswar\n"
           "2026-10-20 09:40:00 login success user=ashis ip=95.165.30.2 location=Moscow")
    assert analyze_event({}, text=log)["riskScore"] >= 51
    trip = ("2026-10-19 09:00:00 login success user=ashis ip=49.37.12.10 location=Bhubaneswar\n"
            "2026-10-20 18:00:00 login success user=ashis ip=103.21.58.77 location=Delhi")
    assert analyze_event({}, text=trip)["riskScore"] < 51
