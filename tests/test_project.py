"""Automated tests T01-T40 (see docs/TEST_REPORT.md for the scenario table)."""
import json

from backend.models.database import create_schema, get_connection
from backend.services import awareness_service as aw
from backend.services.alert_engine import correlate_alerts, generate_threat_alert
from backend.services.attack_mapper import map_to_attack
from backend.services.correlation_engine import correlate_threats
from backend.services.enrichment_engine import enrich_indicator
from backend.services.ioc_validator import defang, refang, validate_indicator
from backend.services.risk_engine import (calculate_confidence, calculate_threat_risk, classify_risk,
                                          interpret_risk_confidence, source_reliability_score)
from backend.services.threat_service import dashboard_stats
from backend.services.vulnerability_service import calculate_vulnerability_priority
from backend.config import Config
from tests.conftest import ADMIN, ANALYST, hdr, make_app

NEW_THREAT = {"threat_name": "Test Threat", "category": "PHISHING", "indicator_type": "DOMAIN",
              "indicator_value": "unit-test-lure.example.com", "source_name": "Security Vendor",
              "base_severity": "HIGH", "confidence_score": 80}


# ---- IOC validation
def test_t01_valid_ipv4():
    r = validate_indicator("198.51.100.25")
    assert r["valid"] and r["indicator_type"] == "IP" and r["format_detail"] == "IPv4"

def test_t02_invalid_ipv4():
    assert not validate_indicator("256.10.10.1")["valid"]
    assert not validate_indicator("1.2.3")["valid"]

def test_t03_valid_ipv6():
    r = validate_indicator("2001:DB8:0:0::1")
    assert r["valid"] and r["format_detail"] == "IPv6" and r["normalized_value"] == "2001:db8::1"

def test_t04_valid_domain():
    r = validate_indicator("Login-Check.INVALID.")
    assert r["valid"] and r["indicator_type"] == "DOMAIN" and r["normalized_value"] == "login-check.invalid"

def test_t05_invalid_domain():
    assert not validate_indicator("-bad-.example.com")["valid"]
    assert not validate_indicator("localhost")["valid"]

def test_t06_valid_url():
    r = validate_indicator("HTTPS://Example.COM/path?a=1#frag")
    assert r["valid"] and r["indicator_type"] == "URL" and r["normalized_value"] == "https://example.com/path?a=1"
    assert not validate_indicator("ftp://example.com/x")["valid"]
    assert not validate_indicator("https://user:pw@example.com/")["valid"]

def test_t07_valid_md5():
    assert validate_indicator("d41d8cd98f00b204e9800998ecf8427e")["format_detail"] == "MD5"

def test_t08_valid_sha1():
    assert validate_indicator("da39a3ee5e6b4b0d3255bfef95601890afd80709")["format_detail"] == "SHA1"

def test_t09_valid_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = validate_indicator(h.upper())
    assert r["valid"] and r["format_detail"] == "SHA256" and r["normalized_value"] == h
    assert not validate_indicator("g" * 64)["valid"]

def test_t10_valid_cve():
    r = validate_indicator("cve-2099-10001")
    assert r["valid"] and r["indicator_type"] == "CVE_ID" and r["normalized_value"] == "CVE-2099-10001"

def test_t11_invalid_cve():
    assert not validate_indicator("CVE-99-1")["valid"]


# ---- threat creation, scoring
def test_t12_threat_creation(client):
    r = client.post("/api/threats", json=NEW_THREAT, headers=hdr(ADMIN))
    assert r.status_code == 201
    d = r.get_json()
    assert d["threat_id"].startswith("THR-2026-") and d["entity_stage"] in ("INDICATOR", "ALERT", "OBSERVATION")

def test_t13_risk_calculation():
    base = {"base_severity": "HIGH", "confidence_score": 85, "last_seen": "2026-10-01",
            "observation_count": 8, "source_reliability": "B"}
    r = calculate_threat_risk(base, context_score=50)
    assert r["risk_score"] == 78 and r["classification"] == "HIGH"
    assert abs(sum(r["weights"].values()) - 1.0) < 1e-9
    assert [classify_risk(x) for x in (0, 21, 41, 61, 81)] == ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    stale = dict(base, last_seen="2026-01-01")
    assert calculate_threat_risk(stale, context_score=50)["risk_score"] < 78

def test_t14_confidence_calculation():
    strong = calculate_confidence("A", 4, 0, True, 100)["confidence_score"]
    weak = calculate_confidence("D", 1, 300, False, 20)["confidence_score"]
    assert 0 <= weak < strong <= 100
    assert "weak" in interpret_risk_confidence(90, 25)
    assert "High-confidence" in interpret_risk_confidence(70, 95)

def test_t15_source_reliability():
    assert [source_reliability_score(x) for x in "ABCD"] == [100, 80, 60, 30]
    assert source_reliability_score("Z") == 30


# ---- enrichment / search
def test_t16_ioc_enrichment(conn):
    r = enrich_indicator(conn, "198.51.100.25")
    assert r["known_in_dataset"] and r["risk_score"] == 78 and r["confidence_score"] == 85
    assert r["related_indicators"] and "no network connection" in r["lookup_note"]
    unknown = enrich_indicator(conn, "203.0.113.250")
    assert "NOT mean" in unknown["interpretation"] or unknown["known_in_dataset"]

def test_t17_indicator_search(client):
    r = client.get("/api/indicators/search?q=login-check[.]invalid")  # defanged input accepted
    d = r.get_json()
    assert r.status_code == 200 and d["known_in_dataset"] and d["indicator_type"] == "DOMAIN" and d["status"] == "MONITORING"
    assert client.get("/api/indicators/search?q=").status_code == 400


# ---- correlation / alerts
def test_t18_threat_correlation():
    items = [{"threat_id": f"T{i}", "category": "PHISHING", "campaign_id": "C1" if i < 3 else None,
              "first_seen": "2026-09-01", "indicator_type": "DOMAIN", "risk_score": 50 + i} for i in range(5)]
    cl = correlate_threats(items)
    strong = [c for c in cl if c["cluster_id"] == "C1"][0]
    assert strong["size"] == 3 and "not guaranteed attribution" in strong["note"]

def test_t19_duplicate_observation(client):
    first = client.post("/api/threats", json=NEW_THREAT, headers=hdr(ADMIN))
    second = client.post("/api/threats", json=dict(NEW_THREAT, indicator_value="UNIT-TEST-LURE.example.com"), headers=hdr(ADMIN))
    assert first.status_code == 201 and second.status_code == 200
    assert second.get_json()["threat_id"] == first.get_json()["threat_id"]
    assert second.get_json()["observation_count"] == 2

def test_t20_alert_generation():
    t = {"threat_id": "THR-X", "status": "NEW", "risk_score": 85, "confidence_score": 80, "severity": "CRITICAL",
         "observation_count": 60, "indicator_value": "a.example.com", "record_timestamp": "2026-10-01T10:00:00"}
    types = {a["alert_type"] for a in generate_threat_alert(t, cluster_size=5)}
    assert {"RISK_THRESHOLD", "REPEATED_OBSERVATIONS", "CORRELATED_INDICATORS"} <= types
    assert generate_threat_alert(dict(t, status="FALSE_POSITIVE")) == []
    low_conf = generate_threat_alert(dict(t, confidence_score=20, observation_count=1))
    assert low_conf[0]["alert_type"] == "HIGH_RISK_LOW_CONFIDENCE"

def test_t21_alert_correlation():
    raw = [{"threat_id": "T", "timestamp": f"2026-10-01T10:00:{i % 60:02d}", "alert_type": "REPEATED_OBSERVATIONS",
            "severity": "HIGH", "risk_score": 70, "confidence_score": 80, "indicator_value": "x.example.com",
            "description": "seen", "observation_count": 1} for i in range(100)]
    merged = correlate_alerts(raw)
    assert len(merged) == 1 and merged[0]["observation_count"] == 100 and merged[0]["raw_alert_count"] == 100
    far = raw[:1] + [dict(raw[0], timestamp="2026-10-01T12:00:00")]
    assert len(correlate_alerts(far)) == 2

def test_t22_alert_status_update(client):
    alert = client.get("/api/alerts").get_json()["items"][0]
    url = f"/api/alerts/{alert['alert_id']}/status"
    assert client.put(url, json={"status": "RESOLVED"}).status_code == 401
    ok = client.put(url, json={"status": "investigating"}, headers=hdr(ANALYST))
    assert ok.status_code == 200 and ok.get_json()["status"] == "INVESTIGATING"
    assert client.put(url, json={"status": "BOGUS"}, headers=hdr(ANALYST)).status_code == 400
    assert client.put("/api/alerts/ALR-999999/status", json={"status": "NEW"}, headers=hdr(ANALYST)).status_code == 404

def test_t23_analyst_notes(client):
    r = client.post("/api/threats/THR-2026-001/notes", json={"note": "Checked <script>alert(1)</script> logs"}, headers=hdr(ANALYST))
    assert r.status_code == 201 and "<" not in r.get_json()["note"]
    d = client.get("/api/threats/THR-2026-001").get_json()
    assert any("Checked" in n["note"] for n in d["notes"])
    assert client.post("/api/threats/THR-2026-001/notes", json={"note": " "}, headers=hdr(ANALYST)).status_code == 400


# ---- ATT&CK, vulnerabilities
def test_t24_attack_mapping():
    m = map_to_attack("PHISHING", "DOMAIN", 85, "MONITORING")
    assert m["tactic"] == "Initial Access" and m["technique_id"] == "T1566.002"
    assert map_to_attack("PHISHING", "DOMAIN", 30) is None            # low confidence -> no mapping
    assert map_to_attack("PHISHING", "DOMAIN", 90, "FALSE_POSITIVE") is None
    assert map_to_attack("NETWORK THREATS", "FILE_HASH", 90) is None  # no justified mapping

def test_t25_vulnerability_scoring():
    isolated = calculate_vulnerability_priority(9.8, 1, "ISOLATED_TEST", "NONE_OBSERVED", 1)
    exposed = calculate_vulnerability_priority(8.1, 5, "INTERNET_FACING", "PROOF_OF_CONCEPT_DEMO", 5)
    assert isolated["priority_label"].startswith("P4") and exposed["priority_label"].startswith("P1")
    assert exposed["priority_score"] > isolated["priority_score"]


# ---- dashboard, filters, sorting
def test_t26_dashboard_statistics(client):
    d = client.get("/api/dashboard/stats").get_json()
    c = d["cards"]
    assert c["total_threat_records"] == 400 and sum(d["by_severity"].values()) == 400
    assert c["vulnerabilities_tracked"] == 60 and sum(d["by_status"].values()) == 400
    assert client.get("/api/dashboard/trends").get_json()["labels"]

def test_t27_severity_filtering(client):
    d = client.get("/api/threats?severity=HIGH&per_page=100").get_json()
    assert d["total"] > 0 and all(i["severity"] == "HIGH" for i in d["items"])
    both = client.get("/api/threats?severity=HIGH,CRITICAL&per_page=100").get_json()
    assert {i["severity"] for i in both["items"]} <= {"HIGH", "CRITICAL"}

def test_t28_category_filtering(client):
    d = client.get("/api/threats?category=PHISHING&min_risk=50&per_page=100").get_json()
    assert d["total"] > 0 and all(i["category"] == "PHISHING" and i["risk_score"] >= 50 for i in d["items"])

def test_t29_threat_sorting(client):
    risk = [i["risk_score"] for i in client.get("/api/threats?sort=risk&per_page=50").get_json()["items"]]
    assert risk == sorted(risk, reverse=True)
    seen = [i["last_seen"] for i in client.get("/api/threats?sort=newest&per_page=50").get_json()["items"]]
    assert seen == sorted(seen, reverse=True)
    assert client.get("/api/threats?sort=evil").status_code == 400


# ---- awareness
def test_t30_awareness_module_retrieval(client):
    mods = client.get("/api/awareness/modules").get_json()
    assert len(mods) == 15 and all(m["warning_signs"] and m["safe_practices"] for m in mods)
    qs = client.get("/api/quiz").get_json()
    assert len(qs) >= 30 and all("answer" not in q for q in qs)       # answers never sent to the browser

def test_t31_quiz_scoring():
    qs = aw.load_json(Config.AWARENESS_DIR, "quiz_questions.json")
    perfect = aw.score_quiz({q["id"]: q["answer"] for q in qs}, qs)
    assert perfect["overall_score"] == 100 and perfect["level"] == "Strong Awareness"
    assert aw.score_quiz({}, qs)["overall_score"] == 0
    assert [aw.score_level(x) for x in (40, 41, 61, 81)] == ["Needs Improvement", "Basic Awareness", "Good Awareness", "Strong Awareness"]

def test_t32_learning_recommendation():
    mods = aw.load_json(Config.AWARENESS_DIR, "modules.json")
    recs = {r["category"]: r["recommendation"] for r in aw.generate_learning_recommendations(
        {"Phishing": 40, "Social Engineering": 55, "Passwords": 90}, mods)}
    assert recs["Phishing"].startswith("Complete") and recs["Social Engineering"].startswith("Review")
    assert recs["Passwords"] == "No immediate module required."


# ---- robustness
def test_t33_empty_dataset(csv_dir, tmp_path):
    path = tmp_path / "empty.db"
    c = get_connection(str(path)); create_schema(c); c.close()
    client = make_app(csv_dir, path).test_client()
    assert client.get("/api/dashboard/stats").get_json()["cards"]["total_threat_records"] == 0
    assert client.get("/api/threats").get_json()["items"] == []
    assert client.get("/api/dashboard/executive").status_code == 200
    assert client.get("/api/threats/THR-2026-001").status_code == 404

def test_t34_api_validation(client):
    assert client.post("/api/threats", json=NEW_THREAT).status_code == 401                       # no key
    assert client.post("/api/threats", json=NEW_THREAT, headers=hdr("wrong")).status_code == 401
    assert client.post("/api/threats", json=NEW_THREAT, headers=hdr(ANALYST)).status_code == 403  # RBAC
    bad = client.post("/api/threats", json=dict(NEW_THREAT, indicator_value="999.1.1.1", indicator_type="IP"), headers=hdr(ADMIN))
    assert bad.status_code == 400
    assert client.post("/api/threats", data="not json", headers=hdr(ADMIN)).status_code == 400
    assert client.post("/api/quiz/submit", json={"answers": {"Q01": "Z"}}).status_code == 400
    assert client.get("/api/threats?min_risk=abc").status_code == 400

def test_t35_database_persistence(csv_dir, tmp_path):
    path = tmp_path / "persist.db"
    first = make_app(csv_dir, path).test_client()
    tid = first.post("/api/threats", json=NEW_THREAT, headers=hdr(ADMIN)).get_json()["threat_id"]
    second = make_app(csv_dir, path).test_client()                    # brand-new app, same file
    assert second.get(f"/api/threats/{tid}").status_code == 200


# ---- extra safety/behaviour tests
def test_t36_defang_and_refang():
    assert defang("https://login-check.invalid/x", "URL") == "hxxps://login-check[.]invalid/x"
    assert refang("hxxps://a[.]example[.]com") == "https://a.example.com"
    assert defang("198.51.100.25", "IP") == "198.51.100.25"

def test_t37_demo_scenario(client):
    d = client.get("/api/threats/THR-2026-001").get_json()
    assert (d["indicator_value"], d["category"], d["severity"], d["risk_score"], d["confidence_score"], d["status"]) == \
        ("login-check.invalid", "PHISHING", "HIGH", 78, 85, "MONITORING")
    assert any(r["indicator_value"] == "198.51.100.25" for r in d["related_indicators"])
    assert d["recommended_actions"] and d["attack_mappings"][0]["technique_id_optional"] == "T1566.002"

def test_t38_entity_stages_not_all_incidents(client):
    stages = client.get("/api/dashboard/stats").get_json()["by_entity_stage"]
    assert stages["INCIDENT"] < stages["INDICATOR"] + stages["ALERT"] + stages["THREAT"]
    assert set(stages) == {"OBSERVATION", "INDICATOR", "ALERT", "THREAT", "INCIDENT"}

def test_t39_security_headers_and_no_key_leak(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert ADMIN not in r.get_data(as_text=True)

def test_t40_quiz_submit_roundtrip(client):
    qs = client.get("/api/quiz").get_json()
    r = client.post("/api/quiz/submit", json={"answers": {q["id"]: "A" for q in qs}})
    d = r.get_json()
    assert r.status_code == 200 and 0 <= d["overall_score"] <= 100 and d["recommendations"] and "Educational" in d["disclaimer"]
