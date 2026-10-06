"""Ingestion pipeline: CSV -> normalise -> validate -> store -> correlate -> alert -> classify.

Mirrors the workflow: Feed -> Collection -> Normalisation -> Validation -> IOC extraction ->
Classification -> Scoring -> ATT&CK mapping -> Database -> Correlation -> Dashboard.
"""
import csv
import json
import random
from datetime import datetime, timedelta

from backend.config import REFERENCE_DATE
from backend.models.database import create_schema
from backend.services.alert_engine import correlate_alerts, generate_threat_alert
from backend.services.awareness_service import load_json
from backend.services.correlation_engine import cluster_sizes, correlate_threats
from backend.services.ioc_validator import validate_indicator
from backend.services.knowledge import CATEGORIES, STATUSES
from backend.services.risk_engine import SEVERITIES, SOURCES, classify_risk
from backend.services.threat_service import classify_entity_stage

ALERT_STATUS_FROM_THREAT = {"NEW": "NEW", "UNDER_REVIEW": "INVESTIGATING", "MONITORING": "MONITORING", "CLOSED": "RESOLVED"}


def _bool(v):
    return 1 if str(v).strip().lower() in ("1", "true", "yes") else 0


def normalize_row(row: dict) -> tuple[dict | None, str | None]:
    """Normalise & validate one CSV row. Returns (clean_row, None) or (None, reason)."""
    v = validate_indicator(row.get("indicator_value", ""), row.get("indicator_type", "").upper())
    if not v["valid"]:
        return None, "invalid indicator: " + " ".join(v["validation_notes"])
    cat = row.get("threat_category", "").upper().strip()
    if cat not in CATEGORIES:
        return None, f"unknown category {cat!r}"
    status = row.get("status", "").upper().strip()
    if status not in STATUSES:
        return None, f"unknown status {status!r}"
    if row.get("source_name") not in SOURCES:
        return None, "unknown source"
    clean = dict(row)
    clean.update(threat_category=cat, status=status, indicator_type=v["indicator_type"],
                 normalized_value=v["normalized_value"],
                 confidence_score=int(row["confidence_score"]), risk_score=int(row["risk_score"]),
                 observation_count=int(row.get("observation_count") or 1),
                 related_alert_count=int(row.get("related_alert_count") or 0))
    clean["severity"] = classify_risk(clean["risk_score"])
    return clean, None


def load_dataset(conn, config, reset: bool = True) -> dict:
    """Build the whole database from the CSV files and awareness JSON. Returns a summary."""
    create_schema(conn, reset=reset)
    summary = {"rows_read": 0, "rows_loaded": 0, "rows_rejected": 0, "rejections": []}

    # --- vulnerabilities
    with open(config.VULNS_CSV, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            conn.execute(
                "INSERT INTO vulnerabilities (cve_id, product_category, severity, cvss_score, published_date, patch_available, "
                "exploitation_status_demo, asset_criticality, exposure, business_impact, priority_score, priority_label, description) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["cve_id"], r["product_category"], r["severity"], float(r["cvss_score"]), r["published_date"],
                 _bool(r["patch_available"]), r["exploitation_status_demo"], int(r["asset_criticality"]), r["exposure"],
                 int(r["business_impact"]), float(r["priority_score"]), r["priority_label"], r["description"]))
    vprio = {r[0]: r[1] for r in conn.execute("SELECT cve_id, priority_score FROM vulnerabilities")}

    # --- sources
    src_ids = {}
    for i, (name, rel) in enumerate(SOURCES.items(), 1):
        src_ids[name] = f"SRC-{i:02d}"
        conn.execute("INSERT INTO sources VALUES (?,?,?)", (src_ids[name], name, rel))

    # --- threats / indicators / ATT&CK
    clean_rows = []
    with open(config.THREATS_CSV, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            summary["rows_read"] += 1
            clean, why = normalize_row(row)
            if why:
                summary["rows_rejected"] += 1
                summary["rejections"].append(f"{row.get('threat_id')}: {why}")
                continue
            clean_rows.append(clean)
            conn.execute(
                "INSERT INTO threats (threat_id, threat_name, category, description, severity, base_severity, risk_score, confidence_score, "
                "status, first_seen, last_seen, record_timestamp, source_id, campaign_id, observation_count, related_alert_count, region, "
                "cve_id, entity_stage, incident_confirmed, synthetic_label) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (clean["threat_id"], clean["threat_name"], clean["threat_category"], clean["description"], clean["severity"],
                 clean["base_severity"], clean["risk_score"], clean["confidence_score"], clean["status"], clean["first_seen"],
                 clean["last_seen"], clean["timestamp"], src_ids[clean["source_name"]], clean["campaign_id"],
                 clean["observation_count"], clean["related_alert_count"], clean["country_or_region_optional"],
                 clean["cve_id_optional"] or None, "INDICATOR", _bool(clean.get("incident_confirmed")), clean["synthetic_label"]))
            conn.execute("INSERT INTO indicators (threat_id, indicator_type, indicator_value, normalized_value, first_seen, last_seen) "
                         "VALUES (?,?,?,?,?,?)", (clean["threat_id"], clean["indicator_type"], clean["indicator_value"],
                                                  clean["normalized_value"], clean["first_seen"], clean["last_seen"]))
            if clean["mitre_tactic_optional"]:
                conn.execute("INSERT INTO attack_mappings (threat_id, tactic, technique, technique_id_optional, rationale) VALUES (?,?,?,?,?)",
                             (clean["threat_id"], clean["mitre_tactic_optional"], clean["mitre_technique_optional"],
                              clean["mitre_technique_id_optional"], "Mapped only because category, indicator type and confidence provided enough context."))
            summary["rows_loaded"] += 1
    summary["rejections"] = summary["rejections"][:20]

    # --- correlation
    t_dicts = [{"threat_id": c["threat_id"], "category": c["threat_category"], "campaign_id": c["campaign_id"],
                "first_seen": c["first_seen"], "indicator_type": c["indicator_type"], "risk_score": c["risk_score"]} for c in clean_rows]
    clusters = correlate_threats(t_dicts)
    sizes = cluster_sizes(clusters)
    summary["clusters"] = len(clusters)

    # --- alerts (raw -> correlated)
    raw = []
    for c in clean_rows:
        t = {"threat_id": c["threat_id"], "status": c["status"], "risk_score": c["risk_score"], "confidence_score": c["confidence_score"],
             "severity": c["severity"], "observation_count": c["observation_count"], "record_timestamp": c["timestamp"],
             "indicator_value": c["normalized_value"]}
        vp = vprio.get(c["cve_id_optional"]) if c["cve_id_optional"] else None
        raw += generate_threat_alert(t, sizes.get(c["threat_id"], 1), vp)
    alerts = correlate_alerts(raw)
    summary["raw_alerts"], summary["correlated_alerts"] = len(raw), len(alerts)
    status_of = {c["threat_id"]: c["status"] for c in clean_rows}
    open_alert = set()
    for n, a in enumerate(alerts, 1):
        st = ALERT_STATUS_FROM_THREAT.get(status_of[a["threat_id"]], "NEW")
        if st in ("NEW", "INVESTIGATING", "MONITORING"):
            open_alert.add(a["threat_id"])
        conn.execute("INSERT INTO alerts (alert_id, threat_id, severity, risk_score, confidence_score, alert_type, description, status, "
                     "observation_count, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (f"ALR-{n:06d}", a["threat_id"], a["severity"], a["risk_score"], a["confidence_score"], a["alert_type"],
                      a["description"], st, a["observation_count"], a["timestamp"]))

    # --- entity stage (observation / indicator / alert / threat / incident)
    for c in clean_rows:
        stage = classify_entity_stage({"incident_confirmed": _bool(c.get("incident_confirmed")), "status": c["status"],
                                       "confidence_score": c["confidence_score"], "risk_score": c["risk_score"]},
                                      sizes.get(c["threat_id"], 1), c["threat_id"] in open_alert)
        conn.execute("UPDATE threats SET entity_stage = ? WHERE threat_id = ?", (stage, c["threat_id"]))

    _seed_demo_notes(conn)
    _load_awareness(conn, config)
    conn.commit()
    return summary


def _seed_demo_notes(conn):
    notes = {"THR-2026-001": "Indicator appears in multiple synthetic phishing observations.",
             "THR-2026-002": "Related infrastructure for the demo phishing campaign (synthetic). Do not connect to it."}
    for tid, text in notes.items():
        if conn.execute("SELECT 1 FROM threats WHERE threat_id = ?", (tid,)).fetchone():
            conn.execute("INSERT INTO analyst_notes (threat_id, note, author, created_at) VALUES (?,?,?,?)",
                         (tid, text, "demo-analyst", "2026-09-30T10:00:00"))


def _load_awareness(conn, config):
    for m in load_json(config.AWARENESS_DIR, "modules.json"):
        conn.execute("INSERT INTO awareness_modules VALUES (?,?,?)", (m["module_id"], m["title"], m["quiz_category"]))
    # Seed synthetic anonymous quiz results so the executive 'awareness trend' has data to show.
    rng = random.Random(11)
    cats = sorted({q["category"] for q in load_json(config.AWARENESS_DIR, "quiz_questions.json")})
    base = {c: rng.randint(55, 85) for c in cats}
    base["Phishing"], base["Social Engineering"] = 58, 62
    for month in range(5, 10):
        for _ in range(12):
            scores = {c: max(0, min(100, int(rng.gauss(base[c] + (month - 5) * 2, 12)))) for c in cats}
            overall = round(sum(scores.values()) / len(scores))
            day = datetime(2026, month, rng.randint(1, 28), rng.randint(8, 18))
            conn.execute("INSERT INTO quiz_results (anonymous_user_id, overall_score, category_scores, created_at) VALUES (?,?,?,?)",
                         (f"anon-{rng.randrange(10**6):06d}", overall, json.dumps(scores), day.isoformat()))
