"""Threat data access + business logic (create, update, list, detail, stats, trends, executive summary)."""
import json
import sqlite3
from collections import Counter

from backend.config import REFERENCE_DATE
from backend.services.attack_mapper import map_to_attack
from backend.services.alert_engine import generate_threat_alert, correlate_alerts
from backend.services.ioc_validator import defang, validate_indicator
from backend.services.knowledge import CATEGORIES, CATEGORY_INFO, STATUSES, recommended_actions
from backend.services.risk_engine import (RELIABILITY_LEVELS, SEVERITIES, SOURCES, calculate_confidence,
                                          calculate_threat_risk, classify_risk, context_from_evidence,
                                          interpret_risk_confidence)
from backend.utils.dates import now_iso, parse_date
from backend.utils.text import sanitize_text

SORTS = {"newest": "t.last_seen DESC, t.threat_id", "risk": "t.risk_score DESC, t.threat_id",
         "confidence": "t.confidence_score DESC, t.threat_id", "observed": "t.observation_count DESC, t.threat_id"}
ACTIVE_STATUSES = ("NEW", "UNDER_REVIEW", "MONITORING")
STAGE_HELP = {
    "OBSERVATION": "A raw sighting with little validation. Not yet a trusted indicator.",
    "INDICATOR": "A validated artifact (IP/domain/URL/hash...) worth tracking. A match is NOT a compromise.",
    "ALERT": "An indicator that crossed a rule threshold and entered the SOC queue.",
    "THREAT": "Corroborated, higher-confidence activity (related indicators + meaningful risk).",
    "INCIDENT": "Analyst-CONFIRMED security incident. Rare - requires human confirmation.",
}


class ValidationError(ValueError):
    """Raised for bad user input (mapped to HTTP 400)."""


def classify_entity_stage(threat: dict, cluster_size: int, has_open_alert: bool) -> str:
    """OBSERVATION < INDICATOR < ALERT < THREAT < INCIDENT. Never label everything a confirmed attack."""
    if threat.get("incident_confirmed"):
        return "INCIDENT"
    if threat["status"] == "FALSE_POSITIVE":
        return "OBSERVATION"
    if threat["confidence_score"] >= 70 and cluster_size >= 2 and threat["risk_score"] >= 61:
        return "THREAT"
    if has_open_alert:
        return "ALERT"
    if threat["status"] == "NEW" and threat["confidence_score"] < 40:
        return "OBSERVATION"
    return "INDICATOR"


# ---------------------------------------------------------------- reads
def _display(row: dict) -> dict:
    row["indicator_defanged"] = defang(row["indicator_value"], row["indicator_type"])
    return row


def list_threats(conn, params: dict) -> dict:
    where, args = ["1=1"], []
    multi = {"severity": "t.severity", "category": "t.category", "status": "t.status", "indicator_type": "i.indicator_type",
             "entity_stage": "t.entity_stage"}
    for key, col in multi.items():
        vals = [v for v in str(params.get(key, "")).split(",") if v]
        if vals:
            where.append(f"{col} IN ({','.join('?' * len(vals))})")
            args += [v.upper() for v in vals]
    for key, col, op in (("min_risk", "t.risk_score", ">="), ("max_risk", "t.risk_score", "<="),
                         ("min_confidence", "t.confidence_score", ">="), ("max_confidence", "t.confidence_score", "<=")):
        if params.get(key) not in (None, ""):
            try:
                args.append(int(params[key]))
            except ValueError:
                raise ValidationError(f"{key} must be an integer")
            where.append(f"{col} {op} ?")
    for key, op in (("date_from", ">="), ("date_to", "<=")):
        if params.get(key):
            try:
                args.append(parse_date(params[key]).isoformat())
            except ValueError:
                raise ValidationError(f"{key} must be YYYY-MM-DD")
            where.append(f"t.last_seen {op} ?")
    q = sanitize_text(params.get("q", ""), 100)
    if q:
        where.append("(t.threat_id LIKE ? OR t.threat_name LIKE ? OR i.indicator_value LIKE ?)")
        args += [f"%{q}%"] * 3
    order = SORTS.get(params.get("sort", "newest"))
    if order is None:
        raise ValidationError("sort must be one of: " + ", ".join(SORTS))
    try:
        page, per_page = max(1, int(params.get("page", 1))), min(100, max(1, int(params.get("per_page", 25))))
    except ValueError:
        raise ValidationError("page and per_page must be integers")
    base = ("FROM threats t JOIN indicators i ON i.threat_id = t.threat_id "
            "LEFT JOIN sources s ON s.source_id = t.source_id WHERE " + " AND ".join(where))
    total = conn.execute("SELECT COUNT(*) " + base, args).fetchone()[0]
    rows = conn.execute(
        "SELECT t.threat_id, t.threat_name, t.category, t.severity, t.risk_score, t.confidence_score, t.status, "
        "t.first_seen, t.last_seen, t.observation_count, t.entity_stage, i.indicator_type, i.indicator_value, "
        f"s.source_name {base} ORDER BY {order} LIMIT ? OFFSET ?", args + [per_page, (page - 1) * per_page]).fetchall()
    return {"total": total, "page": page, "per_page": per_page, "items": [_display(dict(r)) for r in rows]}


def get_threat_detail(conn, threat_id: str) -> dict | None:
    row = conn.execute(
        "SELECT t.*, i.indicator_type, i.indicator_value, s.source_name, s.reliability FROM threats t "
        "JOIN indicators i ON i.threat_id = t.threat_id LEFT JOIN sources s ON s.source_id = t.source_id "
        "WHERE t.threat_id = ?", (threat_id,)).fetchone()
    if not row:
        return None
    t = _display(dict(row))
    t["reliability_label"] = RELIABILITY_LEVELS.get(t["reliability"], ("Unknown", 0))[0]
    t["related_indicators"] = [_display(dict(r)) for r in conn.execute(
        "SELECT t.threat_id, i.indicator_type, i.indicator_value, t.risk_score, t.severity, t.status FROM threats t "
        "JOIN indicators i ON i.threat_id = t.threat_id WHERE t.campaign_id = ? AND t.threat_id != ? "
        "ORDER BY t.risk_score DESC LIMIT 25", (t["campaign_id"], threat_id))]
    t["alerts"] = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE threat_id = ?", (threat_id,))]
    t["attack_mappings"] = [dict(r) for r in conn.execute("SELECT * FROM attack_mappings WHERE threat_id = ?", (threat_id,))]
    t["cve"] = None
    if t["cve_id"]:
        v = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (t["cve_id"],)).fetchone()
        t["cve"] = dict(v) if v else None
    t["notes"] = [dict(r) for r in conn.execute(
        "SELECT note_id, note, author, created_at FROM analyst_notes WHERE threat_id = ? ORDER BY note_id", (threat_id,))]
    t["recommended_actions"] = recommended_actions(t["category"])
    t["category_info"] = CATEGORY_INFO.get(t["category"], {})
    t["stage_explanation"] = STAGE_HELP.get(t["entity_stage"], "")
    t["interpretation"] = interpret_risk_confidence(t["risk_score"], t["confidence_score"])
    t["timeline"] = build_timeline(t)
    return t


def build_timeline(t: dict) -> list[dict]:
    """Derived timeline: first seen -> observations -> risk -> investigation -> monitoring -> closed."""
    ev = [{"date": t["first_seen"], "event": "First seen", "detail": f"Indicator first recorded from {t.get('source_name')}."},
          {"date": t["last_seen"], "event": "Latest observations",
           "detail": f"{t['observation_count']} observation(s) recorded in total."},
          {"date": t["last_seen"], "event": f"Risk assessed: {t['risk_score']}/100 ({t['severity']})",
           "detail": f"Confidence {t['confidence_score']}/100. " + t["interpretation"]}]
    for a in t["alerts"]:
        ev.append({"date": a["created_at"][:10], "event": f"Alert {a['alert_id']} ({a['alert_type']})", "detail": a["description"]})
    labels = {"UNDER_REVIEW": "Investigation in progress", "MONITORING": "Under monitoring",
              "CLOSED": "Closed", "FALSE_POSITIVE": "Marked false positive", "NEW": "Awaiting triage"}
    ev.append({"date": t["last_seen"], "event": labels.get(t["status"], t["status"]), "detail": "Current status."})
    for n in t["notes"]:
        ev.append({"date": n["created_at"][:10], "event": "Analyst note added", "detail": ""})
    return sorted(ev, key=lambda e: e["date"])


# ---------------------------------------------------------------- writes
def _source_id(conn, source_name: str) -> str:
    row = conn.execute("SELECT source_id FROM sources WHERE source_name = ?", (source_name,)).fetchone()
    if row:
        return row[0]
    sid = f"SRC-{conn.execute('SELECT COUNT(*) FROM sources').fetchone()[0] + 1:02d}"
    conn.execute("INSERT INTO sources VALUES (?,?,?)", (sid, source_name, SOURCES.get(source_name, "D")))
    return sid


def _next_threat_id(conn) -> str:
    n = conn.execute("SELECT COALESCE(MAX(CAST(SUBSTR(threat_id, 10) AS INTEGER)), 0) FROM threats").fetchone()[0]
    return f"THR-2026-{n + 1:03d}"


def _cluster_size(conn, campaign_id) -> int:
    if not campaign_id:
        return 1
    return conn.execute("SELECT COUNT(*) FROM threats WHERE campaign_id = ?", (campaign_id,)).fetchone()[0]


def create_threat(conn, payload: dict, actor: str = "system") -> tuple[dict, bool]:
    """Create a threat or, if the indicator already exists, record a DUPLICATE OBSERVATION.
    Returns (record, created)."""
    for field in ("threat_name", "category", "indicator_type", "indicator_value"):
        if not payload.get(field):
            raise ValidationError(f"'{field}' is required")
    category = str(payload["category"]).upper()
    if category not in CATEGORIES:
        raise ValidationError("category must be one of: " + ", ".join(CATEGORIES))
    v = validate_indicator(str(payload["indicator_value"]), str(payload["indicator_type"]).upper())
    if not v["valid"]:
        raise ValidationError("Invalid indicator: " + " ".join(v["validation_notes"]))
    source_name = payload.get("source_name", "Unknown Source")
    if source_name not in SOURCES:
        raise ValidationError("source_name must be one of: " + ", ".join(SOURCES))
    base_sev = str(payload.get("base_severity", "MEDIUM")).upper()
    if base_sev not in SEVERITIES:
        raise ValidationError("base_severity must be one of: " + ", ".join(SEVERITIES))

    existing = conn.execute("SELECT threat_id FROM indicators WHERE indicator_type = ? AND normalized_value = ?",
                            (v["indicator_type"], v["normalized_value"])).fetchone()
    if existing:  # duplicate observation: update counters instead of creating alert noise
        tid = existing[0]
        conn.execute("UPDATE threats SET observation_count = observation_count + 1, last_seen = ? WHERE threat_id = ?",
                     (REFERENCE_DATE.isoformat(), tid))
        _rescore(conn, tid)
        _audit(conn, actor, "DUPLICATE_OBSERVATION", tid, v["normalized_value"])
        conn.commit()
        return get_threat_detail(conn, tid), False

    rel = SOURCES[source_name]
    if payload.get("confidence_score") is not None:
        try:
            conf = int(payload["confidence_score"])
        except (TypeError, ValueError):
            raise ValidationError("confidence_score must be an integer 0-100")
        if not 0 <= conf <= 100:
            raise ValidationError("confidence_score must be between 0 and 100")
    else:
        conf = calculate_confidence(rel, 1, 0, False, 50)["confidence_score"]
    today = REFERENCE_DATE.isoformat()
    tid = _next_threat_id(conn)
    campaign = sanitize_text(payload.get("campaign_id", ""), 40) or None
    rec = {"threat_id": tid, "base_severity": base_sev, "confidence_score": conf, "last_seen": today,
           "observation_count": 1, "source_reliability": rel}
    risk = calculate_threat_risk(rec, context_score=context_from_evidence(_cluster_size(conn, campaign) + 1, 0))["risk_score"]
    status = payload.get("status", "NEW")
    if status not in STATUSES:
        raise ValidationError("status must be one of: " + ", ".join(STATUSES))
    conn.execute(
        "INSERT INTO threats (threat_id, threat_name, category, description, severity, base_severity, risk_score, "
        "confidence_score, status, first_seen, last_seen, record_timestamp, source_id, campaign_id, observation_count, "
        "related_alert_count, region, cve_id, entity_stage, incident_confirmed, synthetic_label) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (tid, sanitize_text(payload["threat_name"], 120), category, sanitize_text(payload.get("description", ""), 1000),
         classify_risk(risk), base_sev, risk, conf, status, today, today, now_iso(), _source_id(conn, source_name),
         campaign, 1, 0, sanitize_text(payload.get("region", ""), 60), None, "INDICATOR", 0, "ANALYST-ENTERED"))
    conn.execute("INSERT INTO indicators (threat_id, indicator_type, indicator_value, normalized_value, first_seen, last_seen) "
                 "VALUES (?,?,?,?,?,?)", (tid, v["indicator_type"], v["normalized_value"], v["normalized_value"], today, today))
    _apply_mapping(conn, tid)
    _refresh_alert(conn, tid)
    _audit(conn, actor, "CREATE_THREAT", tid, v["normalized_value"])
    conn.commit()
    return get_threat_detail(conn, tid), True


def update_threat(conn, threat_id: str, payload: dict, actor: str = "system") -> dict | None:
    row = conn.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
    if not row:
        return None
    sets, args = [], []
    if "status" in payload:
        if payload["status"] not in STATUSES:
            raise ValidationError("status must be one of: " + ", ".join(STATUSES))
        sets.append("status = ?"); args.append(payload["status"])
    if "confidence_score" in payload:
        try:
            c = int(payload["confidence_score"])
        except (TypeError, ValueError):
            raise ValidationError("confidence_score must be an integer 0-100")
        if not 0 <= c <= 100:
            raise ValidationError("confidence_score must be between 0 and 100")
        sets.append("confidence_score = ?"); args.append(c)
    if "description" in payload:
        sets.append("description = ?"); args.append(sanitize_text(payload["description"], 1000))
    if "incident_confirmed" in payload:
        sets.append("incident_confirmed = ?"); args.append(1 if payload["incident_confirmed"] else 0)
    if not sets:
        raise ValidationError("Nothing to update (allowed: status, confidence_score, description, incident_confirmed)")
    conn.execute(f"UPDATE threats SET {', '.join(sets)} WHERE threat_id = ?", args + [threat_id])
    if "confidence_score" in payload or "status" in payload:
        _rescore(conn, threat_id)
    _audit(conn, actor, "UPDATE_THREAT", threat_id, json.dumps({k: payload[k] for k in payload if k in ("status", "confidence_score", "incident_confirmed")}))
    conn.commit()
    return get_threat_detail(conn, threat_id)


def _rescore(conn, threat_id: str) -> None:
    t = dict(conn.execute("SELECT t.*, s.reliability FROM threats t LEFT JOIN sources s ON s.source_id = t.source_id "
                          "WHERE t.threat_id = ?", (threat_id,)).fetchone())
    t["source_reliability"] = t.pop("reliability") or "D"
    ctx = context_from_evidence(_cluster_size(conn, t["campaign_id"]), t["related_alert_count"])
    risk = calculate_threat_risk(t, context_score=ctx)["risk_score"]
    conn.execute("UPDATE threats SET risk_score = ?, severity = ? WHERE threat_id = ?", (risk, classify_risk(risk), threat_id))
    _apply_mapping(conn, threat_id)
    open_alert = conn.execute("SELECT 1 FROM alerts WHERE threat_id = ? AND status IN ('NEW','INVESTIGATING','MONITORING')",
                              (threat_id,)).fetchone() is not None
    fresh = dict(conn.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone())
    stage = classify_entity_stage(fresh, _cluster_size(conn, t["campaign_id"]), open_alert)
    conn.execute("UPDATE threats SET entity_stage = ? WHERE threat_id = ?", (stage, threat_id))


def _apply_mapping(conn, threat_id: str) -> None:
    row = conn.execute("SELECT t.category, t.confidence_score, t.status, i.indicator_type FROM threats t "
                       "JOIN indicators i ON i.threat_id = t.threat_id WHERE t.threat_id = ?", (threat_id,)).fetchone()
    conn.execute("DELETE FROM attack_mappings WHERE threat_id = ?", (threat_id,))
    m = map_to_attack(row["category"], row["indicator_type"], row["confidence_score"], row["status"])
    if m:
        conn.execute("INSERT INTO attack_mappings (threat_id, tactic, technique, technique_id_optional, rationale) VALUES (?,?,?,?,?)",
                     (threat_id, m["tactic"], m["technique"], m["technique_id"], m["rationale"]))


def _refresh_alert(conn, threat_id: str) -> None:
    d = get_threat_detail(conn, threat_id)
    vp = conn.execute("SELECT priority_score FROM vulnerabilities WHERE cve_id = ?", (d["cve_id"],)).fetchone() if d["cve_id"] else None
    raw = generate_threat_alert(d, _cluster_size(conn, d["campaign_id"]), vp[0] if vp else None)
    for a in correlate_alerts(raw):
        n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] + 1
        conn.execute("INSERT INTO alerts (alert_id, threat_id, severity, risk_score, confidence_score, alert_type, description, "
                     "status, observation_count, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (f"ALR-{n:06d}", a["threat_id"], a["severity"], a["risk_score"], a["confidence_score"],
                      a["alert_type"], a["description"], "NEW", a["observation_count"], a["timestamp"]))


def add_note(conn, threat_id: str, note: str, author: str) -> dict | None:
    if not conn.execute("SELECT 1 FROM threats WHERE threat_id = ?", (threat_id,)).fetchone():
        return None
    clean = sanitize_text(note, 2000)
    if not clean:
        raise ValidationError("note must not be empty")
    cur = conn.execute("INSERT INTO analyst_notes (threat_id, note, author, created_at) VALUES (?,?,?,?)",
                       (threat_id, clean, author, now_iso()))
    _audit(conn, author, "ADD_NOTE", threat_id, "")
    conn.commit()
    return {"note_id": cur.lastrowid, "threat_id": threat_id, "note": clean, "author": author}


def list_alerts(conn, status: str | None = None, severity: str | None = None, limit: int = 200) -> dict:
    where, args = ["1=1"], []
    if status:
        where.append("a.status = ?"); args.append(status.upper())
    if severity:
        where.append("a.severity = ?"); args.append(severity.upper())
    rows = conn.execute(
        "SELECT a.*, i.indicator_type, i.indicator_value FROM alerts a JOIN indicators i ON i.threat_id = a.threat_id "
        f"WHERE {' AND '.join(where)} ORDER BY a.risk_score DESC, a.alert_id LIMIT ?", args + [min(limit, 500)]).fetchall()
    return {"total": len(rows), "items": [_display(dict(r)) for r in rows]}


def update_alert_status(conn, alert_id: str, status: str, actor: str) -> dict | None:
    from backend.services.knowledge import ALERT_STATUSES
    if status not in ALERT_STATUSES:
        raise ValidationError("status must be one of: " + ", ".join(ALERT_STATUSES))
    if not conn.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone():
        return None
    conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
    _audit(conn, actor, "ALERT_STATUS", alert_id, status)
    conn.commit()
    return dict(conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone())


def _audit(conn, actor, action, target, detail):
    conn.execute("INSERT INTO audit_log (actor, action, target, detail, created_at) VALUES (?,?,?,?,?)",
                 (actor, action, target, detail, now_iso()))


# ---------------------------------------------------------------- analytics
def _dist(conn, sql, order=None):
    data = {r[0]: r[1] for r in conn.execute(sql)}
    if order:
        data = {k: data.get(k, 0) for k in order}
    return data


def dashboard_stats(conn) -> dict:
    def one(sql):
        return conn.execute(sql).fetchone()[0] or 0
    act = ",".join(f"'{s}'" for s in ACTIVE_STATUSES)
    total = one("SELECT COUNT(*) FROM threats")
    hist = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    conf_hist = dict(hist)
    for (r, c) in conn.execute("SELECT risk_score, confidence_score FROM threats"):
        hist[_bucket(r)] += 1
        conf_hist[_bucket(c)] += 1
    return {
        "as_of": REFERENCE_DATE.isoformat(),
        "cards": {
            "total_threat_records": total,
            "critical_threats": one("SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL'"),
            "high_threats": one("SELECT COUNT(*) FROM threats WHERE severity = 'HIGH'"),
            "active_indicators": one(f"SELECT COUNT(*) FROM threats WHERE status IN ({act})"),
            "open_investigations": one("SELECT COUNT(*) FROM threats WHERE status = 'UNDER_REVIEW'"),
            "average_confidence": round(one("SELECT AVG(confidence_score) FROM threats"), 1),
            "vulnerabilities_tracked": one("SELECT COUNT(*) FROM vulnerabilities"),
        },
        "by_severity": _dist(conn, "SELECT severity, COUNT(*) FROM threats GROUP BY severity", SEVERITIES),
        "by_category": _dist(conn, "SELECT category, COUNT(*) FROM threats GROUP BY category ORDER BY 2 DESC"),
        "by_indicator_type": _dist(conn, "SELECT indicator_type, COUNT(*) FROM indicators GROUP BY indicator_type ORDER BY 2 DESC"),
        "by_status": _dist(conn, "SELECT status, COUNT(*) FROM threats GROUP BY status", STATUSES),
        "by_entity_stage": _dist(conn, "SELECT entity_stage, COUNT(*) FROM threats GROUP BY entity_stage",
                                 ["OBSERVATION", "INDICATOR", "ALERT", "THREAT", "INCIDENT"]),
        "risk_distribution": hist, "confidence_distribution": conf_hist,
        "top_categories": dict(list(_dist(conn, "SELECT category, COUNT(*) FROM threats GROUP BY category ORDER BY 2 DESC").items())[:5]),
        "top_tactics": _dist(conn, "SELECT tactic, COUNT(*) FROM attack_mappings GROUP BY tactic ORDER BY 2 DESC"),
        "vulnerabilities_by_severity": _dist(conn, "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity", SEVERITIES),
        "alerts_by_status": _dist(conn, "SELECT status, COUNT(*) FROM alerts GROUP BY status"),
    }


def _bucket(v):
    return "0-20" if v <= 20 else "21-40" if v <= 40 else "41-60" if v <= 60 else "61-80" if v <= 80 else "81-100"


def dashboard_trends(conn) -> dict:
    months = conn.execute("SELECT SUBSTR(first_seen,1,7) m, COUNT(*) FROM threats GROUP BY m ORDER BY m").fetchall()
    by_sev: dict[str, dict] = {}
    for m, s, c in conn.execute("SELECT SUBSTR(first_seen,1,7), severity, COUNT(*) FROM threats GROUP BY 1,2"):
        by_sev.setdefault(s, {})[m] = c
    labels = [r[0] for r in months]
    return {"labels": labels, "total": [r[1] for r in months],
            "by_severity": {s: [by_sev.get(s, {}).get(m, 0) for m in labels] for s in SEVERITIES},
            "technique_frequency": [dict(r) for r in conn.execute(
                "SELECT technique_id_optional AS technique_id, technique, tactic, COUNT(*) AS count FROM attack_mappings "
                "GROUP BY technique_id_optional, technique, tactic ORDER BY count DESC")]}


def attack_threats(conn, technique_id: str) -> dict:
    rows = conn.execute(
        "SELECT t.threat_id, t.threat_name, t.severity, t.risk_score, t.confidence_score, t.status, i.indicator_type, i.indicator_value, "
        "m.technique, m.tactic FROM attack_mappings m JOIN threats t ON t.threat_id = m.threat_id "
        "JOIN indicators i ON i.threat_id = t.threat_id WHERE m.technique_id_optional = ? ORDER BY t.risk_score DESC LIMIT 100",
        (technique_id.upper(),)).fetchall()
    return {"technique_id": technique_id.upper(), "total": len(rows), "items": [_display(dict(r)) for r in rows]}


def list_vulnerabilities(conn, severity=None, min_priority=None) -> dict:
    where, args = ["1=1"], []
    if severity:
        where.append("severity = ?"); args.append(severity.upper())
    if min_priority not in (None, ""):
        try:
            args.append(float(min_priority))
        except ValueError:
            raise ValidationError("min_priority must be a number")
        where.append("priority_score >= ?")
    rows = conn.execute(f"SELECT * FROM vulnerabilities WHERE {' AND '.join(where)} ORDER BY priority_score DESC", args).fetchall()
    return {"total": len(rows), "items": [dict(r) for r in rows]}


def executive_summary(conn) -> dict:
    s = dashboard_stats(conn)
    c = s["cards"]
    top_cats = list(s["top_categories"].items())
    vcat = [dict(r) for r in conn.execute(
        "SELECT product_category, COUNT(*) AS count FROM vulnerabilities WHERE priority_label LIKE 'P1%' OR priority_label LIKE 'P2%' "
        "GROUP BY product_category ORDER BY count DESC LIMIT 3")]
    trend = [dict(r) for r in conn.execute(
        "SELECT SUBSTR(created_at,1,7) AS month, ROUND(AVG(overall_score),1) AS avg_score, COUNT(*) AS attempts "
        "FROM quiz_results GROUP BY month ORDER BY month")]
    agg: dict[str, list[int]] = {}
    for (cs,) in conn.execute("SELECT category_scores FROM quiz_results WHERE category_scores IS NOT NULL"):
        for k, v in json.loads(cs).items():
            agg.setdefault(k, []).append(v)
    weak = sorted(({"category": k, "avg_score": round(sum(v) / len(v))} for k, v in agg.items()), key=lambda x: x["avg_score"])[:3]
    p12 = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE priority_label LIKE 'P1%'").fetchone()[0]
    narrative = (f"As of {s['as_of']}, the platform tracks {c['total_threat_records']} synthetic threat records. "
                 f"{c['critical_threats'] + c['high_threats']} are rated High or Critical, but only a small number have been confirmed as incidents "
                 f"({s['by_entity_stage'].get('INCIDENT', 0)}); most are indicators to monitor. "
                 f"Most activity relates to {top_cats[0][0].title() if top_cats else 'n/a'}.")
    priorities = [
        f"Review the {c['open_investigations']} investigations currently open before taking on new work.",
        f"Patch the {p12} urgent (P1) vulnerabilities first - they combine severity, exposure and exploitation evidence.",
        "Keep multi-factor authentication enforced on all internet-facing accounts.",
        "Run phishing awareness refreshers" + (f" - weakest quiz area is {weak[0]['category']}." if weak else "."),
        "Confirm backups are offline and restorable (ransomware readiness).",
    ]
    return {"as_of": s["as_of"], "narrative": narrative, "critical_high_count": c["critical_threats"] + c["high_threats"],
            "top_threat_categories": top_cats, "top_vulnerability_categories": vcat, "awareness_score_trend": trend,
            "top_awareness_weaknesses": weak, "recommended_priorities": priorities, "cards": c,
            "entity_stages": s["by_entity_stage"]}
