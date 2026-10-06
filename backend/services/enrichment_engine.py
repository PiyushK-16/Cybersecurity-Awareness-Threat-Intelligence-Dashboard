"""Indicator search + enrichment using LOCAL data only.

This module performs a DATABASE LOOKUP. It never connects to the searched IP/domain/URL.
Optional future integrations (authorised threat-intel APIs) are discussed in docs, not implemented.
"""
from backend.services.ioc_validator import defang, validate_indicator
from backend.services.risk_engine import SEVERITIES, interpret_risk_confidence


def enrich_indicator(conn, value: str) -> dict:
    v = validate_indicator(value)
    out = {"query": value[:200], "valid": v["valid"], "indicator_type": v["indicator_type"],
           "validation_notes": v["validation_notes"], "known_in_dataset": False,
           "lookup_note": "Database lookup only - no network connection was made to this indicator."}
    if not v["valid"]:
        return out
    out["normalized_value"] = v["normalized_value"]
    out["indicator_defanged"] = defang(v["normalized_value"], v["indicator_type"])
    rows = conn.execute(
        "SELECT t.*, i.indicator_type, s.source_name, s.reliability FROM indicators i JOIN threats t ON t.threat_id = i.threat_id "
        "LEFT JOIN sources s ON s.source_id = t.source_id WHERE i.normalized_value = ? ORDER BY t.risk_score DESC",
        (v["normalized_value"],)).fetchall()
    if not rows:
        out["interpretation"] = ("Not found in the demo dataset. That does NOT mean the indicator is safe - "
                                 "it only means this local dataset has no record of it.")
        return out
    top = dict(rows[0])
    tids = [r["threat_id"] for r in rows]
    ph = ",".join("?" * len(tids))
    campaigns = {r["campaign_id"] for r in rows if r["campaign_id"]}
    related = []
    for cid in campaigns:
        related += [dict(r) for r in conn.execute(
            "SELECT t.threat_id, i.indicator_type, i.indicator_value, t.risk_score FROM threats t JOIN indicators i "
            f"ON i.threat_id = t.threat_id WHERE t.campaign_id = ? AND i.normalized_value != ? LIMIT 20", (cid, v["normalized_value"]))]
    for r in related:
        r["indicator_defanged"] = defang(r["indicator_value"], r["indicator_type"])
    out.update({
        "known_in_dataset": True,
        "threat_ids": tids,
        "risk_score": top["risk_score"], "severity": top["severity"], "confidence_score": top["confidence_score"],
        "associated_categories": sorted({r["category"] for r in rows}),
        "first_seen": min(r["first_seen"] for r in rows), "last_seen": max(r["last_seen"] for r in rows),
        "status": top["status"], "entity_stage": top["entity_stage"], "source": top["source_name"],
        "source_reliability": top["reliability"],
        "related_alerts": [dict(r) for r in conn.execute(f"SELECT alert_id, alert_type, severity, status FROM alerts WHERE threat_id IN ({ph})", tids)],
        "related_indicators": related,
        "attack_mappings": [dict(r) for r in conn.execute(
            f"SELECT tactic, technique, technique_id_optional FROM attack_mappings WHERE threat_id IN ({ph})", tids)],
        "analyst_notes": [dict(r) for r in conn.execute(
            f"SELECT note, author, created_at FROM analyst_notes WHERE threat_id IN ({ph}) ORDER BY note_id", tids)],
        "interpretation": interpret_risk_confidence(top["risk_score"], top["confidence_score"]),
        "caution": "An IOC match is NOT automatic confirmed compromise. Validate against authorised internal evidence.",
    })
    return out
