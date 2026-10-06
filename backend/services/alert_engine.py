"""Alert generation and alert correlation (fighting alert fatigue).

Alert fatigue = analysts receive so many alerts that important ones are missed.
Fix: merge duplicate alerts for the same indicator into ONE alert with an observation count.
"""
from datetime import datetime, timezone

SEVERITY_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ALERT_PRIORITY = ["HIGH_PRIORITY_VULNERABILITY", "RISK_THRESHOLD", "CORRELATED_INDICATORS",
                  "REPEATED_OBSERVATIONS", "HIGH_RISK_LOW_CONFIDENCE"]

DEFAULTS = {"risk_threshold": 70, "confidence_threshold": 50, "repeat_threshold": 50,
            "cluster_threshold": 4, "vuln_priority_threshold": 70}


def generate_threat_alert(threat: dict, cluster_size: int = 1, vuln_priority: float | None = None,
                          config: dict | None = None) -> list[dict]:
    """Return a list of raw alerts (possibly empty) for one threat record.

    Triggers: risk threshold, confidence threshold, high-priority vulnerability,
    repeated observations, correlated indicators. Closed / false-positive records never alert.
    """
    cfg = {**DEFAULTS, **(config or {})}
    if threat.get("status") in ("CLOSED", "FALSE_POSITIVE"):
        return []
    risk, conf = threat.get("risk_score", 0), threat.get("confidence_score", 0)
    reasons = []
    if risk >= cfg["risk_threshold"] and conf >= cfg["confidence_threshold"]:
        reasons.append(("RISK_THRESHOLD", f"Risk {risk} and confidence {conf} exceed alert thresholds."))
    elif risk >= 80 and conf < cfg["confidence_threshold"]:
        reasons.append(("HIGH_RISK_LOW_CONFIDENCE", f"Risk {risk} is high but confidence is only {conf}: validate the intelligence."))
    if vuln_priority is not None and vuln_priority >= cfg["vuln_priority_threshold"]:
        reasons.append(("HIGH_PRIORITY_VULNERABILITY", f"Associated vulnerability has priority score {vuln_priority}."))
    if threat.get("observation_count", 1) >= cfg["repeat_threshold"]:
        reasons.append(("REPEATED_OBSERVATIONS", f"Indicator observed {threat['observation_count']} times."))
    if cluster_size >= cfg["cluster_threshold"] and risk >= 50:
        reasons.append(("CORRELATED_INDICATORS", f"Part of a related cluster of {cluster_size} indicators."))

    ts = threat.get("record_timestamp") or datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None).isoformat()
    alerts = []
    for i, (atype, why) in enumerate(reasons):
        alerts.append({
            "threat_id": threat["threat_id"], "timestamp": ts, "alert_type": atype,
            "severity": threat.get("severity", "MEDIUM"), "risk_score": risk, "confidence_score": conf,
            "indicator_value": threat.get("indicator_value", ""), "description": why,
            # All triggers describe the SAME sightings, so only the first carries the count.
            "observation_count": threat.get("observation_count", 1) if i == 0 else 0,
            "status": "NEW",
        })
    return alerts


def correlate_alerts(raw_alerts: list[dict], window_seconds: int = 300) -> list[dict]:
    """Merge raw alerts for the same indicator inside a time window into ONE alert.

    100 identical alerts in 5 minutes -> 1 alert with observation_count = 100.
    """
    by_indicator: dict[str, list[dict]] = {}
    for a in raw_alerts:
        by_indicator.setdefault(a["indicator_value"], []).append(a)

    merged = []
    for indicator, items in by_indicator.items():
        items.sort(key=lambda a: a["timestamp"])
        group = []
        for a in items:
            if group and _seconds_between(group[0]["timestamp"], a["timestamp"]) > window_seconds:
                merged.append(_merge(indicator, group))
                group = []
            group.append(a)
        if group:
            merged.append(_merge(indicator, group))
    merged.sort(key=lambda a: a["timestamp"])
    return merged


def _seconds_between(t1: str, t2: str) -> float:
    return abs((datetime.fromisoformat(t2) - datetime.fromisoformat(t1)).total_seconds())


def _merge(indicator: str, group: list[dict]) -> dict:
    top = max(group, key=lambda a: (SEVERITY_RANK.get(a["severity"], 0), a["risk_score"]))
    types = sorted({a["alert_type"] for a in group}, key=lambda t: ALERT_PRIORITY.index(t) if t in ALERT_PRIORITY else 99)
    merged = dict(top)
    merged.update({
        "alert_type": types[0],
        "reasons": types,
        "observation_count": sum(a.get("observation_count", 1) for a in group),
        "raw_alert_count": len(group),
        "timestamp": max(a["timestamp"] for a in group),
        "description": " | ".join(dict.fromkeys(a["description"] for a in group))[:500],
    })
    return merged
