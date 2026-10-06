"""Risk scoring, confidence scoring and source reliability.

RISK       = how concerning the indicator/event may be.
CONFIDENCE = how much we trust the intelligence itself.
High risk does NOT mean confirmed compromise, and low confidence does not mean harmless.
"""
import math
from datetime import date

from backend.config import REFERENCE_DATE
from backend.utils.dates import parse_date

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_SCORES = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}

# Source name -> (reliability letter, label)
SOURCES = {
    "Internal SOC": "A",
    "Security Vendor": "B",
    "Research Report": "B",
    "Public Threat Feed": "C",
    "Community Submission": "C",
    "Unknown Source": "D",
}
RELIABILITY_LEVELS = {
    "A": ("Highly Reliable", 100),
    "B": ("Usually Reliable", 80),
    "C": ("Fairly Reliable", 60),
    "D": ("Reliability Unknown", 30),
}

# Conceptual weights from the project brief (sum = 1.0)
WEIGHTS = {"severity": 0.30, "confidence": 0.25, "recency": 0.15,
           "observations": 0.10, "source_reliability": 0.10, "context": 0.10}


def source_reliability_score(letter: str) -> int:
    """Numeric value (0-100) for a reliability letter. Unknown letters fall back to D."""
    return RELIABILITY_LEVELS.get(letter, RELIABILITY_LEVELS["D"])[1]


def recency_score(last_seen, as_of: date | None = None) -> float:
    """100 when seen today, decaying exponentially (half-life about 31 days)."""
    as_of = as_of or REFERENCE_DATE
    days = max(0, (as_of - parse_date(last_seen)).days)
    return 100.0 * math.exp(-days / 45.0)


def observation_score(count: int) -> float:
    """Diminishing returns: 1 sighting=20, 8=63, 31+=100."""
    return min(100.0, 20.0 * math.log2(max(0, int(count)) + 1))


def classify_risk(score: float) -> str:
    """0-20 INFORMATIONAL, 21-40 LOW, 41-60 MEDIUM, 61-80 HIGH, 81-100 CRITICAL."""
    s = round(score)
    if s <= 20:
        return "INFORMATIONAL"
    if s <= 40:
        return "LOW"
    if s <= 60:
        return "MEDIUM"
    if s <= 80:
        return "HIGH"
    return "CRITICAL"


def calculate_threat_risk(threat: dict, as_of: date | None = None, context_score: float = 0) -> dict:
    """Weighted 0-100 risk score.

    threat keys used: base_severity, confidence_score, last_seen, observation_count, source_reliability
    context_score (0-100): correlation / related-alert evidence supplied by the caller.
    """
    components = {
        "severity": SEVERITY_SCORES.get(threat.get("base_severity", "MEDIUM"), 50),
        "confidence": max(0, min(100, float(threat.get("confidence_score", 50)))),
        "recency": recency_score(threat["last_seen"], as_of),
        "observations": observation_score(threat.get("observation_count", 1)),
        "source_reliability": source_reliability_score(threat.get("source_reliability", "D")),
        "context": max(0, min(100, float(context_score))),
    }
    raw = sum(components[k] * WEIGHTS[k] for k in WEIGHTS)
    score = int(round(max(0, min(100, raw))))
    return {
        "risk_score": score,
        "classification": classify_risk(score),
        "components": {k: round(v, 1) for k, v in components.items()},
        "weights": WEIGHTS,
        "note": "High risk is NOT confirmed compromise - it prioritises analyst attention.",
    }


def context_from_evidence(cluster_size: int, related_alerts: int) -> int:
    """Context/correlation score: more related records and alerts = stronger context."""
    return int(min(100, 15 * max(0, cluster_size - 1) + 20 * max(0, related_alerts)))


def calculate_confidence(source_reliability: str, corroborating_sources: int = 1, age_days: int = 0,
                         analyst_validated: bool = False, context_completeness: int = 50) -> dict:
    """0-100 confidence in the intelligence itself (not in how bad the threat is)."""
    parts = {
        "source_reliability": source_reliability_score(source_reliability),
        "corroboration": min(100, corroborating_sources * 35) if corroborating_sources > 1 else 30,
        "freshness": 100.0 * math.exp(-max(0, age_days) / 90.0),
        "analyst_validation": 100 if analyst_validated else 0,
        "context_completeness": max(0, min(100, context_completeness)),
    }
    weights = {"source_reliability": 0.35, "corroboration": 0.25, "freshness": 0.20,
               "analyst_validation": 0.10, "context_completeness": 0.10}
    score = int(round(sum(parts[k] * weights[k] for k in weights)))
    return {"confidence_score": max(0, min(100, score)), "components": {k: round(v, 1) for k, v in parts.items()}}


def interpret_risk_confidence(risk: int, confidence: int) -> str:
    """Plain-language reading of the (risk, confidence) pair."""
    if risk >= 61 and confidence < 40:
        return "Potentially serious, but evidence quality is weak - validate before acting."
    if risk >= 61 and confidence >= 70:
        return "High-confidence intelligence with meaningful risk - prioritise investigation."
    if risk >= 61:
        return "Meaningful risk with moderate confidence - enrich and corroborate."
    if confidence >= 70:
        return "Reliable intelligence with limited risk - monitor."
    return "Low risk and limited confidence - low priority; keep for context."
