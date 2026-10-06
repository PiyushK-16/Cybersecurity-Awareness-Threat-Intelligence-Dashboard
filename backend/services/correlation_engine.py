"""Threat correlation: group related records into RELATED THREAT CLUSTERS.

Correlation = shared evidence (same campaign, category, observation window).
Correlation is NOT attribution: it never proves WHO is behind activity.
"""
from collections import defaultdict
from datetime import timedelta

from backend.utils.dates import parse_date


def correlate_threats(threats: list[dict], window_days: int = 14, min_cluster_size: int = 2) -> list[dict]:
    """Return clusters (lists of related threats).

    Strong link : identical campaign_id.
    Weak link   : (only for records WITHOUT a campaign_id) same category and first_seen
                  within `window_days` of the previous record in that category.
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    basis: dict[str, str] = {}
    no_campaign: dict[str, list[dict]] = defaultdict(list)

    for t in threats:
        cid = t.get("campaign_id")
        if cid:
            groups[cid].append(t)
            basis[cid] = "shared campaign_id"
        else:
            no_campaign[t["category"]].append(t)

    for category, items in no_campaign.items():
        items.sort(key=lambda x: parse_date(x["first_seen"]))
        bucket, bucket_id = [], 0
        for t in items:
            if bucket and parse_date(t["first_seen"]) - parse_date(bucket[-1]["first_seen"]) > timedelta(days=window_days):
                _flush(groups, basis, category, bucket_id, bucket)
                bucket, bucket_id = [], bucket_id + 1
            bucket.append(t)
        _flush(groups, basis, category, bucket_id, bucket)

    clusters = []
    for cid, members in groups.items():
        if len(members) < min_cluster_size:
            continue
        clusters.append({
            "cluster_id": cid,
            "link_basis": basis[cid],
            "size": len(members),
            "categories": sorted({m["category"] for m in members}),
            "indicator_types": sorted({m.get("indicator_type", "?") for m in members}),
            "max_risk": max(m.get("risk_score", 0) for m in members),
            "threat_ids": [m["threat_id"] for m in members],
            "note": "RELATED THREAT CLUSTER - indicates relationship/evidence, not guaranteed attribution.",
        })
    clusters.sort(key=lambda c: (-c["max_risk"], -c["size"]))
    return clusters


def _flush(groups, basis, category, bucket_id, bucket):
    if bucket:
        key = f"WEAK-{category.replace(' ', '_')}-{bucket_id}"
        groups[key].extend(bucket)
        basis[key] = f"same category + first_seen window (weak link)"


def cluster_sizes(clusters: list[dict]) -> dict[str, int]:
    """Map threat_id -> size of the cluster it belongs to."""
    out = {}
    for c in clusters:
        for tid in c["threat_ids"]:
            out[tid] = c["size"]
    return out
