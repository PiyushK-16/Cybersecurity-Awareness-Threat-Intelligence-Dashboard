#!/usr/bin/env python3
"""Synthetic threat-intelligence dataset generator (SAFE - nothing here is real intelligence).

Safety rules baked in:
  * IPs come ONLY from documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
  * Domains use example.com / example.org / example.net / .invalid
  * Hashes are random hex strings - they match no real file. Labelled SYNTHETIC / DEMO ONLY
  * CVE IDs use the fictional year 2099 (CVE-2099-xxxxx) so they can never collide with real CVEs

Run from the project root:   python data/generate_threat_data.py [--records 2100] [--seed 42]
Outputs: data/threat_intelligence_dataset.csv and data/vulnerabilities.csv
"""
import argparse
import csv
import math
import random
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import REFERENCE_DATE  # noqa: E402
from backend.services.attack_mapper import map_to_attack  # noqa: E402
from backend.services.knowledge import CATEGORIES  # noqa: E402
from backend.services.risk_engine import (SEVERITIES, SOURCES, calculate_confidence,  # noqa: E402
                                          calculate_threat_risk, classify_risk, context_from_evidence)
from backend.services.vulnerability_service import (EXPLOIT_SCORES, EXPOSURE_SCORES,  # noqa: E402
                                                    calculate_vulnerability_priority, cvss_to_severity)

SYNTHETIC_LABEL = "SYNTHETIC / DEMO ONLY"
WORDS = ["login", "secure", "account", "verify", "portal", "update", "billing", "invoice", "support", "cloud",
         "mail", "docs", "payroll", "delivery", "track", "reset", "auth", "bank", "shop", "wallet", "survey",
         "files", "share", "meeting", "helpdesk", "status", "alert", "notice", "review", "access"]
PATHS = ["session", "verify", "reset", "download", "invoice", "update", "confirm", "review", "files", "view"]
TLDS = ["example.com", "example.org", "example.net", "invalid"]
REGIONS = ["North America", "Europe", "Asia-Pacific", "Latin America", "Middle East", "Africa", "Global", ""]

NAMES = {
    "PHISHING": ["Synthetic Credential Phishing Campaign", "Synthetic Invoice Lure Wave", "Synthetic Delivery-Notice Lure", "Synthetic Account-Verification Lure"],
    "MALWARE": ["Synthetic Loader Sample Cluster", "Synthetic Info-Stealer Sample Set", "Synthetic Trojan Delivery Pattern"],
    "RANSOMWARE": ["Synthetic Ransomware Sample Family", "Synthetic Extortion-Linked Infrastructure"],
    "CREDENTIAL THREATS": ["Synthetic Credential Stuffing Wave", "Synthetic Password Spray Pattern", "Synthetic Leaked-Credential Report"],
    "WEB THREATS": ["Synthetic Malicious Web Content Set", "Synthetic Web App Probing Pattern"],
    "NETWORK THREATS": ["Synthetic Port-Probing Activity", "Synthetic Scanning Source Cluster"],
    "VULNERABILITY EXPOSURE": ["Synthetic Exposed-Service Advisory", "Synthetic Unpatched-Software Watch"],
    "SOCIAL ENGINEERING": ["Synthetic Impersonation Attempt Pattern", "Synthetic Vishing Pretext Report"],
    "DATA EXPOSURE": ["Synthetic Public Share Exposure", "Synthetic Misconfigured Storage Report"],
    "ACCOUNT SECURITY": ["Synthetic Risky Sign-In Pattern", "Synthetic Account Takeover Attempt Set"],
}
TYPE_CHOICES = {
    "PHISHING": ["DOMAIN", "URL", "EMAIL_DOMAIN", "IP"],
    "MALWARE": ["FILE_HASH", "DOMAIN", "IP", "URL"],
    "RANSOMWARE": ["FILE_HASH", "DOMAIN", "IP"],
    "CREDENTIAL THREATS": ["IP", "DOMAIN", "URL"],
    "WEB THREATS": ["URL", "DOMAIN", "IP"],
    "NETWORK THREATS": ["IP"],
    "VULNERABILITY EXPOSURE": ["CVE_ID"],
    "SOCIAL ENGINEERING": ["EMAIL_DOMAIN", "DOMAIN"],
    "DATA EXPOSURE": ["URL", "DOMAIN", "FILE_HASH"],
    "ACCOUNT SECURITY": ["IP", "EMAIL_DOMAIN", "DOMAIN"],
}
CATEGORY_WEIGHT = [18, 14, 7, 12, 10, 9, 8, 8, 7, 7]
# severity weights INFO, LOW, MEDIUM, HIGH, CRITICAL
SEV_WEIGHTS = {"RANSOMWARE": [1, 5, 20, 40, 34], "MALWARE": [3, 12, 35, 35, 15], "PHISHING": [5, 20, 40, 28, 7],
               "VULNERABILITY EXPOSURE": [3, 12, 30, 35, 20]}
DEFAULT_SEV_WEIGHTS = [8, 25, 38, 22, 7]
SOURCE_WEIGHTS = [15, 20, 10, 25, 20, 10]  # Internal SOC, Vendor, Research, Public Feed, Community, Unknown
PRODUCTS = ["Web Server", "VPN Appliance", "Email Gateway", "Operating System", "Database Server", "Web Browser",
            "IoT Device Firmware", "Content Management System", "Container Runtime", "Identity Provider", "Network Device"]


class SafeIndicators:
    """Generates unique, safe indicator values."""

    def __init__(self, rng):
        self.rng, self.used = rng, set()

    def _unique(self, fn):
        for _ in range(1000):
            v = fn()
            if v not in self.used:
                self.used.add(v)
                return v
        raise RuntimeError("could not generate a unique indicator")

    def domain(self):
        r = self.rng
        def fn():
            host = f"{r.choice(WORDS)}-{r.choice(WORDS)}"
            tld = r.choice(TLDS)
            return f"{host}.{tld}" if tld == "invalid" else f"{host}.{tld}" if r.random() < .5 else f"{r.choice(WORDS)}.{host}.{tld}"
        return self._unique(fn)

    def ip(self):
        r = self.rng
        def fn():
            if r.random() < 0.08:
                return f"2001:db8:{r.randrange(0x10000):x}::{r.randrange(1, 0x10000):x}"
            net = r.choice(["192.0.2", "198.51.100", "203.0.113"])
            return f"{net}.{r.randrange(1, 255)}"
        return self._unique(fn)

    def url(self):
        r = self.rng
        return self._unique(lambda: f"https://{self.domain()}/{r.choice(PATHS)}/{r.randrange(100, 999)}")

    def file_hash(self):
        r = self.rng
        return self._unique(lambda: "".join(r.choices("0123456789abcdef", k=64)))

    def email_domain(self):
        r = self.rng
        return self._unique(lambda: f"mail-{r.choice(WORDS)}{r.randrange(10, 99)}.{r.choice(['example.org', 'example.net', 'invalid'])}")

    def make(self, itype, cve_pool):
        if itype == "CVE_ID":
            return self.rng.choice(cve_pool)  # many threat records may reference one CVE
        return {"IP": self.ip, "DOMAIN": self.domain, "URL": self.url,
                "FILE_HASH": self.file_hash, "EMAIL_DOMAIN": self.email_domain}[itype]()


def generate_vulnerabilities(rng, count=60):
    rows = []
    for i in range(count):
        cvss = round(min(10.0, max(1.0, rng.gauss(6.8, 2.0))), 1)
        published = REFERENCE_DATE - timedelta(days=rng.randrange(5, 330))
        expo = rng.choices(list(EXPOSURE_SCORES), weights=[20, 45, 35])[0]
        exploit = rng.choices(list(EXPLOIT_SCORES), weights=[60, 28, 12])[0]
        crit, biz = rng.randint(1, 5), rng.randint(1, 5)
        pr = calculate_vulnerability_priority(cvss, crit, expo, exploit, biz)
        product = rng.choice(PRODUCTS)
        rows.append({
            "cve_id": f"CVE-2099-{10001 + i}", "product_category": product,
            "severity": cvss_to_severity(cvss), "cvss_score": cvss, "published_date": published.isoformat(),
            "patch_available": rng.random() < 0.7, "exploitation_status_demo": exploit,
            "asset_criticality": crit, "exposure": expo, "business_impact": biz,
            "priority_score": pr["priority_score"], "priority_label": pr["priority_label"],
            "description": f"{SYNTHETIC_LABEL}: fictional weakness in a {product.lower()} used for awareness training. "
                           f"No exploitation details are included.",
        })
    return rows


def _pick_status(rng, days_old):
    if days_old <= 14:
        w = [35, 30, 30, 0, 5]
    elif days_old <= 60:
        w = [10, 25, 35, 20, 10]
    else:
        w = [3, 7, 20, 55, 15]
    return rng.choices(["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"], weights=w)[0]


def build_record(rng, ind, n, spec, cve_pool, vuln_by_cve):
    """Create one dataset row from a spec dict."""
    category, itype = spec["category"], spec["indicator_type"]
    source = spec["source_name"]
    rel = SOURCES[source]
    last_seen, first_seen = spec["last_seen"], spec["first_seen"]
    age_days = (REFERENCE_DATE - last_seen).days
    status = spec["status"]

    if "confidence" in spec:  # explicit demo value
        confidence = spec["confidence"]
    else:
        conf = calculate_confidence(rel, spec["corroboration"], age_days, spec["validated"], spec["completeness"])
        confidence = conf["confidence_score"]
        if status == "FALSE_POSITIVE":
            confidence = int(confidence * 0.6)

    threat = {"base_severity": spec["base_severity"], "confidence_score": confidence, "last_seen": last_seen,
              "observation_count": spec["observation_count"], "source_reliability": rel}
    context = context_from_evidence(spec["cluster_size"], spec["related_alert_count"])
    risk = calculate_threat_risk(threat, context_score=context)["risk_score"]
    mapping = map_to_attack(category, itype, confidence, status)

    cve = spec.get("cve_id") or ""
    if not cve and itype != "CVE_ID" and category in ("WEB THREATS", "MALWARE", "NETWORK THREATS") and rng.random() < .2:
        cve = rng.choice(cve_pool)
    if itype == "CVE_ID":
        cve = spec["indicator_value"]

    incident = int(spec.get("incident_confirmed", 0))
    desc = spec.get("description") or (
        f"{SYNTHETIC_LABEL}. Fictional {category.lower()} observation involving a {itype.replace('_', ' ').lower()} indicator. "
        f"An indicator match is NOT proof of compromise; analyst validation is required.")
    return {
        "threat_id": f"THR-2026-{n:03d}",
        "timestamp": spec["timestamp"].isoformat(timespec="seconds"),
        "threat_name": spec["threat_name"], "threat_category": category, "indicator_type": itype,
        "indicator_value": spec["indicator_value"], "source_name": source,
        "confidence_score": confidence, "severity": classify_risk(risk), "risk_score": risk, "status": status,
        "first_seen": first_seen.isoformat(), "last_seen": last_seen.isoformat(),
        "country_or_region_optional": spec["region"], "description": desc,
        "mitre_tactic_optional": mapping["tactic"] if mapping else "",
        "mitre_technique_optional": mapping["technique"] if mapping else "",
        "mitre_technique_id_optional": mapping["technique_id"] if mapping else "",
        "cve_id_optional": cve, "campaign_id": spec["campaign_id"], "observation_count": spec["observation_count"],
        "source_reliability": rel, "base_severity": spec["base_severity"],
        "related_alert_count": spec["related_alert_count"], "incident_confirmed": incident,
        "synthetic_label": SYNTHETIC_LABEL,
    }


def demo_specs():
    """The fixed, documented demo scenario THR-2026-001..003 (campaign CMP-2026-001)."""
    common = dict(category="PHISHING", threat_name="Synthetic Credential Phishing Campaign",
                  source_name="Security Vendor", base_severity="HIGH", confidence=85, observation_count=8,
                  related_alert_count=1, cluster_size=3, status="MONITORING", campaign_id="CMP-2026-001",
                  first_seen=date(2026, 9, 12), last_seen=REFERENCE_DATE, region="Global",
                  timestamp=datetime.combine(REFERENCE_DATE, datetime.min.time()).replace(hour=9))
    return [
        {**common, "indicator_type": "DOMAIN", "indicator_value": "login-check.invalid",
         "description": f"{SYNTHETIC_LABEL}. Fictional credential-phishing lure domain. Indicator appears in multiple synthetic phishing observations."},
        {**common, "indicator_type": "IP", "indicator_value": "198.51.100.25",
         "description": f"{SYNTHETIC_LABEL}. Fictional infrastructure associated with the demo phishing campaign."},
        {**common, "indicator_type": "URL", "indicator_value": "https://login-check.invalid/session/verify",
         "description": f"{SYNTHETIC_LABEL}. Fictional lure URL for the demo phishing campaign. Never visit it."},
    ]


def generate_dataset(n_records=2100, seed=42):
    rng = random.Random(seed)
    ind = SafeIndicators(rng)
    for s in demo_specs():
        ind.used.add(s["indicator_value"])
    vulns = generate_vulnerabilities(rng)
    cve_pool = [v["cve_id"] for v in vulns]
    vuln_by_cve = {v["cve_id"]: v for v in vulns}

    specs = demo_specs()
    campaign_no = 2
    source_names = list(SOURCES)
    while len(specs) < n_records:
        category = rng.choices(CATEGORIES, weights=CATEGORY_WEIGHT)[0]
        size = min(rng.choices([1, 2, 3, 4, 5, 6, 8], weights=[34, 22, 16, 11, 8, 5, 4])[0], n_records - len(specs))
        cid = f"CMP-2026-{campaign_no:03d}"
        campaign_no += 1
        base_last = REFERENCE_DATE - timedelta(days=int(rng.expovariate(1 / 55)) % 180)
        window = rng.randint(1, 14)
        name = rng.choice(NAMES[category])
        sev = rng.choices(SEVERITIES, weights=SEV_WEIGHTS.get(category, DEFAULT_SEV_WEIGHTS))[0]
        for _ in range(size):
            itype = rng.choice(TYPE_CHOICES[category])
            last_seen = min(REFERENCE_DATE, base_last + timedelta(days=rng.randint(0, window)))
            first_seen = last_seen - timedelta(days=rng.randint(0, 25))
            source = rng.choices(source_names, weights=SOURCE_WEIGHTS)[0]
            status = _pick_status(rng, (REFERENCE_DATE - last_seen).days)
            obs = max(1, min(400, int(rng.paretovariate(1.2) * 2)))
            record_ts = datetime.combine(last_seen, datetime.min.time()) + timedelta(seconds=rng.randrange(86400))
            spec = dict(category=category, indicator_type=itype, threat_name=name, source_name=source,
                        indicator_value=ind.make(itype, cve_pool), base_severity=sev, status=status,
                        observation_count=obs, related_alert_count=rng.choices([0, 1, 2, 3], weights=[55, 25, 14, 6])[0],
                        cluster_size=size, campaign_id=cid, first_seen=first_seen, last_seen=last_seen,
                        region=rng.choice(REGIONS), timestamp=record_ts,
                        corroboration=rng.choices([1, 2, 3, 4], weights=[45, 30, 17, 8])[0],
                        validated=rng.random() < (0.7 if source == "Internal SOC" else 0.3),
                        completeness=rng.randint(35, 100))
            specs.append(spec)

    rows = [build_record(rng, ind, i + 1, s, cve_pool, vuln_by_cve) for i, s in enumerate(specs)]
    # A handful of analyst-CONFIRMED incidents (rare on purpose: most indicators are NOT incidents).
    candidates = [r for r in rows if r["source_name"] == "Internal SOC" and r["risk_score"] >= 70
                  and r["status"] in ("UNDER_REVIEW", "MONITORING") and r["threat_id"] > "THR-2026-003"]
    for r in rng.sample(candidates, min(8, len(candidates))):
        r["incident_confirmed"] = 1
    return rows, vulns


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--records", type=int, default=2100)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default=str(ROOT / "data"))
    a = ap.parse_args()
    rows, vulns = generate_dataset(a.records, a.seed)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "threat_intelligence_dataset.csv", rows)
    write_csv(out / "vulnerabilities.csv", vulns)
    print(f"Wrote {len(rows)} threat records and {len(vulns)} vulnerabilities to {out}")
    print(f"All data is {SYNTHETIC_LABEL}.")


if __name__ == "__main__":
    main()
