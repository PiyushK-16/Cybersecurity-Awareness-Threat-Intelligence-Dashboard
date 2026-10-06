"""MITRE ATT&CK mapping - only when there is enough context.

We map a record only if (a) the category + indicator type pair appears in the table below,
(b) confidence >= MIN_CONFIDENCE and (c) the record is not a false positive.
Otherwise we return None: NO MAPPING IS BETTER THAN A GUESS.

IDs below are well-known Enterprise ATT&CK techniques. ATT&CK is updated regularly,
so verify names/IDs at https://attack.mitre.org before publishing your report.
IOC = WHAT artifact was seen. ATT&CK = HOW behaviour may relate to adversary technique.
"""
MIN_CONFIDENCE = 50

# (category, indicator_type) -> (tactic, technique name, technique id)
_MAP = {
    ("PHISHING", "URL"): ("Initial Access", "Phishing: Spearphishing Link", "T1566.002"),
    ("PHISHING", "DOMAIN"): ("Initial Access", "Phishing: Spearphishing Link", "T1566.002"),
    ("PHISHING", "EMAIL_DOMAIN"): ("Initial Access", "Phishing", "T1566"),
    ("SOCIAL ENGINEERING", "EMAIL_DOMAIN"): ("Reconnaissance", "Phishing for Information", "T1598"),
    ("SOCIAL ENGINEERING", "DOMAIN"): ("Reconnaissance", "Phishing for Information", "T1598"),
    ("CREDENTIAL THREATS", "IP"): ("Credential Access", "Brute Force: Credential Stuffing", "T1110.004"),
    ("CREDENTIAL THREATS", "DOMAIN"): ("Credential Access", "Brute Force", "T1110"),
    ("ACCOUNT SECURITY", "IP"): ("Initial Access", "Valid Accounts", "T1078"),
    ("ACCOUNT SECURITY", "EMAIL_DOMAIN"): ("Initial Access", "Valid Accounts", "T1078"),
    ("MALWARE", "FILE_HASH"): ("Execution", "User Execution", "T1204"),
    ("MALWARE", "DOMAIN"): ("Command and Control", "Application Layer Protocol", "T1071"),
    ("MALWARE", "IP"): ("Command and Control", "Application Layer Protocol", "T1071"),
    ("RANSOMWARE", "FILE_HASH"): ("Impact", "Data Encrypted for Impact", "T1486"),
    ("WEB THREATS", "URL"): ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    ("WEB THREATS", "IP"): ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    ("VULNERABILITY EXPOSURE", "CVE_ID"): ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    ("NETWORK THREATS", "IP"): ("Discovery", "Network Service Discovery", "T1046"),
    ("DATA EXPOSURE", "URL"): ("Exfiltration", "Exfiltration Over Web Service", "T1567"),
    ("DATA EXPOSURE", "DOMAIN"): ("Exfiltration", "Exfiltration Over Web Service", "T1567"),
}


def map_to_attack(category: str, indicator_type: str, confidence_score: float, status: str = "NEW") -> dict | None:
    """Return a mapping dict or None when evidence is insufficient."""
    if status == "FALSE_POSITIVE" or confidence_score < MIN_CONFIDENCE:
        return None
    hit = _MAP.get((category, indicator_type))
    if not hit:
        return None
    tactic, technique, tid = hit
    return {
        "tactic": tactic, "technique": technique, "technique_id": tid,
        "rationale": f"Category {category} with a {indicator_type} indicator and confidence "
                     f">= {MIN_CONFIDENCE}. Analyst should confirm before reporting.",
    }
