"""Static, defensive knowledge base: category descriptions and recommended actions.
No exploitation details - only recognition, impact and defensive controls."""

CATEGORIES = [
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", "WEB THREATS", "NETWORK THREATS",
    "VULNERABILITY EXPOSURE", "SOCIAL ENGINEERING", "DATA EXPOSURE", "ACCOUNT SECURITY",
]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
ALERT_STATUSES = ["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"]

CATEGORY_INFO = {
    "PHISHING": {
        "description": "Deceptive messages that try to trick people into revealing credentials or taking unsafe actions.",
        "indicators": "Look-alike sender domains, lure URLs, urgent wording, unexpected attachments.",
        "impact": "Credential loss, account takeover, fraud, malware delivery.",
        "controls": "Email filtering, DMARC/SPF/DKIM, MFA (ideally phishing-resistant), URL rewriting.",
        "awareness": "Verify requests through a trusted channel; report suspicious emails."},
    "MALWARE": {
        "description": "Malicious software intended to damage systems or steal data.",
        "indicators": "File hashes, command-and-control domains/IPs, unusual process behaviour.",
        "impact": "Data theft, system disruption, persistence of unauthorised access.",
        "controls": "Endpoint protection, application allow-listing, patching, least privilege.",
        "awareness": "Do not open unexpected attachments; install software only from trusted sources."},
    "RANSOMWARE": {
        "description": "Malware that encrypts or locks data and demands payment, often with data-theft extortion.",
        "indicators": "Known sample hashes, associated infrastructure, mass file-change alerts.",
        "impact": "Operational downtime, data loss, extortion, recovery cost.",
        "controls": "Offline/immutable backups, patching, segmentation, MFA, tested incident-response plan.",
        "awareness": "Report odd file behaviour at once; never ignore backup hygiene."},
    "CREDENTIAL THREATS": {
        "description": "Attempts to obtain or reuse login credentials (stuffing, spraying, theft).",
        "indicators": "Bursts of failed logins, logins from unusual sources, leaked-credential reports.",
        "impact": "Account compromise, lateral access, fraud.",
        "controls": "MFA, unique passwords, lockout/rate-limits, breached-password checks.",
        "awareness": "Use a password manager; never reuse passwords."},
    "WEB THREATS": {
        "description": "Risks from malicious or compromised web content and attacks on public web applications.",
        "indicators": "Suspicious URLs, abnormal request patterns, known-bad web infrastructure.",
        "impact": "Drive-by compromise, data exposure, defacement.",
        "controls": "Secure coding, WAF, patching, secure headers, DNS/web filtering.",
        "awareness": "Check URLs before clicking; keep browsers updated."},
    "NETWORK THREATS": {
        "description": "Suspicious network activity such as scanning, probing or unusual traffic patterns.",
        "indicators": "Repeated connection attempts, unusual ports, traffic to unexpected regions.",
        "impact": "Reconnaissance for later attacks, service disruption.",
        "controls": "Firewalls, segmentation, IDS/IPS, minimal exposed services, monitoring.",
        "awareness": "Report unexplained network slowdowns or unknown devices."},
    "VULNERABILITY EXPOSURE": {
        "description": "Systems running software with known weaknesses (CVEs) that could be abused if unpatched.",
        "indicators": "CVE identifiers on asset inventory, scanner findings, vendor advisories.",
        "impact": "Unauthorised access, data exposure, service disruption.",
        "controls": "Asset inventory, risk-based patching, compensating controls, exposure reduction.",
        "awareness": "Install updates promptly; do not postpone security patches."},
    "SOCIAL ENGINEERING": {
        "description": "Manipulating people (phone, chat, email, in person) into bypassing security.",
        "indicators": "Impersonation, pressure to act fast, requests to bypass process.",
        "impact": "Fraud, unauthorised access, data disclosure.",
        "controls": "Verification procedures, callback processes, awareness training.",
        "awareness": "Pause, verify identity through an official channel, then act."},
    "DATA EXPOSURE": {
        "description": "Sensitive data accessible to people who should not see it (misconfiguration, leaks, oversharing).",
        "indicators": "Public storage links, leaked-data mentions, unusual large transfers.",
        "impact": "Privacy harm, regulatory impact, reputational damage.",
        "controls": "Data classification, access reviews, DLP, encryption, secure configuration.",
        "awareness": "Share the minimum data needed; check link-sharing settings."},
    "ACCOUNT SECURITY": {
        "description": "Risks to account integrity: takeover attempts, risky sign-ins, weak recovery paths.",
        "indicators": "Impossible-travel sign-ins, new devices, mailbox-rule changes.",
        "impact": "Account takeover, fraud, data access.",
        "controls": "MFA, conditional access, sign-in monitoring, secure recovery options.",
        "awareness": "Enable MFA and review recent sign-in activity regularly."},
}

COMMON_ACTIONS = [
    "Review related internal logs (authorised sources only) for sightings of this indicator",
    "Check whether any sightings are authorised or benign (shared hosting, security tooling)",
    "Do NOT visit, scan or connect to the indicator - analyse it as data",
    "Document findings in analyst notes and update the status",
]
CATEGORY_ACTIONS = {
    "PHISHING": ["Review email-security telemetry for related senders/links", "Increase phishing awareness for affected groups",
                 "Monitor for related indicators in the same campaign"],
    "MALWARE": ["Check endpoint-protection telemetry for the hash/domain", "Confirm patch and protection coverage"],
    "RANSOMWARE": ["Verify backups are offline/immutable and restorable", "Review segmentation and privileged access"],
    "CREDENTIAL THREATS": ["Review authentication logs for bursts of failures", "Confirm MFA coverage on exposed accounts"],
    "WEB THREATS": ["Review web-proxy/WAF logs", "Confirm public web applications are patched"],
    "NETWORK THREATS": ["Review firewall/IDS logs for the source", "Confirm only required services are exposed"],
    "VULNERABILITY EXPOSURE": ["Identify affected assets and prioritise by exposure and criticality", "Apply patch or compensating control"],
    "SOCIAL ENGINEERING": ["Remind staff of verification procedures", "Review whether impersonated roles need extra controls"],
    "DATA EXPOSURE": ["Review sharing/permission settings", "Assess what data class is involved"],
    "ACCOUNT SECURITY": ["Review sign-in anomalies", "Require password reset/MFA re-enrolment where justified"],
}


def recommended_actions(category: str) -> list[str]:
    return CATEGORY_ACTIONS.get(category, []) + COMMON_ACTIONS
