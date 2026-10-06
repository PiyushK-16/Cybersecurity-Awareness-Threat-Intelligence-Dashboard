# 06 - Resume, LinkedIn, future work, interview prep

## A. Resume bullets
- Built a defensive Cybersecurity Awareness & Threat Intelligence Dashboard (Python, Flask, SQLite, JavaScript) that ingests 2,100 synthetic IOC records, validates 6 indicator types, and presents SOC-style analytics across 10 charts.
- Designed explainable risk and confidence scoring, conservative MITRE ATT&CK mapping and alert correlation (959 raw alerts reduced to 738), and context-aware CVE prioritisation, backed by 40 automated tests.
- Delivered a 15-module awareness center and 32-question quiz with educational scoring, personalised learning recommendations and an executive summary; secured the API with RBAC, rate limiting, CSP and audit logging.

## B. Two-line description
A defensive SOC-style threat-intelligence dashboard with explainable risk/confidence scoring, ATT&CK mapping and alert correlation, paired with a security awareness center and quiz. Runs fully offline on synthetic data and never contacts any indicator.

## C. LinkedIn project description
I built a **Cybersecurity Awareness & Threat Intelligence Dashboard** to practise how defenders turn raw indicators into decisions. It ingests synthetic IOCs (documentation-range IPs, .invalid domains, random hashes), validates and normalises them, scores **risk and confidence separately**, maps behaviour to **MITRE ATT&CK only when evidence supports it**, correlates related indicators into clusters, and merges duplicate alerts to reduce alert fatigue. A vulnerability module shows why CVSS alone should not set patch priority. For people, an Awareness Center and quiz give an educational score and learning recommendations. The platform distinguishes observation, indicator, alert, threat and incident, so a match is never presented as a confirmed compromise. Python | Flask | SQLite | JavaScript | pytest. Defensive and synthetic by design.

## D. Skills demonstrated
Cybersecurity, cyber threat intelligence, SOC triage, IOC analysis and validation, MITRE ATT&CK, vulnerability management and prioritisation, risk and confidence scoring, threat correlation, alert management, security awareness training, incident-response concepts, secure API design (RBAC, rate limiting, input validation, XSS defence), Python, SQL/SQLite, REST APIs, data visualisation, automated testing, Git/GitHub, technical documentation.

## E. GitHub description
Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.

## Future improvements (all defensive)
Authorised live threat-feed integration; STIX/TAXII concepts and import; SIEM and SOAR integration; CVE feed integration; CISA KEV awareness; EPSS-style likelihood in prioritisation; threat-feed deduplication; IOC expiration/ageing; learned confidence models; automated enrichment from approved sources; graph-based clustering; ATT&CK Navigator layer export; email-security, endpoint and cloud-security telemetry; threat-hunting workbook; richer executive reports; role-based dashboards; Docker deployment; CI/CD with the test suite; centralised logging.

## Interview preparation (10 questions)

**1. Explain your project.**
I built a defensive dashboard that does two jobs. For analysts it takes synthetic threat indicators through ingestion, validation, scoring, ATT&CK mapping, correlation and alerting, then shows them in a SOC-style dashboard. For regular users it has an awareness center and a 32-question quiz. Everything runs on synthetic data, offline, and nothing ever connects to an indicator. The part I care most about is the wording: the system separates observation, indicator, alert, threat and incident, and keeps risk apart from confidence, so a match is never presented as a confirmed attack.

**2. What is threat intelligence and which types does your project cover?**
It is analysed information about threats that supports defensive decisions. The four types are strategic, tactical, operational and technical. My project is mainly technical (the indicators) and tactical (ATT&CK mapping), with an awareness angle, and a small strategic piece in the executive summary written for non-technical readers.

**3. What is an IOC and why is a match not a confirmed compromise?**
An IOC is an observable artifact like an IP, domain, URL or hash linked to malicious activity. But indicators go stale, IPs and cloud hosting are shared with benign users, and context can be missing. So in my dashboard a match only creates an indicator or alert for an analyst to validate; only an analyst can mark a record as an incident, and only 8 of my 2,100 records are.

**4. What is the difference between risk and confidence?**
Risk is how concerning something may be; confidence is how much I trust the intelligence. I compute them separately. For example risk 90 with confidence 25 means potentially serious but weak evidence, so validate first, while risk 70 with confidence 95 is solid intelligence with meaningful risk. I added a specific alert type for high risk with low confidence for exactly that case.

**5. How does your enrichment work?**
`enrich_indicator()` validates and normalises the input, then looks it up in my SQLite database only. It returns first and last seen, categories, risk, severity, confidence, source and its reliability grade, related alerts, related indicators from the same campaign, ATT&CK mappings and analyst notes, plus a plain-language interpretation. If it is not found, it says that does not mean the indicator is safe.

**6. How did you use MITRE ATT&CK?**
I mapped a record only when the category and indicator type are a justified pair, confidence is at least 50, and it is not a false positive. So phishing with a domain lure maps to Initial Access, Spearphishing Link, T1566.002, while many records stay unmapped. About 58% have no mapping, which is intentional. I also noted that ATT&CK changes over time, so IDs should be re-verified before publishing.

**7. How does your vulnerability prioritisation differ from using CVSS?**
CVSS is technical severity in the abstract. My priority score uses CVSS 35%, asset criticality 20%, exposure 20%, exploitation evidence 20% and business impact 5%. In my tests a CVSS 9.8 on an isolated test asset comes out P4, while a CVSS 8.1 on an internet-facing critical system with proof-of-concept evidence comes out P1. All CVE IDs are fictional (CVE-2099-*).

**8. What does threat correlation do and what are its limits?**
It groups records that share a campaign ID, or for records without one, the same category in a time window, into related threat clusters. I found 513 clusters. That shows relationship and shared evidence, but not attribution: it does not prove who is behind the activity, and shared infrastructure can cause false links.

**9. Walk me through your SOC workflow and how you reduced alert fatigue.**
A Tier 1 analyst takes an alert from the queue, validates the indicator, reads enrichment, risk and confidence, checks related indicators and ATT&CK, checks authorised logs, then escalates, monitors, resolves or marks a false positive and documents it in notes. To reduce fatigue, `correlate_alerts()` merges duplicates for the same indicator within a window; I tested that 100 identical alerts become one alert with an observation count of 100, and on the dataset 959 raw alerts became 738.

**10. How do you handle false positives and what are the limitations of your project?**
False positives can come from shared IPs, changed domain ownership, stale indicators or benign cloud hosting. In my tool a false-positive status stops alert generation, drops the record to observation and removes its ATT&CK mapping. The limits are that the data is synthetic, the weights are illustrative and not calibrated against real incidents, SQLite and the in-memory rate limiter suit a single user, and there are no live feeds. I would validate weights with real, authorised data next.
