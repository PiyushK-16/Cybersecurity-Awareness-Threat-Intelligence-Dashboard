# 01 - Concepts (simple + technical)

> Every indicator in this project is **synthetic / demo only**.

## 1. Glossary

| Term | Simple explanation | Technical explanation |
|---|---|---|
| Cybersecurity awareness | Helping people spot and avoid security risks. | Training and behaviour change that reduce human-factor risk (phishing, weak passwords, oversharing). |
| Cyber threat intelligence (CTI) | Organised knowledge about threats that helps defenders decide what to do. | Collected, processed and analysed information about adversaries, infrastructure and behaviours, delivered in a form that supports decisions. |
| IOC (Indicator of Compromise) | A clue that *may* show something bad happened. | An observable artifact (IP, domain, URL, file hash, sender domain) associated with malicious activity. |
| IOA (Indicator of Attack) | A clue about what an attacker is *trying to do right now*. | A behaviour-based signal (e.g. a suspicious sequence of actions) rather than a static artifact. |
| Vulnerability | A weakness that could be abused. | A flaw in design, code or configuration. |
| CVE | A public ID for a known vulnerability. | Common Vulnerabilities and Exposures identifier, format `CVE-YYYY-NNNN+`. (This project uses fictional `CVE-2099-*` IDs.) |
| CVSS | A 0-10 severity score for a vulnerability. | Common Vulnerability Scoring System; describes technical severity, not your business risk. |
| Threat feed | A stream of indicators from a source. | Structured data (CSV, JSON, STIX/TAXII...) published by a vendor, community or internal team. |
| Threat actor (conceptually) | A person or group behind malicious activity. | Used for grouping activity; attribution is hard and often uncertain. This project never attributes. |
| TTP | How an attacker operates. | Tactics, Techniques and Procedures. |
| MITRE ATT&CK | A catalogue of attacker behaviours. | A knowledge base of adversary tactics and techniques used to describe and compare behaviour. |
| Enrichment | Adding useful context to an indicator. | Joining an indicator with first/last seen, categories, scores, related items, ATT&CK mapping and notes. |
| Correlation | Linking related records. | Grouping by shared campaign, category and time window into a *related threat cluster*. |
| Threat hunting | Proactively looking for signs of threats. | Hypothesis-driven search of logs/telemetry (authorised sources) for activity that automated rules missed. |
| SOC | The team/room that watches for and responds to security events. | Security Operations Center: monitoring, triage, investigation, escalation. |

## Workflow implemented

```
Synthetic feed (CSV) -> Collection -> Normalisation -> Validation -> IOC extraction
 -> Classification -> Risk/Confidence scoring -> ATT&CK mapping (only if justified)
 -> Threat database (SQLite) -> Correlation -> Alerts -> SOC dashboard
 -> Awareness module -> Analyst / User
```
Code map: `data/generate_threat_data.py` (feed) -> `services/ingestion.py` (collect/normalise/validate/store) -> `ioc_validator.py` -> `risk_engine.py` -> `attack_mapper.py` -> `correlation_engine.py` -> `alert_engine.py` -> `routes/api.py` -> `frontend/`.

## 2. Awareness vs threat intelligence
*Awareness* helps **people** recognise risks (phishing, passwords, MFA, safe browsing, updates, Wi-Fi, privacy, reporting). *Threat intelligence* helps **defenders** decide using data about threats. This project combines **human defence + technical intelligence**: the same phishing theme appears as an indicator in the SOC view and as a lesson in the Awareness Center.

## 3. Industry relevance
SOCs, banks, cloud companies, IT enterprises, government, e-commerce, healthcare, universities, MSSPs and consultancies all use intelligence dashboards to prioritise alerts and focus defences.

| Role | Skill this project demonstrates |
|---|---|
| SOC analyst | Triage queue, alert correlation, status workflow, notes |
| Cybersecurity analyst | Risk vs confidence reading, defensive actions |
| Threat intelligence analyst | IOC lifecycle, enrichment, source reliability, ATT&CK mapping |
| Incident response analyst | Entity stages (alert -> incident), timeline, IR checklist |
| Security engineer | Validation engine, REST API, RBAC, rate limiting, secure headers |
| Vulnerability analyst | Context-aware CVE prioritisation |
| Security awareness specialist | 15 modules, quiz, personalised recommendations |
| Threat hunter | Search, filters, cluster pivots |

## 4. Types of threat intelligence
- **Strategic** - high-level trends for executives ("ransomware is the top risk to our sector"). Implemented as the *Executive summary*.
- **Tactical** - attacker TTPs ("campaigns use look-alike login domains"). Implemented through ATT&CK mapping.
- **Operational** - details about specific campaigns/timing. Partly via clusters and timelines.
- **Technical** - concrete indicators (IPs, hashes, domains). The IOC database.

This student project focuses on **technical + tactical + awareness-oriented** intelligence.

## 6. IOCs, limits and lifecycle
Limitations: an IOC can become **stale**, be **shared by benign infrastructure**, or lack **context**. Therefore **IOC match != confirmed compromise**.

Lifecycle: Observed -> Validated -> Enriched -> Scored -> Investigated -> Monitored -> Expired/Closed.

The dashboard separates five words: **Observation** (seen) < **Indicator** (validated artifact) < **Alert** (crossed a rule) < **Threat** (corroborated, related, high-confidence) < **Incident** (analyst-confirmed). In the data only 8 of 2,100 records are incidents, on purpose.

## 10-12. Risk, confidence, source reliability
**Risk score (0-100)** - how concerning something may be: severity 30%, confidence 25%, recency 15%, observation frequency 10%, source reliability 10%, context/correlation 10%. Classes: 0-20 Informational, 21-40 Low, 41-60 Medium, 61-80 High, 81-100 Critical.
**Confidence score (0-100)** - how much we trust the intelligence: source reliability 35%, corroboration 25%, freshness 20%, analyst validation 10%, context completeness 10%.

| Risk | Confidence | Reading |
|---|---|---|
| 90 | 25 | Potentially serious, but evidence quality is weak - validate first. |
| 70 | 95 | High-confidence intelligence with meaningful risk. |

**Source reliability:** A Highly reliable (Internal SOC) - B Usually reliable (Security Vendor, Research Report) - C Fairly reliable (Public Threat Feed, Community Submission) - D Unknown (Unknown Source). A reliable *source* can still publish a weak *item*, so reliability feeds confidence but is not the same thing.
**High risk does not mean confirmed compromise.**

## 13. Threat categories (defensive view)
Each category's description, common indicators, impact, controls and awareness advice are in `backend/services/knowledge.py` and shown on the threat-detail page. Categories: Phishing, Malware, Ransomware, Credential Threats, Web Threats, Network Threats, Vulnerability Exposure, Social Engineering, Data Exposure, Account Security. No exploitation instructions are included anywhere.

## 14-15. MITRE ATT&CK
**Tactic** = *why* (goal, e.g. Initial Access). **Technique** = *how* (e.g. Phishing). **Sub-technique** = a more specific way (e.g. Spearphishing Link, T1566.002). An IOC tells you **what** was seen; ATT&CK helps describe **how behaviour relates** to known techniques.
Rule used: map only when category + indicator type are a justified pair **and** confidence >= 50 **and** not a false positive; otherwise no mapping (about 58% of records stay unmapped). IDs used: T1566, T1566.002, T1598, T1110, T1110.004, T1078, T1204, T1071, T1486, T1190, T1046, T1567. ATT&CK is updated regularly - re-check names/IDs at attack.mitre.org before publishing.

## 16-17. Vulnerabilities and prioritisation
Patch = vendor fix. Exploit (concept) = code/technique that abuses a flaw. Zero-day (concept) = flaw with no patch available yet.
CVSS alone is not enough: **CVSS + asset criticality + exposure + exploitation evidence + business context = better priority.**
`calculate_vulnerability_priority()` weights 35/20/20/20/5. Example: a CVSS 9.8 on an isolated test asset scores about 34 (P4) while a CVSS 8.1 on an internet-facing critical system with demo proof-of-concept evidence scores about 85 (P1).

## 18. Correlation
Records sharing a campaign ID (or, for records without one, category + first-seen window) form a **related threat cluster** (513 clusters in the demo data). Correlation shows relationship/evidence - **not attribution**.

## 31-32. Alerts and alert fatigue
Triggers: risk + confidence thresholds, high-priority vulnerability, repeated observations (>= 50), correlated cluster (>= 4). **Alert fatigue** = so many alerts that real ones are missed. `correlate_alerts()` merges duplicates: 100 identical alerts in 5 minutes become 1 alert with `observation_count = 100`. On the demo data 959 raw alerts become 738.

## 45. False positives and limitations
An IP can be shared by many users; domains change owners; cloud infrastructure hosts benign and malicious services; indicators go stale; feeds disagree; confidence varies; correlation is not attribution. Threat intelligence should **support analyst decisions**, not replace them.
