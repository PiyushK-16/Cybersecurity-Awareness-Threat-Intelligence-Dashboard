# Cybersecurity Awareness & Threat Intelligence Dashboard - Project Report

*(Fill in your name, course, college and date. Figures below come from the demo data in this repository.)*

## Abstract
This project builds a defensive dashboard that combines cyber threat intelligence (CTI) analysis with security awareness training. It generates 2,100 synthetic threat records and 60 fictional vulnerabilities, validates and normalises indicators, scores each record for risk and confidence, maps behaviour to MITRE ATT&CK only when justified, correlates related records, produces de-duplicated alerts, and presents everything in a SOC-style dashboard. A parallel Awareness Center offers 15 modules and a 32-question quiz with an educational score and learning recommendations. All data is synthetic and no component contacts any indicator.

## 1. Introduction
Organisations receive large volumes of threat data but have limited analyst time. People are also a major attack surface. This project demonstrates both sides: technical intelligence for defenders and awareness for users.

## 2. Problem statement
Raw indicators are noisy, can be stale or benign, and are often mistaken for proof of compromise. Alert floods cause fatigue. Users lack simple guidance. The project explores how scoring, correlation and education can improve decisions safely.

## 3. Objectives
Build a safe synthetic CTI platform; separate risk from confidence; distinguish observation/indicator/alert/threat/incident; reduce alert noise; prioritise vulnerabilities by context; teach awareness; document and test everything.

## 4. Cybersecurity awareness
Teaching people to recognise phishing, protect passwords, use MFA, browse safely, patch, secure Wi-Fi, protect privacy and report incidents. Implemented as 15 modules and a quiz.

## 5. Cyber threat intelligence
Collecting and analysing information about threats to support defensive decisions. Types: strategic, tactical, operational, technical (see docs/01).

## 6. Threat intelligence types
This project emphasises technical (indicators), tactical (ATT&CK) and awareness-oriented intelligence, with a small strategic layer (executive summary).

## 7. IOC and IOA concepts
IOCs are static artifacts (IP, domain, URL, hash, sender domain, CVE). IOAs describe behaviour. The project handles IOCs; ATT&CK mapping gives a behavioural view.

## 8. Threat intelligence lifecycle
Observed -> Validated -> Enriched -> Scored -> Investigated -> Monitored -> Closed. In code: ingestion (observe/validate), enrichment, scoring, alerts/triage, status workflow.

## 9. Proposed system
Flask REST API, SQLite database, vanilla JS frontend, Chart.js charts (vendored for offline use).

## 10. Architecture
See docs/02. Layers: ingestion, validation, enrichment, scoring, correlation, alerting, ATT&CK mapping, storage, API, UI, plus the awareness path.

## 11. Synthetic dataset
2,100 records in 513 clusters (campaigns of 1-8 indicators) plus the fixed demo campaign. IPs from documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32); domains under example.com/.org/.net and `.invalid`; random hex hashes labelled SYNTHETIC / DEMO ONLY; fictional CVE-2099-* IDs. Severity mix: 1,167 Medium, 766 High, 141 Low, 26 Critical. 201 records are false positives; 8 are analyst-confirmed incidents.

## 12. IOC validation
`validate_indicator()` checks syntax for IPv4, IPv6, domain, URL, MD5/SHA-1/SHA-256 format, email sender domain and CVE; it normalises (lower-case, compressed IPv6, URL fragment removal) and accepts defanged input. It never checks maliciousness. In ingestion all 2,100 rows passed.

## 13. Threat enrichment
`enrich_indicator()` joins a normalised indicator with scores, categories, first/last seen, alerts, related indicators, ATT&CK mappings and notes - using local data only.

## 14. Risk scoring
Weighted score: severity 30%, confidence 25%, recency 15%, observations 10%, source reliability 10%, context 10%. Classified Informational to Critical. High risk is not confirmed compromise.

## 15. Confidence scoring
Source reliability 35%, corroboration 25%, freshness 20%, analyst validation 10%, completeness 10%. Risk 90 / confidence 25 means serious but weakly evidenced.

## 16. Source reliability
Six synthetic sources graded A-D. Reliability of a source differs from confidence in an individual item.

## 17. Threat correlation
Shared campaign IDs (or category + time window as a weak link) form related clusters. This indicates relationship, not attribution.

## 18. MITRE ATT&CK
Twelve technique IDs are mapped through a conservative table. 1,216 of 2,100 records have a mapping; the other 58% are deliberately left unmapped because they lack enough evidence or confidence.

## 19. Vulnerability awareness
Context-aware priority combining CVSS (35%), asset criticality (20%), exposure (20%), exploitation evidence (20%) and business impact (5%). A CVSS 9.8 isolated test asset ranks P4; a CVSS 8.1 internet-facing critical system with proof-of-concept evidence ranks P1.

## 20. Alert management
Triggers: risk/confidence thresholds, repeated observations, correlated clusters, high-priority vulnerabilities, and a "high risk, low confidence" validation alert. Correlation reduced 959 raw alerts to 738.

## 21. SOC workflow
Feed -> detect -> validate -> enrich -> score -> alert -> triage -> correlate -> investigate -> escalate/monitor/resolve/false-positive -> document. The UI supports status changes and analyst notes.

## 22. Awareness center
15 modules, each with what it is, why it matters, warning signs, safe practices and what to do if something happens. Includes passkeys/WebAuthn, AI-enabled scams and safe fictional phishing examples.

## 23. Quiz system
32 questions over 10 categories; answers never leave the server until submission. The score is educational: 0-40 Needs Improvement, 41-60 Basic, 61-80 Good, 81-100 Strong. Recommendations: below 50 complete the module, 50-74 review, 75 and above none.

## 24. Executive dashboard
Plain-language summary: landscape narrative, High/Critical count, top categories, top vulnerability areas, awareness trend, top weaknesses and recommended priorities.

## 25. Testing
40 automated pytest tests (docs/TEST_REPORT.md) covering validation, scoring, correlation, alerts, ATT&CK, vulnerabilities, API validation, RBAC, persistence, empty dataset and quiz logic. All pass.

## 26. Security
No outbound connections to indicators, defanged display, XSS defences (sanitiser, textContent, CSP), API-key RBAC, rate limiting, audit log, environment-based secrets, minimal personal data.

## 27. Results
2,100 records ingested with 0 rejections; dashboard renders 10 charts; demo scenario THR-2026-001 reproduces risk 78 / confidence 85 / HIGH / MONITORING; all 40 tests pass.

## 28. Limitations
Synthetic data (no real-world validation); weights are illustrative, not calibrated; single-user SQLite; demo API keys; in-memory rate limiter; ATT&CK mapping is rule-based; no live feeds; quiz is small; the demo clock is fixed.

## 29. Future scope
Authorised live feeds (STIX/TAXII), SIEM/SOAR integration, CISA KEV and EPSS-style prioritisation, IOC expiration, better confidence models, ATT&CK Navigator export, Docker/CI, role-based dashboards.

## 30. Conclusion
The project shows that safe, explainable defensive tooling can combine threat intelligence and awareness, and that careful wording (risk vs confidence, indicator vs incident) matters as much as code.
