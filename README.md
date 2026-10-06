# Cybersecurity Awareness & Threat Intelligence Dashboard

> This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.

## Overview
A SOC-style dashboard that ingests **synthetic** threat intelligence, validates and scores it, maps it to MITRE ATT&CK where justified, correlates related indicators, raises de-duplicated alerts, and pairs all of that with an interactive **Cybersecurity Awareness Center** and quiz. It runs fully offline: no API keys, no internet, no contact with any indicator.

## Problem statement
Raw indicators are noisy, can be stale or benign, and are easily mistaken for proof of compromise. Alert floods cause fatigue, and users need simple, practical security guidance.

## Objectives
Safe synthetic CTI platform - separate **risk** from **confidence** - separate **observation / indicator / alert / threat / incident** - reduce alert noise - prioritise CVEs by context - teach awareness - document and test everything.

## Cybersecurity relevance
Mirrors daily work of SOC analysts, threat-intelligence analysts, vulnerability analysts and awareness teams (see `docs/01_CONCEPTS.md`).

## Features
- 2,100 synthetic threat records + 60 fictional CVEs (`CVE-2099-*`)
- IOC validation (IPv4/IPv6, domain, URL, MD5/SHA-1/SHA-256 format, sender domain, CVE) and lookup-only search
- Enrichment, risk score, confidence score, source reliability (A-D)
- Conservative ATT&CK mapping, technique drill-down
- Correlation clusters, alert engine, alert de-duplication
- Context-aware vulnerability prioritisation
- 10 dashboard charts, filterable threat feed, threat detail + timeline, analyst notes
- Executive summary for non-technical readers
- 15 awareness modules, 32-question quiz, awareness score and recommendations
- 40 automated tests

## Architecture
```
Synthetic CSV -> Ingestion -> Normalise -> Validate -> Enrich -> Risk+Confidence -> Correlate
   -> Threat DB | Alert engine | ATT&CK mapping -> SOC dashboard -> Analyst
Awareness content -> Modules -> Quiz -> Awareness score -> Recommendations
```
Details: `docs/02_ARCHITECTURE_DB_API.md`

## Technology stack
Python 3.10+, Flask, SQLite, HTML/CSS/JavaScript, Chart.js (vendored in `frontend/js/vendor`), pytest.

## Threat intelligence / IOC / enrichment
Types: strategic, tactical, operational, technical (this project: technical + tactical + awareness). **An IOC match is not a confirmed compromise.** Lifecycle: Observed -> Validated -> Enriched -> Scored -> Investigated -> Monitored -> Closed. Enrichment uses local data only.

## Scoring
**Risk** = severity 30% + confidence 25% + recency 15% + observations 10% + source reliability 10% + context 10% (0-100: 0-20 Informational, 21-40 Low, 41-60 Medium, 61-80 High, 81-100 Critical).
**Confidence** = source reliability 35% + corroboration 25% + freshness 20% + analyst validation 10% + completeness 10%.
Risk 90 / confidence 25 = potentially serious but weakly evidenced. High risk is not confirmed compromise.

## Correlation, ATT&CK, vulnerabilities, alerts, SOC workflow
- Records sharing a campaign form a **related threat cluster** (relationship, not attribution).
- ATT&CK mapping only when category + indicator type fit and confidence >= 50.
- Vulnerability priority = CVSS 35% + asset criticality 20% + exposure 20% + exploitation evidence 20% + business impact 5%.
- 100 identical alerts in 5 minutes become 1 alert with `observation_count = 100`.
- Tier 1 workflow: detect -> validate -> enrich -> score -> triage -> investigate -> escalate/monitor/resolve/false positive -> document.

## Awareness center, quiz, executive dashboard
15 modules (phishing, passwords, MFA, social engineering, safe browsing, Wi-Fi, updates, ransomware, USB, privacy, mobile, remote work, cloud accounts, incident reporting, AI scams). Quiz score is **educational only**. Executive view summarises landscape, priorities and awareness trend.

## Installation
```bash
python -m venv venv
venv\Scripts\activate        # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python data/generate_threat_data.py
python backend/init_db.py
python backend/app.py        # open http://127.0.0.1:5000
```
The CSVs are already included; regenerate any time (`--records 3000 --seed 1`).

## Usage
Dashboard tabs: Overview, Threat feed, Indicator search (try `198.51.100.25`), Alerts, ATT&CK, Vulnerabilities, Executive summary. Demo scenario: `THR-2026-001` (`login-check.invalid`). To write notes or change alert status, paste the analyst key (see `.env.example`) in the left panel.

## API documentation
See `docs/02_ARCHITECTURE_DB_API.md` (all 16 endpoints with request, response, validation, auth, status codes). Example:
```bash
curl "http://127.0.0.1:5000/api/indicators/search?q=198.51.100.25"
curl -X PUT http://127.0.0.1:5000/api/alerts/ALR-000001/status -H "Content-Type: application/json" -H "X-API-Key: <analyst-key>" -d '{"status":"INVESTIGATING"}'
```

## Testing
`python -m pytest -v` - 40 tests; matrix in `docs/TEST_REPORT.md` (regenerate with `python tests/generate_test_report.py`).

## Security & privacy
No connections to indicators, defanged display, input validation, XSS defences (sanitiser, `textContent`, CSP), API-key RBAC, rate limiting, audit log, secrets in `.env`, minimal personal data. See `docs/03_SECURITY_AND_INCIDENT_RESPONSE.md`.

## Results
2,100 records ingested, 0 rejected - 513 clusters - 959 raw alerts reduced to 738 - 8 analyst-confirmed incidents (rare by design) - 40/40 tests pass.

## Limitations
Synthetic data; illustrative (uncalibrated) weights; single-user SQLite; demo API keys; in-memory rate limiter; rule-based ATT&CK mapping; no live feeds. Verify ATT&CK IDs at attack.mitre.org before publishing.

## Future improvements
STIX/TAXII, SIEM/SOAR, CISA KEV, EPSS-style prioritisation, IOC expiry, Navigator export, Docker/CI, role-based dashboards (see `docs/06_RESUME_FUTURE_INTERVIEW.md`).

## Screenshots
Sample captures are in `screenshots/`; replace them with your own using the checklist in `docs/04_RUNBOOK_GITHUB_PROOF.md`.

## Learning outcomes
IOC analysis, risk vs confidence, ATT&CK, vulnerability prioritisation, correlation, alert fatigue, secure API design, testing, documentation, security awareness.

## Ethical disclaimer
Defensive education only. Do not use this code to scan, probe or attack systems. All indicators are fictional, in reserved documentation ranges.

## Author
*Your name - course - college.*
