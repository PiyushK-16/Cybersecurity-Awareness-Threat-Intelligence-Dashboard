# 04 - Run it, demo it, publish it

## Local execution (Windows PowerShell shown first; macOS/Linux in brackets)
```bash
# STEP 1  Unzip the project and open a terminal inside the folder
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard

# STEP 2  Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate            # [macOS/Linux: source venv/bin/activate]

# STEP 3  Install dependencies
pip install -r requirements.txt

# (optional) copy .env.example to .env and set your own API keys
copy .env.example .env           # [cp .env.example .env]

# STEP 4  Generate the synthetic dataset (2,100 records + 60 CVEs)
python data/generate_threat_data.py

# STEP 5  Initialise the database
python backend/init_db.py

# STEP 6  Start the backend (it also serves the frontend)
python backend/app.py

# STEP 7  Frontend: nothing extra needed. Open http://127.0.0.1:5000
#         (Optional separate server: cd frontend && python -m http.server 8000 -> http://127.0.0.1:8000)
```
Run the tests any time: `python -m pytest -v`

Walkthrough in the browser:
8. Open **SOC dashboard** -> Overview (cards, entity stages, 10 charts).
9. **Indicator search** -> `198.51.100.25` (database lookup only).
10. **Threat feed** -> click `THR-2026-001` for the detail page.
11. On the detail page and the **ATT&CK** tab, review the mapping (click `T1566.002`).
12. **Vulnerabilities** tab -> see why priority differs from CVSS.
13. Open **Awareness center** and read the Phishing module.
14. Open **Awareness quiz**, answer, submit.
15. Read your score, weakest areas and recommended modules. To save analyst notes or change alert status, paste the analyst key (default `demo-analyst-key-change-me`, or the value in your `.env`) in the left panel.

## Safe demonstration scenario
| Field | Value |
|---|---|
| Threat | THR-2026-001 "Synthetic Credential Phishing Campaign" |
| Category / indicator | PHISHING / DOMAIN `login-check.invalid` |
| Severity / risk / confidence | HIGH / 78 / 85 |
| First seen / status | 2026-09-12 (synthetic) / MONITORING |
| Related indicators | `198.51.100.25` (THR-2026-002), a lure URL (THR-2026-003), same campaign CMP-2026-001 |
| ATT&CK | Initial Access - Phishing: Spearphishing Link (T1566.002), mapped because confidence >= 50 and a domain lure fits the technique |
| Analyst note | "Indicator appears in multiple synthetic phishing observations." |
| Actions | Review related internal logs; check for authorised sightings; review email-security telemetry; increase phishing awareness; monitor for related indicators |
**Do not visit the domain.** `.invalid` can never resolve, and no code here connects to it.

## GitHub
Repository name: `Cybersecurity-Awareness-Threat-Intelligence-Dashboard`
Description: *Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.*
Topics: cybersecurity, threat-intelligence, cti, soc, ioc, mitre-attack, security-awareness, python, flask, fastapi, vulnerability-management, incident-response, security-analytics, defensive-security
(`fastapi` is a listed topic from your brief - keep it only if you later add a FastAPI version; the code here uses Flask.)

```bash
git init
git branch -M main
git add .gitignore README.md requirements.txt .env.example
git commit -m "Initialize cybersecurity threat intelligence dashboard"
git add data/
git commit -m "Add synthetic threat intelligence dataset"
git add backend/services/ioc_validator.py
git commit -m "Implement IOC validation"
git add backend/services/enrichment_engine.py
git commit -m "Add threat enrichment engine"
git add backend/services/risk_engine.py
git commit -m "Implement risk and confidence scoring"
git add backend/services/correlation_engine.py
git commit -m "Add threat correlation"
git add backend/services/alert_engine.py
git commit -m "Implement security alert engine"
git add backend/services/attack_mapper.py
git commit -m "Add ATT&CK mapping module"
git add backend/services/vulnerability_service.py
git commit -m "Build vulnerability awareness module"
git add backend/ frontend/css frontend/js frontend/threat-dashboard.html frontend/index.html
git commit -m "Create SOC threat dashboard"
git commit --allow-empty -m "Add IOC search functionality"   # or commit the search view separately if you split files
git add frontend/threat-details.html frontend/js/details.js
git commit -m "Build threat investigation view"
git add awareness/ frontend/awareness.html frontend/js/awareness.js
git commit -m "Create cybersecurity awareness center"
git add frontend/quiz.html frontend/js/quiz.js
git commit -m "Add security awareness quiz"
git commit --allow-empty -m "Implement awareness scoring"
git commit --allow-empty -m "Add executive cybersecurity summary"
git add tests/ pytest.ini
git commit -m "Implement automated tests"
git add docs/ screenshots/ reports/ README.md
git commit -m "Complete README and documentation"
git remote add origin https://github.com/<your-username>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
git push -u origin main
```
Tip: honest commits look better than empty ones. If a commit message in your list has no new files, make a real small change first (for example improve a comment) or skip that commit.

## Screenshot checklist (save in `screenshots/`)
| # | Capture | Filename |
|---|---|---|
| 1 | Folder structure | 01_project_folder_structure.png |
| 2 | Architecture diagram | 02_system_architecture.png |
| 3 | Dataset in a spreadsheet | 03_synthetic_threat_dataset.png |
| 4-5 | Dashboard top cards | 04_threat_dashboard_overview.png / 05_total_threat_cards.png |
| 6 | Severity chart | 06_severity_distribution.png |
| 7 | Category chart | 07_threat_category_chart.png |
| 8 | IOC type chart | 08_ioc_type_distribution.png |
| 9 | Timeline | 09_threat_timeline.png |
| 10-11 | Risk and confidence charts | 10_risk_distribution.png / 11_confidence_distribution.png |
| 12-13 | IOC search and result | 12_ioc_search.png / 13_ioc_result.png |
| 14-17 | Detail page, scores, related indicators | 14_threat_detail.png / 15_risk_score.png / 16_confidence_score.png / 17_related_indicators.png |
| 18 | ATT&CK tab | 18_attack_mapping.png |
| 19 | Vulnerabilities | 19_vulnerability_dashboard.png |
| 20-22 | Alerts, investigation, notes | 20_alert_dashboard.png / 21_alert_investigation.png / 22_analyst_notes.png |
| 23-26 | Awareness center, phishing, password/MFA, ransomware | 23_awareness_center.png / 24_phishing_module.png / 25_password_mfa_module.png / 26_ransomware_module.png |
| 27-30 | Quiz, result, category scores, recommendations | 27_quiz.png / 28_quiz_result.png / 29_category_scores.png / 30_learning_recommendations.png |
| 31 | Executive summary | 31_executive_dashboard.png |
| 32 | `pytest -v` output | 32_automated_tests.png |
| 33 | API JSON in browser | 33_api_response.png |
| 34 | DB Browser for SQLite | 34_database_tables.png |
| 35-37 | GitHub commits, repo, README | 35_github_commits.png / 36_github_repository.png / 37_readme_preview.png |
