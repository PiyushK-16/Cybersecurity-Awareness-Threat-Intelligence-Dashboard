# 02 - Architecture, database, API, stack, folders

## System architecture
```
Synthetic data (CSV) -> Ingestion -> Normalisation -> IOC validation
   -> Enrichment -> Risk + Confidence -> Correlation
   -> [Threat DB]  [Alert engine]  [ATT&CK mapping]
   -> SOC dashboard -> Analyst
Parallel: Awareness content -> Learning modules -> Quiz -> Awareness score -> Recommendations
```

## SOC workflow (Tier 1)
Threat feed -> IOC detected -> Validation -> Enrichment -> Risk + confidence -> Alert -> SOC queue -> Analyst triage -> Correlation -> Investigation -> **Escalate / Monitor / Resolve / False positive** -> Documentation.
A Tier 1 analyst picks the highest-priority alert, validates the indicator, reads risk *and* confidence, checks related indicators and ATT&CK, checks authorised internal logs, decides the outcome and records a note. In the app: Alerts tab -> open threat -> read detail -> set status -> add note.

## Stack recommendation
| Option | Stack | Verdict |
|---|---|---|
| A (used) | HTML/CSS/JS + Flask + SQLite + Chart.js | Best for a beginner: one command, no database server, works offline, easy to explain. |
| B | React + FastAPI + PostgreSQL | Good next step for portfolio growth. |
| C | + Redis + Docker | Deployment practice; overkill for the course submission. |
Pandas is not required here; the generator uses only the standard library, so there is less to install.

## Database (SQLite)
Tables: `sources`, `threats`, `indicators`, `attack_mappings`, `vulnerabilities`, `alerts`, `analyst_notes`, `awareness_modules`, `quiz_results`, `audit_log`.
Relationships: `threats.source_id -> sources`; `indicators`, `attack_mappings`, `alerts`, `analyst_notes` -> `threats(threat_id)` (cascade delete); `threats.campaign_id` groups related records; `threats.cve_id` joins `vulnerabilities.cve_id` (logical link).
Indexes: severity, category, status, risk, last_seen, campaign_id, indicator `normalized_value` (fast IOC search), alert status/threat, ATT&CK technique id.
Extra columns beyond the brief: `base_severity`, `observation_count`, `entity_stage`, `incident_confirmed`, `campaign_id`, `author`, plus an `audit_log` table.

## REST API
Auth: none for reads (demo). Writes need header `X-API-Key`. Roles: **analyst** (notes, alert status) and **admin** (create/update threats, plus analyst rights). Errors are JSON `{"error": "..."}` - never a stack trace.

| Method + endpoint | Request | Response | Validation | Auth | Status codes |
|---|---|---|---|---|---|
| GET /api/threats | Query: severity, category, indicator_type, status, entity_stage, min_risk, max_risk, min_confidence, date_from, date_to, q, sort (newest/risk/confidence/observed), page, per_page (max 100) | `{total,page,per_page,items[]}` | Integers, dates, sort whitelist | none | 200, 400 |
| GET /api/threats/{id} | - | Scores, related indicators, alerts, ATT&CK, CVE, notes, timeline, actions | id lookup | none | 200, 404 |
| POST /api/threats | JSON: threat_name, category, indicator_type, indicator_value, source_name?, base_severity?, confidence_score?, description? | Threat detail; a duplicate indicator increments its counter instead | Enums, indicator syntax, confidence 0-100, sanitised text | admin | 201 created, 200 duplicate, 400, 401, 403 |
| PUT /api/threats/{id} | JSON subset: status, confidence_score, description, incident_confirmed | Updated, re-scored detail | Enums, ranges | admin | 200, 400, 401, 403, 404 |
| GET /api/indicators/search?q= | q = IP/domain/URL/hash/CVE (defanged input accepted) | Enrichment result (lookup only) | Syntax validation | none | 200, 400 |
| GET /api/dashboard/stats | - | Cards + chart datasets | - | none | 200 |
| GET /api/dashboard/trends | - | Monthly counts by severity, technique frequency | - | none | 200 |
| GET /api/dashboard/executive | - | Management summary | - | none | 200 |
| GET /api/attack/techniques/{tid}/threats | - | Records for one technique | - | none | 200 |
| GET /api/alerts | Query: status, severity | Correlated alerts | - | none | 200 |
| PUT /api/alerts/{id}/status | `{"status": "INVESTIGATING"}` | Updated alert | Status enum | analyst | 200, 400, 401, 404 |
| POST /api/threats/{id}/notes | `{"note": "..."}` | New note | Non-empty, sanitised, max 2000 chars | analyst | 201, 400, 401, 404 |
| GET /api/vulnerabilities | Query: severity, min_priority | CVE list with priority | Number check | none | 200, 400 |
| GET /api/awareness/modules | - | 15 modules | - | none | 200 |
| GET /api/quiz | - | Questions **without** answers | - | none | 200 |
| POST /api/quiz/submit | `{"answers": {"Q01": "C"}}` | Score, category scores, weakest areas, recommendations | A-D only | none | 200, 400 |

Also: 413 if the body is over 64 KB, 429 when rate-limited, and `GET /api/health`.

## Folder guide
| Folder | Purpose |
|---|---|
| backend/ | Flask app (`app.py`), `config.py`, `init_db.py` |
| backend/routes/ | HTTP endpoints (`api.py`) |
| backend/models/ | SQLite schema and connection (`database.py`) |
| backend/services/ | All logic: validator, risk, ATT&CK, correlation, alerts, enrichment, ingestion, vulnerabilities, awareness |
| backend/utils/ | Security (auth, RBAC, rate limit), text sanitiser, dates |
| frontend/ | Pages, CSS, JS, vendored Chart.js (works offline) |
| awareness/ | `modules.json`, `quiz_questions.json` |
| data/ | Generator and generated CSVs (the local DB is git-ignored) |
| tests/ | 40 automated tests |
| screenshots/ | Your proof images |
| reports/ | Put your final PDF report here |
| docs/ | These documents |
