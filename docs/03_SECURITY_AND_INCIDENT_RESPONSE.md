# 03 - Security, privacy, incident-response awareness

## Safe handling rules (and where the code enforces them)
| Rule | How |
|---|---|
| Never visit suspicious URLs / contact suspicious IPs | No code path opens a network connection to an indicator. Search is a **database lookup** (`enrichment_engine.py`). |
| Never execute files based on hashes | Hashes are strings; only their format is checked. |
| Indicators are shown defanged | URLs/domains display as `hxxps://login-check[.]invalid` so they cannot be clicked by accident. |
| Sanitise descriptions, prevent XSS | `sanitize_text()` strips tags/control characters on write; the frontend builds the page with `textContent` only (no `innerHTML`); a strict Content-Security-Policy blocks inline scripts. |
| Validate API input | Enum whitelists, integer/date parsing, indicator syntax, 64 KB body limit. |
| Authenticate analyst functions + RBAC | `X-API-Key` checked with constant-time compare; analyst vs admin roles. |
| Protect analyst notes | Written only by authenticated roles; author recorded. |
| Rate limiting | Sliding window per IP (`utils/security.py`). |
| Protect API keys | Environment variables (`.env`, git-ignored). The sample file holds placeholders only. |
| HTTPS | The dev server uses HTTP on localhost. In production, put it behind a TLS reverse proxy. |
| Audit administrative changes | `audit_log` table records creates, updates, notes, alert status changes. |
| Minimise personal data | Email addresses are reduced to the sender **domain**; the quiz stores anonymous scores. |
| No debug server | `debug=False` so the Werkzeug debugger is never exposed. |

**Why threat intelligence itself needs access control:** it can reveal what an organisation is watching for, expose investigation notes, and leak sensitive internal sightings. Attackers who learn what defenders know can adapt.

## Incident-response lifecycle (awareness level)
Frameworks differ (NIST SP 800-61 uses Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity - SANS uses six steps). This project uses the common six-step view:

1. **Preparation** - contacts, roles, backups, logging, training.
2. **Detection / identification** - alerts, user reports; confirm whether it is a real incident.
3. **Containment** - limit spread using steps your policy approves.
4. **Eradication** - remove the cause (e.g. patch, remove unauthorised access).
5. **Recovery** - restore services safely and monitor.
6. **Lessons learned** - what worked, what to improve.

### Educational checklist (non-destructive)
- [ ] Note the time and what you observed; keep original evidence (e.g. the email).
- [ ] Report to the security contact straight away.
- [ ] Do not delete logs, wipe devices or "clean up" on your own.
- [ ] Do not contact or retaliate against the sender/indicator.
- [ ] Preserve a timeline: who, what, when.
- [ ] Reset exposed credentials and enable MFA when instructed.
- [ ] Record the outcome and follow-up actions.
- [ ] Hold a short lessons-learned review.

## False positives
See `01_CONCEPTS.md` section 45. In the app: status `FALSE_POSITIVE` excludes a record from alert generation, drops it to the OBSERVATION stage and withdraws its ATT&CK mapping.
