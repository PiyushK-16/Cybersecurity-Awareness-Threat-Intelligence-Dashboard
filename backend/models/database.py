"""SQLite schema and connection helper (plain sqlite3 - easy to read for beginners)."""
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY, source_name TEXT UNIQUE NOT NULL, reliability TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS threats (
    threat_id TEXT PRIMARY KEY, threat_name TEXT NOT NULL, category TEXT NOT NULL, description TEXT,
    severity TEXT NOT NULL, base_severity TEXT, risk_score INTEGER NOT NULL, confidence_score INTEGER NOT NULL,
    status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, record_timestamp TEXT,
    source_id TEXT REFERENCES sources(source_id), campaign_id TEXT, observation_count INTEGER DEFAULT 1,
    related_alert_count INTEGER DEFAULT 0, region TEXT, cve_id TEXT, entity_stage TEXT DEFAULT 'INDICATOR',
    incident_confirmed INTEGER DEFAULT 0, synthetic_label TEXT);
CREATE TABLE IF NOT EXISTS indicators (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL, indicator_value TEXT NOT NULL, normalized_value TEXT NOT NULL,
    first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS attack_mappings (
    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    tactic TEXT NOT NULL, technique TEXT NOT NULL, technique_id_optional TEXT, rationale TEXT);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE NOT NULL, product_category TEXT,
    severity TEXT, cvss_score REAL, published_date TEXT, patch_available INTEGER, exploitation_status_demo TEXT,
    asset_criticality INTEGER, exposure TEXT, business_impact INTEGER, priority_score REAL, priority_label TEXT,
    description TEXT);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    severity TEXT, risk_score INTEGER, confidence_score INTEGER, alert_type TEXT, description TEXT,
    status TEXT NOT NULL DEFAULT 'NEW', observation_count INTEGER DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    note TEXT NOT NULL, author TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS awareness_modules (module_id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT);
CREATE TABLE IF NOT EXISTS quiz_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT, anonymous_user_id TEXT, overall_score INTEGER NOT NULL,
    category_scores TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, target TEXT, detail TEXT, created_at TEXT);

CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_risk ON threats(risk_score);
CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats(last_seen);
CREATE INDEX IF NOT EXISTS idx_threats_campaign ON threats(campaign_id);
CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators(normalized_value);
CREATE INDEX IF NOT EXISTS idx_ind_threat ON indicators(threat_id);
CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts(threat_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_attack_tid ON attack_mappings(technique_id_optional);
CREATE INDEX IF NOT EXISTS idx_attack_threat ON attack_mappings(threat_id);
CREATE INDEX IF NOT EXISTS idx_notes_threat ON analyst_notes(threat_id);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_schema(conn: sqlite3.Connection, reset: bool = False) -> None:
    if reset:
        for t in ("audit_log", "quiz_results", "awareness_modules", "analyst_notes", "alerts", "vulnerabilities",
                  "attack_mappings", "indicators", "threats", "sources"):
            conn.execute(f"DROP TABLE IF EXISTS {t}")
    conn.executescript(SCHEMA)
    conn.commit()
