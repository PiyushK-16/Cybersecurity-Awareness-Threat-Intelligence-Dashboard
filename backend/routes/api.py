"""REST API. Reads are open in this demo; writes need an API key (RBAC)."""
from flask import Blueprint, current_app, g, jsonify, request

from backend.models.database import get_connection
from backend.services import awareness_service as aw
from backend.services import threat_service as ts
from backend.services.enrichment_engine import enrich_indicator
from backend.utils.security import require_role

api = Blueprint("api", __name__, url_prefix="/api")


def db():
    if "db" not in g:
        g.db = get_connection(current_app.config["DATABASE_PATH"])
    return g.db


@api.teardown_app_request
def _close(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def _json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ts.ValidationError("Request body must be a JSON object.")
    return data


@api.errorhandler(ts.ValidationError)
def _bad(e):
    return jsonify(error=str(e)), 400


@api.get("/health")
def health():
    return jsonify(status="ok", note="Synthetic demo data only")


# ---- threats
@api.get("/threats")
def threats():
    return jsonify(ts.list_threats(db(), request.args))


@api.get("/threats/<threat_id>")
def threat_detail(threat_id):
    d = ts.get_threat_detail(db(), threat_id.upper())
    return (jsonify(d), 200) if d else (jsonify(error="Threat not found."), 404)


@api.post("/threats")
@require_role("admin")
def threat_create():
    rec, created = ts.create_threat(db(), _json_body(), request.actor)
    return jsonify(rec), (201 if created else 200)


@api.put("/threats/<threat_id>")
@require_role("admin")
def threat_update(threat_id):
    d = ts.update_threat(db(), threat_id.upper(), _json_body(), request.actor)
    return (jsonify(d), 200) if d else (jsonify(error="Threat not found."), 404)


@api.post("/threats/<threat_id>/notes")
@require_role("analyst")
def threat_note(threat_id):
    body = _json_body()
    n = ts.add_note(db(), threat_id.upper(), body.get("note", ""), request.actor)
    return (jsonify(n), 201) if n else (jsonify(error="Threat not found."), 404)


# ---- indicators / dashboard
@api.get("/indicators/search")
def indicator_search():
    q = request.args.get("q", "")
    if not q.strip():
        return jsonify(error="Query parameter 'q' is required."), 400
    return jsonify(enrich_indicator(db(), q))


@api.get("/dashboard/stats")
def stats():
    return jsonify(ts.dashboard_stats(db()))


@api.get("/dashboard/trends")
def trends():
    return jsonify(ts.dashboard_trends(db()))


@api.get("/dashboard/executive")
def executive():
    return jsonify(ts.executive_summary(db()))


@api.get("/attack/techniques/<technique_id>/threats")
def attack_technique(technique_id):
    return jsonify(ts.attack_threats(db(), technique_id))


# ---- alerts / vulnerabilities
@api.get("/alerts")
def alerts():
    return jsonify(ts.list_alerts(db(), request.args.get("status"), request.args.get("severity")))


@api.put("/alerts/<alert_id>/status")
@require_role("analyst")
def alert_status(alert_id):
    a = ts.update_alert_status(db(), alert_id.upper(), str(_json_body().get("status", "")).upper(), request.actor)
    return (jsonify(a), 200) if a else (jsonify(error="Alert not found."), 404)


@api.get("/vulnerabilities")
def vulnerabilities():
    return jsonify(ts.list_vulnerabilities(db(), request.args.get("severity"), request.args.get("min_priority")))


# ---- awareness
def _cfg(name):
    return current_app.config[name]


@api.get("/awareness/modules")
def modules():
    return jsonify(aw.load_json(_cfg("AWARENESS_DIR"), "modules.json"))


@api.get("/quiz")
def quiz():
    qs = aw.load_json(_cfg("AWARENESS_DIR"), "quiz_questions.json")
    return jsonify([{k: v for k, v in q.items() if k not in ("answer", "explanation")} for q in qs])


@api.post("/quiz/submit")
def quiz_submit():
    body = _json_body()
    answers = body.get("answers")
    if not isinstance(answers, dict) or not answers:
        raise ts.ValidationError("'answers' must be an object like {\"Q01\": \"C\"}.")
    if any(str(v).upper() not in ("A", "B", "C", "D") for v in answers.values()):
        raise ts.ValidationError("Each answer must be one of A, B, C, D.")
    qs = aw.load_json(_cfg("AWARENESS_DIR"), "quiz_questions.json")
    result = aw.score_quiz(answers, qs)
    result["recommendations"] = aw.generate_learning_recommendations(
        result["category_scores"], aw.load_json(_cfg("AWARENESS_DIR"), "modules.json"))
    import json
    from backend.utils.dates import now_iso
    db().execute("INSERT INTO quiz_results (anonymous_user_id, overall_score, category_scores, created_at) VALUES (?,?,?,?)",
                 (None, result["overall_score"], json.dumps(result["category_scores"]), now_iso()))
    db().commit()
    return jsonify(result)
