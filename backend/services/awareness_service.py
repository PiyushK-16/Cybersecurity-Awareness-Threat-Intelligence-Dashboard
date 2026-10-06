"""Awareness content, quiz scoring and learning recommendations.
The score is an EDUCATIONAL indicator - not an employee fitness or competency judgement."""
import json
from pathlib import Path


def load_json(awareness_dir: str, name: str):
    with open(Path(awareness_dir) / name, encoding="utf-8") as fh:
        return json.load(fh)


def score_level(score: float) -> str:
    if score <= 40:
        return "Needs Improvement"
    if score <= 60:
        return "Basic Awareness"
    if score <= 80:
        return "Good Awareness"
    return "Strong Awareness"


def score_quiz(answers: dict, questions: list[dict]) -> dict:
    """answers: {question_id: 'A'..'D'}. Unanswered questions count as wrong."""
    if not questions:
        return {"overall_score": 0, "level": score_level(0), "category_scores": {}, "weakest_areas": [], "details": []}
    per_cat: dict[str, list[int]] = {}
    details = []
    for q in questions:
        given = str(answers.get(q["id"], "")).upper()
        ok = given == q["answer"]
        per_cat.setdefault(q["category"], []).append(1 if ok else 0)
        details.append({"id": q["id"], "category": q["category"], "correct": ok, "your_answer": given or None,
                        "correct_answer": q["answer"], "explanation": q["explanation"]})
    cat_scores = {c: round(100 * sum(v) / len(v)) for c, v in per_cat.items()}
    total = sum(sum(v) for v in per_cat.values())
    overall = round(100 * total / len(questions))
    weakest = [c for c, _ in sorted(cat_scores.items(), key=lambda kv: kv[1])[:3] if cat_scores[c] < 75]
    return {"overall_score": overall, "level": score_level(overall), "category_scores": cat_scores,
            "weakest_areas": weakest, "details": details,
            "disclaimer": "Educational score only - not a judgement of competence or fitness for any role."}


def generate_learning_recommendations(category_scores: dict, modules: list[dict]) -> list[dict]:
    """<50: complete the module. 50-74: review it. >=75: no immediate module needed."""
    by_cat = {}
    for m in modules:
        by_cat.setdefault(m["quiz_category"], m)
    recs = []
    for cat, score in sorted(category_scores.items(), key=lambda kv: kv[1]):
        mod = by_cat.get(cat)
        title = mod["title"] if mod else cat
        if score < 50:
            action = f"Complete the {title} module."
        elif score < 75:
            action = f"Review the {title} module."
        else:
            action = "No immediate module required."
        recs.append({"category": cat, "score": score, "module_id": mod["module_id"] if mod else None, "recommendation": action})
    return recs
