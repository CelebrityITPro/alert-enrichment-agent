"""Pure scoring logic for the agent evaluation (no LLM calls, so it's unit-tested).

Metrics (ADR 0008):
- accuracy:       share of runs whose verdict is in the alert's acceptable set
- consistency:    per alert, share of runs that gave the most common verdict (1.0 = always the same)
- overconfident:  runs that were wrong AND said "high" confidence (the most dangerous failure)
- errors:         runs where the agent failed to produce a result (counted as not correct)
"""

from collections import Counter


def score(runs, labels):
    """`runs`: list of {"alert_id", "verdict", "confidence", "error"}.
    `labels`: {alert_id: {"acceptable": [...], ...}}. Returns per-alert and overall metrics."""
    by_alert = {}
    for r in runs:
        by_alert.setdefault(r["alert_id"], []).append(r)

    per_alert = {}
    for alert_id, alert_runs in by_alert.items():
        acceptable = set(labels[alert_id]["acceptable"])
        verdicts = [r["verdict"] for r in alert_runs if not r.get("error")]
        correct = [v in acceptable for v in verdicts]
        most_common = Counter(verdicts).most_common(1)
        per_alert[alert_id] = {
            "scenario": labels[alert_id].get("scenario", ""),
            "runs": len(alert_runs),
            "verdicts": [r["verdict"] or "ERROR" for r in alert_runs],
            "confidences": [r["confidence"] for r in alert_runs],
            "correct": sum(correct),
            "errors": sum(1 for r in alert_runs if r.get("error")),
            "consistency": round(most_common[0][1] / len(alert_runs), 2) if most_common else 0.0,
            "overconfident": sum(
                1 for r in alert_runs
                if not r.get("error") and r["verdict"] not in acceptable and r["confidence"] == "high"
            ),
        }

    total_runs = sum(a["runs"] for a in per_alert.values())
    total_correct = sum(a["correct"] for a in per_alert.values())
    completed = total_runs - sum(a["errors"] for a in per_alert.values())
    overall = {
        "alerts": len(per_alert),
        "total_runs": total_runs,
        "accuracy": round(total_correct / total_runs, 3) if total_runs else 0.0,
        # Same, but ignoring failed runs (e.g. rate limits), so quota problems
        # don't look like bad reasoning. Report both.
        "accuracy_completed": round(total_correct / completed, 3) if completed else 0.0,
        "avg_consistency": round(sum(a["consistency"] for a in per_alert.values()) / len(per_alert), 3)
        if per_alert else 0.0,
        "overconfident_runs": sum(a["overconfident"] for a in per_alert.values()),
        "error_runs": sum(a["errors"] for a in per_alert.values()),
    }
    return {"overall": overall, "per_alert": per_alert}
