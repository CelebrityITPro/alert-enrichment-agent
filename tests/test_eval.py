"""Tests for the evaluation scoring (pure logic, no LLM)."""

import json
from pathlib import Path

from eval.scoring import score

LABELS = {
    "a": {"acceptable": ["true_positive", "needs_investigation"], "scenario": "attack"},
    "b": {"acceptable": ["benign_true_positive"], "scenario": "eicar"},
}


def run(alert_id, verdict, confidence="medium", error=None):
    return {"alert_id": alert_id, "verdict": verdict, "confidence": confidence, "error": error}


def test_accuracy_counts_any_acceptable_verdict():
    report = score([run("a", "true_positive"), run("a", "needs_investigation"), run("b", "true_positive")], LABELS)
    assert report["per_alert"]["a"]["correct"] == 2
    assert report["per_alert"]["b"]["correct"] == 0
    assert report["overall"]["accuracy"] == round(2 / 3, 3)


def test_consistency_is_share_of_most_common_verdict():
    report = score([run("a", "true_positive"), run("a", "true_positive"), run("a", "needs_investigation")], LABELS)
    assert report["per_alert"]["a"]["consistency"] == 0.67


def test_overconfident_means_wrong_and_high():
    report = score([
        run("b", "true_positive", "high"),        # wrong + high -> overconfident
        run("b", "true_positive", "low"),         # wrong but humble -> not
        run("b", "benign_true_positive", "high"), # right + high -> not
    ], LABELS)
    assert report["per_alert"]["b"]["overconfident"] == 1


def test_errors_count_as_not_correct():
    report = score([run("a", None, None, error="rate limit"), run("a", "true_positive")], LABELS)
    assert report["per_alert"]["a"]["errors"] == 1
    assert report["overall"]["accuracy"] == 0.5


def test_every_label_points_at_an_existing_fixture():
    labels = json.loads(Path("eval/labels.json").read_text(encoding="utf-8"))
    for alert_id, label in labels.items():
        if alert_id.startswith("_"):
            continue
        fixture = json.loads(Path("fixtures/wazuh", label["fixture"]).read_text(encoding="utf-8"))
        assert fixture["id"] == alert_id
        assert label["acceptable"], f"{alert_id} has no acceptable verdicts"
