"""Evaluate the triage agent against labelled fixtures: `python -m eval`.

Prerequisite: `python -m pipeline` (produces data/enriched/alerts.jsonl).
Runs the agent EVAL_RUNS times (default 3) on every labelled alert, scores the
results (eval/scoring.py), prints a table and saves a JSON report in data/eval/.

The report records the model and a hash of the system prompt, so runs before and
after a prompt change can be compared fairly.
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from agent.graph import triage
from agent.llm import get_llm, model_name
from agent.prompts import SYSTEM_PROMPT
from eval.scoring import score

LABELS_PATH = Path("eval/labels.json")
INPUT_PATH = Path("data/enriched/alerts.jsonl")
REPORT_DIR = Path("data/eval")

logger = logging.getLogger("eval")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    for noisy in ("httpx", "groq", "agent", "pipeline"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    runs_per_alert = int(os.environ.get("EVAL_RUNS", "3"))
    labels = {k: v for k, v in json.loads(LABELS_PATH.read_text(encoding="utf-8")).items()
              if not k.startswith("_")}
    with open(INPUT_PATH, encoding="utf-8") as f:
        batch = [json.loads(line) for line in f if line.strip()]

    by_id = {a["alert_id"]: a for a in batch}
    missing = [k for k in labels if k not in by_id]
    if missing:
        raise SystemExit(f"Labelled alerts missing from {INPUT_PATH}: {missing}. Run `python -m pipeline`.")

    llm = get_llm()
    prompt_hash = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:12]
    logger.info("Evaluating %d alerts x %d runs with %s (prompt %s)",
                len(labels), runs_per_alert, model_name(), prompt_hash)

    runs = []
    for run in range(1, runs_per_alert + 1):
        for alert_id in labels:
            r = triage(by_id[alert_id], batch, llm)
            t = r["triage"] or {}
            guard = r.get("prompt_guard") or {}
            runs.append({"run": run, "alert_id": alert_id, "verdict": t.get("verdict"),
                         "confidence": t.get("confidence"), "error": r["error"],
                         "guard_score": guard.get("score"), "guard_override": r.get("guard_override", False)})
            logger.info("run %d  %-18s -> %s / %s%s", run, alert_id, t.get("verdict"), t.get("confidence"),
                        "  [guard override]" if r.get("guard_override") else "")

    report = score(runs, labels)
    report["meta"] = {"model": model_name(), "prompt_hash": prompt_hash, "runs_per_alert": runs_per_alert,
                      "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    report["runs"] = runs

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / f"eval_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nPer alert:")
    for a in report["per_alert"].values():
        print(f"  {a['correct']}/{a['runs']} correct  consistency {a['consistency']:.2f}  "
              f"overconfident {a['overconfident']}  {a['verdicts']}  - {a['scenario']}")
    o = report["overall"]
    print(f"\nOverall: accuracy {o['accuracy']:.1%} (completed runs only: {o['accuracy_completed']:.1%}) | "
          f"avg consistency {o['avg_consistency']:.2f} | "
          f"overconfident runs {o['overconfident_runs']} | errors {o['error_runs']}")
    print(f"Report saved to {out}")


if __name__ == "__main__":
    main()
