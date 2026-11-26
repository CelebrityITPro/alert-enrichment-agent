"""Agent entry point: run with `python -m agent` (after `python -m pipeline`).

Reads data/enriched/alerts.jsonl, triages each alert with the LLM agent, and writes
data/triage/triage.jsonl. Recommendations only: nothing is changed anywhere.
"""

import json
import logging
import os
from pathlib import Path

from agent.graph import triage
from agent.llm import get_llm, model_name
from pipeline.output import write_jsonl

INPUT_PATH = Path("data/enriched/alerts.jsonl")
OUTPUT_PATH = Path("data/triage/triage.jsonl")

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(
        level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    if not INPUT_PATH.exists():
        raise SystemExit(f"{INPUT_PATH} not found. Run `python -m pipeline` first.")

    with open(INPUT_PATH, encoding="utf-8") as f:
        batch = [json.loads(line) for line in f if line.strip()]

    llm = get_llm()
    model = model_name()
    logger.info("Triaging %d alerts with %s", len(batch), model)

    results = []
    for alert in batch:
        r = triage(alert, batch, llm)
        r["description"] = alert.get("description")
        r["model"] = model
        results.append(r)
        t = r["triage"]
        if t:
            logger.info("%s -> %s (%s confidence)", alert.get("description"), t["verdict"], t["confidence"])

    write_jsonl(results, OUTPUT_PATH)
    failed = sum(1 for r in results if r["error"])
    logger.info("Done: %d triaged, %d failed, written to %s", len(results) - failed, failed, OUTPUT_PATH)


if __name__ == "__main__":
    main()
