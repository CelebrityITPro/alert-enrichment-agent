"""Pipeline entry point: run with `python -m pipeline`.

Flow: load alerts -> normalize to one standard shape -> enrich with threat intel
-> correlate across alerts (impossible travel) -> write to data/enriched/alerts.jsonl.
Settings come from environment variables (see .env.example):
  PIPELINE_MODE  fixtures | wazuh
  LOG_LEVEL      DEBUG | INFO | WARNING | ERROR   (default INFO)
"""

import logging
import os

from pipeline.ingest import load_fixtures
from pipeline.normalize import normalize
from pipeline.enrich import enrich
from pipeline.correlate import detect_impossible_travel
from pipeline.output import write_jsonl

# fixtures = read sample alerts from ./fixtures (no lab needed)
# wazuh    = poll a live Wazuh indexer (not built yet)
VALID_MODES = ["fixtures", "wazuh"]
OUTPUT_PATH = "data/enriched/alerts.jsonl"  # data/ is gitignored and mounted in Docker

logger = logging.getLogger(__name__)


def setup_logging():
    """Configure logging from LOG_LEVEL. Logs go to stderr, keeping data output clean."""
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper().strip()
    level = getattr(logging, level_name, None)
    valid = isinstance(level, int)
    logging.basicConfig(
        level=level if valid else logging.INFO,  # unknown value: fall back instead of crashing
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    if not valid:
        logger.warning("Unknown LOG_LEVEL %r, using INFO", level_name)


def main():
    setup_logging()

    # Clean the value before checking it: "Fixtures " in .env should still work.
    mode = os.environ.get("PIPELINE_MODE", "fixtures")
    mode = mode.lower().strip()

    # Fail fast on bad config, before doing any work.
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid PIPELINE_MODE: {mode}. Must be one of {VALID_MODES}.")
    logger.info("Pipeline starting in %s mode", mode)

    if mode == "wazuh":
        logger.error("Wazuh mode is not built yet (Phase 1). Use PIPELINE_MODE=fixtures.")
        return

    raw_alerts = load_fixtures("fixtures/wazuh")
    enriched = []
    for alert in raw_alerts:
        e = enrich(normalize(alert))
        logger.debug("%s | ip=%s | intel=%s", e["description"], e["src_ip"], list(e["intel"]))
        enriched.append(e)

    # Correlation needs the whole batch, so it runs after every alert is enriched.
    enriched = detect_impossible_travel(enriched)

    count = write_jsonl(enriched, OUTPUT_PATH)

    # One-line run summary at INFO level.
    looked_up = sum(1 for e in enriched if e["intel"])
    failed = sum(1 for e in enriched for r in e["intel"].values() if "error" in r)
    correlated = sum(1 for e in enriched if e["correlation"])
    logger.info(
        "Done: %d alerts written to %s (%d with intel, %d lookup errors, %d correlations)",
        count, OUTPUT_PATH, looked_up, failed, correlated,
    )


# Only run main() when executed directly, not when another module imports this file.
if __name__ == "__main__":
    main()
