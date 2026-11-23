"""Pipeline entry point: run with `python -m pipeline`.

Flow: load alerts -> normalize to one standard shape -> enrich with threat intel.
The mode is chosen by the PIPELINE_MODE environment variable (see .env.example).
"""

import os

from pipeline.ingest import load_fixtures
from pipeline.normalize import normalize
from pipeline.enrich import enrich

# fixtures = read sample alerts from ./fixtures (no lab needed)
# wazuh    = poll a live Wazuh indexer (not built yet)
VALID_MODES = ["fixtures", "wazuh"]


def main():
    # Clean the value before checking it: "Fixtures " in .env should still work.
    mode = os.environ.get("PIPELINE_MODE", "fixtures")
    mode = mode.lower().strip()

    # Fail fast on bad config, before doing any work.
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid PIPELINE_MODE: {mode}. Must be one of {VALID_MODES}.")
    print(f"Pipeline starting in {mode} mode.")

    if mode == "fixtures":
        alerts = load_fixtures("fixtures/wazuh")
        for alert in alerts:
            n = normalize(alert)
            e = enrich(n)
            print(e["description"], "| ip:", e["src_ip"], "| intel:", e["intel"])


# Only run main() when executed directly, not when another module imports this file.
if __name__ == "__main__":
    main()
