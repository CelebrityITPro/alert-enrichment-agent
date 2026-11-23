import os
from pipeline.ingest import load_fixtures
from pipeline.normalize import normalize

VALID_MODES = ["fixtures", "wazuh"]


def main():
    mode = os.environ.get("PIPELINE_MODE", "fixtures")
    mode = mode.lower().strip()
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid PIPELINE_MODE: {mode}. Must be one of {VALID_MODES}.")
    print(f"Pipeline starting in {mode} mode.")
    if mode == "fixtures":
        alerts = load_fixtures("fixtures/wazuh")
        for alert in alerts:
            n = normalize(alert)
            print(n["description"], "| ip:", n["src_ip"], "| user:", n["user"], "| sha256:", n["file_sha256"])


if __name__ == "__main__":
    main()