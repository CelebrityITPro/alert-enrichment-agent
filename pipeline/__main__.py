import os

VALID_MODES = ["fixtures", "wazuh"]


def main():
    mode = os.environ.get("PIPELINE_MODE", "fixtures")
    mode = mode.lower().strip()
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid PIPELINE_MODE: {mode}. Must be one of {VALID_MODES}.")
    print(f"Pipeline starting in {mode} mode.")


if __name__ == "__main__":
    main()