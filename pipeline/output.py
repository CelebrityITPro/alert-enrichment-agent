"""Output: save enriched alerts as JSON Lines (one JSON object per line).

This file is the hand-off point to later stages (LLM agent, IRIS, Discord).
JSON Lines is the same format Wazuh uses for alerts.json, can be streamed line by
line, and loads straight into pandas: pd.read_json(path, lines=True).
"""

import json
from pathlib import Path


def write_jsonl(alerts, path):
    """Write `alerts` to `path`, one per line, replacing any existing file.

    Overwrite (not append) so re-running fixtures mode gives the same file every time.
    Returns the number of alerts written.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        for alert in alerts:
            # ensure_ascii=False keeps non-English characters readable instead of \u escapes.
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    return len(alerts)
