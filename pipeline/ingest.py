import json
from pathlib import Path


def load_fixtures(folder):
    alerts = []
    for path in sorted(Path(folder).glob("*.json")):        # match every .json file
        with open(path, encoding="utf-8") as f:
            alerts.append(json.load(f))                     # read JSON from a file
    return alerts
