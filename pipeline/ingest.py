"""Ingest: load raw Wazuh alerts into Python dicts."""

import json
from pathlib import Path


def load_fixtures(folder):
    """Load every .json file in `folder` as one alert dict.

    Files are read in sorted order so results (and tests) are the same on every run.
    """
    alerts = []
    for path in sorted(Path(folder).glob("*.json")):
        # Explicit UTF-8: on Windows, Python's default encoding is not UTF-8.
        with open(path, encoding="utf-8") as f:
            alerts.append(json.load(f))
    return alerts
