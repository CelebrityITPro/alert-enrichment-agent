"""AlienVault OTX client: which community threat reports ("pulses") mention an IP or hash.

API docs: https://otx.alienvault.com/api (indicators endpoints, `general` section).
Requires OTX_API_KEY in .env (only needed on a cache miss).

What OTX adds over AbuseIPDB/VirusTotal: context. Pulses link indicators to malware
families, threat actors (adversaries) and MITRE ATT&CK technique IDs.

UNTRUSTED: pulse names and tags are written by anyone in the community. They are
capped and cleaned here (see pipeline/sanitize.py) before reaching the agent.
"""

import ipaddress
import logging
import os
import re

import requests
from dotenv import load_dotenv

from pipeline.intel.cache import NOT_FOUND, cached_lookup
from pipeline.sanitize import clean_text, unique_clean

load_dotenv()

API_URL = "https://otx.alienvault.com/api/v1/indicators/{kind}/{value}/general"

MAX_PULSES = 5        # names of the first N pulses only
MAX_ITEMS = 10        # cap for families / adversaries / tags / ATT&CK IDs
ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")  # e.g. T1110 or T1110.001

logger = logging.getLogger(__name__)


def _fetch(kind, value):
    """Call OTX for one indicator. Returns raw JSON (or NOT_FOUND). Raises on errors."""
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        raise RuntimeError("OTX_API_KEY environment variable is not set")

    response = requests.get(
        API_URL.format(kind=kind, value=value),
        headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
        timeout=20,  # OTX can be slow for popular indicators
    )
    if response.status_code == 404:
        return NOT_FOUND
    response.raise_for_status()
    return response.json()


def _names(items):
    """OTX lists may hold dicts ({"display_name": ...}) or plain strings."""
    for item in items or []:
        if isinstance(item, dict):
            yield item.get("display_name") or item.get("name") or item.get("id")
        else:
            yield item


def _summarize(indicator, raw):
    """Turn OTX's raw response into our standard shape, capping untrusted text."""
    if raw.get("_not_found"):
        return {"indicator": indicator, "pulse_count": 0}

    pulse_info = raw.get("pulse_info") or {}
    pulses = [p for p in (pulse_info.get("pulses") or []) if isinstance(p, dict)]

    families, adversaries, tags, attack_ids = [], [], [], []
    for p in pulses:
        families.extend(_names(p.get("malware_families")))
        adversaries.append(p.get("adversary"))
        tags.extend(p.get("tags") or [])
        for a in p.get("attack_ids") or []:
            tid = a.get("id") if isinstance(a, dict) else a
            # Strict format check: only real-looking technique IDs get through.
            if isinstance(tid, str) and ATTACK_ID_RE.fullmatch(tid) and tid not in attack_ids:
                attack_ids.append(tid)

    count = pulse_info.get("count")
    return {
        "indicator": indicator,
        "pulse_count": count if isinstance(count, int) else len(pulses),
        "pulses": unique_clean((p.get("name") for p in pulses), MAX_PULSES),
        "malware_families": unique_clean(families, MAX_ITEMS, max_len=60),
        "adversaries": unique_clean(adversaries, MAX_ITEMS, max_len=60),
        "attack_ids": attack_ids[:MAX_ITEMS],
        "tags": unique_clean(tags, MAX_ITEMS, max_len=40),
        "reputation": raw.get("reputation") if isinstance(raw.get("reputation"), int) else None,
        "country": clean_text(raw.get("country_code"), max_len=2),
    }


def check_ip(ip):
    """OTX context for a validated public IP (IPv4 or IPv6)."""
    kind = "IPv6" if ipaddress.ip_address(ip).version == 6 else "IPv4"
    return cached_lookup("otx_ip", ip, lambda v: _fetch(kind, v), _summarize)


def check_hash(sha256):
    """OTX context for a validated, lowercase SHA256."""
    return cached_lookup("otx_hash", sha256, lambda v: _fetch("file", v), _summarize)


if __name__ == "__main__":
    # Quick manual check: python -m pipeline.intel.otx
    logging.basicConfig(level=logging.DEBUG)
    print(check_ip("195.178.110.150"))
